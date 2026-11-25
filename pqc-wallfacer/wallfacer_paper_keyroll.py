#!/usr/bin/env python3
"""
wallfacer_paper_keyroll.py : Wallfacer out-of-band paper key-roll

Prints a post-quantum key (static public key, PSK, or PQC private key) as a
numbered set of QR codes on A4 paper, and reassembles the exact key file from
scans of that paper.

Context (ThereminQ-PQC, pqc-wallfacer):
  Provides a physical, air-gapped paper QR alternative to the LoRa / Reticulum
  radio network (and IP) for relaying post-quantum keys into the enclave
  workflow:
    - Classic McEliece 460896 static public keys (524,160 bytes) never cross
      the wire or radio link; radio only carries 188-byte Rosenpass ciphertexts
      and fixed-size envelopes inside the 500-byte payload.
    - PQC private keys (Classic McEliece pqsk, ML-DSA-87, ML-KEM-768/1024,
      SLH-DSA-SHA2-256s, PKCS#8 PEM) can be relayed off-radio on 2 A4 sheets
      using --allow-secret, optionally passphrase-sealed with AES-256-GCM +
      scrypt (--seal).

Commands
  encode   key file            -> PDF key-roll (plus optional per-frame PNGs)
  decode   scans / text dumps  -> byte-identical key file, SHA3-256 verified
  verify   scans / text dumps  -> dry-run integrity/fingerprint check (no write)
  psk      new random PSK file (32 bytes default) for the envelope layer

Frame format (QR alphanumeric mode, scanner-safe, RFC 9285 Base45 payload)
  WFK1:<KID>:<IDX>:<TOT>:<CRC32>:<BASE45>
  KID   first 8 hex of SHA3-256(framed payload), uppercase
  IDX   0000 = manifest frame, 0001..TOT = data frames
  CRC32 of the decoded payload bytes of that frame

Dependencies
  encode : segno, reportlab (plus cryptography when using --seal)
  decode : zxing-cpp + pillow (dense v40 sheets), opencv-python-headless as
           fallback, poppler-utils for PDF input, cryptography for sealed rolls
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

MAGIC = "WFK1"
HEADER_LEN = len(MAGIC) + 1 + 8 + 1 + 4 + 1 + 4 + 1 + 8 + 1  # 33 chars

SEAL_MAGIC = b"WFSEAL1\x00"
SEAL_HEADER_FMT = ">8sBBBB16s12s"
SEAL_HEADER_LEN = struct.calcsize(SEAL_HEADER_FMT)  # 40 bytes
SEAL_SCRYPT_LOG2_N = 15  # N = 32768
SEAL_SCRYPT_R = 8
SEAL_SCRYPT_P = 1

# Known raw key sizes, for labelling and for guarding private keys.
KEY_TYPES = {
    524160: ("Classic McEliece 460896 public key (Rosenpass static)", "public"),
    261120: ("Classic McEliece 348864 public key", "public"),
    1044992: ("Classic McEliece 6688128 public key", "public"),
    1047319: ("Classic McEliece 6960119 public key", "public"),
    1357824: ("Classic McEliece 8192128 public key", "public"),
    1184: ("ML-KEM-768 public key", "public"),
    1568: ("ML-KEM-1024 public key", "public"),
    1952: ("ML-DSA-65 public key", "public"),
    2592: ("ML-DSA-87 public key", "public"),
    13608: ("Classic McEliece 460896 SECRET key", "secret-key"),
    6492: ("Classic McEliece 348864 SECRET key", "secret-key"),
    13932: ("Classic McEliece 6688128 SECRET key", "secret-key"),
    13948: ("Classic McEliece 6960119 SECRET key", "secret-key"),
    14120: ("Classic McEliece 8192128 SECRET key", "secret-key"),
    2400: ("ML-KEM-768 SECRET key", "secret-key"),
    3168: ("ML-KEM-1024 SECRET key", "secret-key"),
    4032: ("ML-DSA-65 SECRET key", "secret-key"),
    4896: ("ML-DSA-87 SECRET key", "secret-key"),
    128: ("SLH-DSA-SHA2-256s SECRET key", "secret-key"),
    32: ("256-bit pre-shared key", "psk"),
    64: ("512-bit pre-shared key", "psk"),
}

# NIST PQC DER OID encodings for identifying OpenSSL 3.5 PEM keys.
PEM_PQC_OIDS = (
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13", "ML-DSA-87"),
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12", "ML-DSA-65"),
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x03", "ML-KEM-1024"),
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04\x02", "ML-KEM-768"),
    (b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x18", "SLH-DSA-SHA2-256s"),
)

CLASS_LABEL = {
    "public": "RESTRICTED : public key, keep off the wire (initiator deniability)",
    "psk": "SECRET : symmetric key material, destroy after enrolment",
    "secret-key": "SECRET : PQC private key material (paper QR relay — off radio/IP)",
    "unknown": "RESTRICTED : unclassified key material",
}


def _pem_pqc_alg(data: bytes) -> str:
    """Identify a NIST PQC algorithm OID inside a PEM block, if present."""
    lines = [
        ln.strip() for ln in data.splitlines()
        if ln.strip() and not ln.strip().startswith(b"-----")
    ]
    try:
        der = base64.b64decode(b"".join(lines), validate=False)
    except Exception:
        return ""
    for oid, name in PEM_PQC_OIDS:
        if oid in der:
            return name
    return ""


def detect_key_type(data: bytes) -> tuple:
    """Return (human label, class) for raw PQC keys, PSKs, or OpenSSL PEM keys."""
    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN "):
        first = stripped.splitlines()[0]
        alg = _pem_pqc_alg(stripped)
        prefix = f"{alg} " if alg else "PEM "
        if b"ENCRYPTED PRIVATE KEY" in first:
            return (f"{prefix}encrypted private key (PKCS#8)", "secret-key")
        if b"PRIVATE KEY" in first:
            return (f"{prefix}SECRET key (PEM)", "secret-key")
        if b"PUBLIC KEY" in first:
            return (f"{prefix}public key (PEM)", "public")
        if b"CERTIFICATE" in first:
            return (f"{prefix}X.509 certificate (PEM)", "public")
    return KEY_TYPES.get(len(data), (f"{len(data)}-byte key material", "unknown"))


# ---------------------------------------------------------------- sealing --
def _derive_seal_key(passphrase: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    n = 1 << log2_n
    maxmem = max(64 * 1024 * 1024, 256 * r * n)
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=32
    )


def seal_payload(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt key bytes for physical paper relay using scrypt + AES-256-GCM."""
    if not passphrase:
        raise ValueError("Passphrase for --seal must not be empty")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "Sealed paper key-rolls require the 'cryptography' package "
            "(pip install cryptography)"
        ) from exc
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    header = struct.pack(
        SEAL_HEADER_FMT, SEAL_MAGIC, SEAL_SCRYPT_LOG2_N, SEAL_SCRYPT_R, SEAL_SCRYPT_P,
        0, salt, nonce
    )
    key = _derive_seal_key(passphrase, salt, SEAL_SCRYPT_LOG2_N, SEAL_SCRYPT_R, SEAL_SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + ct


def is_sealed_payload(data: bytes) -> bool:
    return len(data) >= SEAL_HEADER_LEN + 16 and data[:len(SEAL_MAGIC)] == SEAL_MAGIC


def unseal_payload(blob: bytes, passphrase: str) -> bytes:
    """Verify and decrypt a WFSEAL1 paper key-roll envelope."""
    if not is_sealed_payload(blob):
        raise ValueError("Input is not a WFSEAL1 sealed payload")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "Decoding a sealed paper key-roll requires the 'cryptography' package "
            "(pip install cryptography)"
        ) from exc
    header = blob[:SEAL_HEADER_LEN]
    magic, log2_n, r, p, reserved, salt, nonce = struct.unpack(SEAL_HEADER_FMT, header)
    if magic != SEAL_MAGIC or reserved != 0 or not (10 <= log2_n <= 20) or r == 0 or p == 0:
        raise ValueError("Malformed WFSEAL1 header")
    key = _derive_seal_key(passphrase, salt, log2_n, r, p)
    return AESGCM(key).decrypt(nonce, blob[SEAL_HEADER_LEN:], header)


def resolve_passphrase(args, confirm: bool = False) -> str:
    """Read passphrase from --passphrase-file, --passphrase-env, or TTY prompt."""
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, "r", encoding="utf-8") as fh:
            pw = fh.read().rstrip("\r\n")
        if not pw:
            sys.exit(f"Passphrase file {args.passphrase_file} is empty")
        return pw
    if getattr(args, "passphrase_env", None):
        pw = os.environ.get(args.passphrase_env, "")
        if not pw:
            sys.exit(f"Environment variable {args.passphrase_env} is unset or empty")
        return pw
    if not sys.stdin.isatty():
        sys.exit("Passphrase required: supply --passphrase-file or --passphrase-env")
    pw = getpass.getpass("Paper key-roll passphrase: ")
    if not pw:
        sys.exit("Passphrase must not be empty")
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            sys.exit("Passphrases do not match")
    return pw


def write_secret_file(path: str, data: bytes, mode: int = 0o600):
    """Write key material atomically with restrictive permissions from creation."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp_path = os.path.join(parent, f".{os.path.basename(path)}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- Base45 ---
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
B45_INV = {c: i for i, c in enumerate(B45)}


def b45encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - 1, 2):
        n = data[i] * 256 + data[i + 1]
        n, c = divmod(n, 45)
        e, d = divmod(n, 45)
        out += [B45[c], B45[d], B45[e]]
    if len(data) % 2:
        d, c = divmod(data[-1], 45)
        out += [B45[c], B45[d]]
    return "".join(out)


def b45decode(s: str) -> bytes:
    out = bytearray()
    vals = [B45_INV[c] for c in s]
    for i in range(0, len(vals), 3):
        chunk = vals[i:i + 3]
        if len(chunk) == 3:
            n = chunk[0] + chunk[1] * 45 + chunk[2] * 2025
            if n > 0xFFFF:
                raise ValueError("base45 triplet out of range")
            out += bytes((n >> 8, n & 0xFF))
        elif len(chunk) == 2:
            n = chunk[0] + chunk[1] * 45
            if n > 0xFF:
                raise ValueError("base45 pair out of range")
            out.append(n)
        else:
            raise ValueError("dangling base45 character")
    return bytes(out)


# ---------------------------------------------------------------- framing --
def fingerprint(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest().upper()


def fp_groups(fp: str, per_line: int = 8) -> list:
    groups = [fp[i:i + 4] for i in range(0, len(fp), 4)]
    return [" ".join(groups[i:i + per_line]) for i in range(0, len(groups), per_line)]


def make_frame(kid: str, idx: int, tot: int, payload: bytes) -> str:
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return f"{MAGIC}:{kid}:{idx:04d}:{tot:04d}:{crc:08X}:{b45encode(payload)}"


def parse_frame(text: str):
    text = text.strip()
    if not text.startswith(MAGIC + ":") or len(text) < HEADER_LEN:
        return None
    try:
        _, kid, idx, tot, crc, body = text.split(":", 5)
        payload = b45decode(body)
    except (ValueError, KeyError):
        return None
    if zlib.crc32(payload) & 0xFFFFFFFF != int(crc, 16):
        return None
    return kid, int(idx), int(tot), payload


def qr_capacity(version: int, ecc: str) -> int:
    import segno
    lo, hi = 1, 8000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            segno.make("A" * mid, version=version, error=ecc,
                       mode="alphanumeric", boost_error=False)
            lo = mid
        except Exception:
            hi = mid - 1
    return lo


def build_frames(data: bytes, label: str, klass: str, version: int, ecc: str,
                 sealed: bool = False, key_sha3_256: str = "", key_len: int = 0,
                 capacity: int = 0):
    cap = capacity or qr_capacity(version, ecc)
    per_frame = ((cap - HEADER_LEN) // 3) * 2
    chunks = [data[i:i + per_frame] for i in range(0, len(data), per_frame)]
    tot = len(chunks)
    fp = fingerprint(data)
    kid = fp[:8]
    manifest = {
        "v": 1, "type": label, "class": klass, "len": len(data),
        "sha3_256": fp, "chunk": per_frame, "frames": tot,
        "qr": f"{version}-{ecc}", "relay": "paper-qr",
    }
    if sealed:
        manifest["sealed"] = True
        manifest["cipher"] = "scrypt-aes-256-gcm"
        if key_len:
            manifest["key_len"] = key_len
        if key_sha3_256:
            manifest["key_sha3_256"] = key_sha3_256
    frames = [make_frame(kid, 0, tot, json.dumps(manifest, separators=(",", ":")).encode())]
    frames += [make_frame(kid, i + 1, tot, c) for i, c in enumerate(chunks)]
    return frames, manifest



# ---------------------------------------------------------------- PDF ------
def draw_qr(c, text: str, x: float, y: float, size: float, version: int, ecc: str):
    """Vector QR, bottom-left corner at (x, y), side length size (points).
    version None lets segno pick the smallest symbol; full frames still land
    on the requested version because the chunk size was derived from it."""
    import segno
    qr = segno.make(text, version=version, error=ecc, mode="alphanumeric",
                    boost_error=False)
    matrix = qr.matrix
    n = len(matrix)
    quiet = 4
    mod = size / (n + 2 * quiet)
    c.setFillColorRGB(0, 0, 0)
    for r, row in enumerate(matrix):
        col = 0
        while col < n:
            if row[col] & 1:
                start = col
                while col < n and row[col] & 1:
                    col += 1
                c.rect(x + (quiet + start) * mod,
                       y + size - (quiet + r + 1) * mod,
                       (col - start) * mod, mod, stroke=0, fill=1)
            else:
                col += 1


def write_pdf(path: str, frames: list, manifest: dict, version: int, ecc: str,
              cols: int, rows: int, node: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    W, H = A4
    margin = 12 * mm
    head = 16 * mm
    foot = 10 * mm
    cell_w = (W - 2 * margin) / cols
    cell_h = (H - 2 * margin - head - foot) / rows
    label_h = 7 * mm
    qsize = min(cell_w - 4 * mm, cell_h - label_h - 2 * mm)

    kid = manifest["sha3_256"][:8]
    tot = manifest["frames"]
    per_page = cols * rows
    data_pages = -(-tot // per_page)
    pages = data_pages + 1
    klass_line = CLASS_LABEL.get(manifest["class"], CLASS_LABEL["unknown"])
    sealed = bool(manifest.get("sealed"))
    verify_fp = manifest.get("key_sha3_256", manifest["sha3_256"])

    c = canvas.Canvas(path, pagesize=A4)
    c.setTitle(f"Wallfacer key-roll {kid}")
    c.setAuthor("ThereminQ-PQC wallfacer_paper_keyroll.py")

    def header_footer(page_no: int, title: str):
        c.setFont("Helvetica-Bold", 11)
        c.drawString(margin, H - margin - 5 * mm, title)
        c.setFont("Helvetica", 8)
        c.drawString(margin, H - margin - 10 * mm, klass_line)
        c.drawRightString(W - margin, H - margin - 5 * mm, f"KID {kid}")
        c.drawRightString(W - margin, H - margin - 10 * mm, f"Sheet {page_no} / {pages}")
        c.setLineWidth(0.5)
        c.line(margin, H - margin - head + 2 * mm, W - margin, H - margin - head + 2 * mm)
        c.line(margin, margin + foot - 2 * mm, W - margin, margin + foot - 2 * mm)
        c.setFont("Courier", 7)
        fp_tag = "ROLL SHA3-256 " if sealed else "SHA3-256 "
        c.drawString(margin, margin + 2 * mm,
                     fp_tag + manifest["sha3_256"][:32] + " " + manifest["sha3_256"][32:])
        c.drawRightString(W - margin, margin + 2 * mm, "WFK1 paper QR relay (off radio/IP)")

    # Cover sheet
    header_footer(1, "WALLFACER OUT-OF-BAND PAPER QR KEY-ROLL")
    y = H - margin - head - 6 * mm
    len_desc = (
        f"{manifest['key_len']:,} bytes key ({manifest['len']:,} bytes sealed)"
        if sealed and manifest.get("key_len")
        else f"{manifest['len']:,} bytes"
    )
    prot_desc = (
        f"SEALED ({manifest.get('cipher', 'scrypt-aes-256-gcm')}) — passphrase required"
        if sealed
        else "Unencrypted — guard sheets physically"
    )
    rows_info = [
        ("Key type", manifest["type"]),
        ("Length", len_desc),
        ("Relay channel", "Paper QR code (air-gapped alternative to radio/IP)"),
        ("Protection", prot_desc),
        ("Node / owner", node or "-"),
        ("Data frames", f"{tot} (frame 0000 is the manifest, below)"),
        ("Frame payload", f"{manifest['chunk']:,} bytes, Base45, CRC32 per frame"),
        ("QR symbol", f"version {version}, ECC {ecc}, alphanumeric mode"),
        ("Layout", f"{cols} x {rows} per sheet, {data_pages} data sheets"),
    ]
    c.setFont("Helvetica", 10)
    for k, v in rows_info:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(margin, y, k)
        c.setFont("Helvetica", 10)
        c.drawString(margin + 38 * mm, y, v)
        y -= 5.5 * mm
    y -= 2.5 * mm
    c.setFont("Helvetica-Bold", 10)
    fp_heading = (
        "Key SHA3-256 fingerprint (verified after unseal; read back on second channel)"
        if sealed
        else "SHA3-256 fingerprint (read back by voice or second channel)"
    )
    c.drawString(margin, y, fp_heading)
    y -= 6 * mm
    c.setFont("Courier-Bold", 12)
    for line in fp_groups(verify_fp):
        c.drawString(margin, y, line)
        y -= 6 * mm
    y -= 4 * mm
    msize = min(80 * mm, y - margin - foot - 40 * mm)
    draw_qr(c, frames[0], margin, y - msize, msize, None, "M")
    c.setFont("Helvetica", 8)
    c.drawString(margin, y - msize - 4 * mm, "Frame 0000 : manifest")
    bx = margin + msize + 8 * mm
    by = y - 4 * mm
    c.setFont("Helvetica-Bold", 10)
    c.drawString(bx, by, "Handling")
    c.setFont("Helvetica", 9)
    handling = [
        "1. Verify the fingerprint with the sender before use.",
        "2. Scan every sheet; order does not matter.",
        "3. Rebuild:  wf-keyroll decode <scans> -o key --expect <SHA3>",
        "4. Passphrase travels separately from these sheets." if sealed
        else "4. Decoder refuses any SHA3-256 mismatch.",
        "5. Shred all sheets after enrolment is confirmed.",
        "6. Never transmit this key over radio or IP.",
    ]
    for line in handling:
        by -= 5 * mm
        c.drawString(bx, by, line)
    c.showPage()

    # Data sheets
    data_frames = frames[1:]
    for p in range(data_pages):
        header_footer(p + 2, f"KEY-ROLL DATA  frames {p * per_page + 1:04d}"
                             f"..{min((p + 1) * per_page, tot):04d} of {tot:04d}")
        for k in range(per_page):
            i = p * per_page + k
            if i >= tot:
                break
            r, col = divmod(k, cols)
            cx = margin + col * cell_w + (cell_w - qsize) / 2
            cy = H - margin - head - (r + 1) * cell_h + label_h
            draw_qr(c, data_frames[i], cx, cy, qsize, None, ecc)
            crc = data_frames[i].split(":")[4]
            c.setFont("Courier-Bold", 8)
            c.drawCentredString(cx + qsize / 2, cy - 3.5 * mm,
                                f"{i + 1:04d}/{tot:04d}  CRC {crc}")
        c.showPage()
    c.save()
    return pages


# ---------------------------------------------------------------- decode ---
def read_qr_texts(path: str) -> list:
    """Return all QR payload strings found in an image, PDF or text dump."""
    low = path.lower()
    if low.endswith((".txt", ".log", ".csv")):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    if low.endswith(".pdf"):
        if not shutil.which("pdftoppm"):
            sys.exit("PDF input needs pdftoppm (poppler-utils)")
        out = []
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["pdftoppm", "-r", "300", "-gray", "-png", path,
                            os.path.join(td, "p")], check=True)
            for f in sorted(os.listdir(td)):
                out += read_qr_texts(os.path.join(td, f))
        return out
    try:
        import zxingcpp
        from PIL import Image
        img = Image.open(path).convert("L")
        return [r.text for r in zxingcpp.read_barcodes(img) if r.text]
    except ImportError:
        pass
    import cv2  # fallback: fine for single or sparse symbols, weak on v40 sheets
    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        print(f"  skip {path}: not an image", file=sys.stderr)
        return []
    det = cv2.QRCodeDetector()
    ok, texts, _, _ = det.detectAndDecodeMulti(img)
    found = [t for t in texts if t] if ok else []
    if not found:
        t, _, _ = det.detectAndDecode(img)
        found = [t] if t else []
    return found


def reassemble_frames(args, unseal: bool = True):
    """Collect, validate, and optionally unseal WFK1 frames from args.inputs."""
    frames = {}
    manifest = None
    kid_seen = set()
    for path in args.inputs:
        texts = read_qr_texts(path)
        new = 0
        for t in texts:
            f = parse_frame(t)
            if not f:
                continue
            kid, idx, tot, payload = f
            kid_seen.add(kid)
            if idx == 0:
                manifest = json.loads(payload)
            elif idx not in frames:
                frames[idx] = (kid, tot, payload)
                new += 1
        print(f"  {path}: {new} new frames")
    if len(kid_seen) > 1:
        sys.exit(f"Mixed key-rolls in input: KIDs {sorted(kid_seen)}")
    if not frames:
        sys.exit("No valid WFK1 frames found")
    tot = next(iter(frames.values()))[1]
    missing = [i for i in range(1, tot + 1) if i not in frames]
    if missing:
        print(f"Missing {len(missing)} of {tot} frames: "
              + ", ".join(f"{m:04d}" for m in missing[:60])
              + (" ..." if len(missing) > 60 else ""), file=sys.stderr)
        sys.exit(2)
    raw = b"".join(frames[i][2] for i in range(1, tot + 1))
    roll_fp = fingerprint(raw)
    kid = next(iter(kid_seen))
    if roll_fp[:8] != kid:
        sys.exit(f"Reassembled key fingerprint {roll_fp[:8]} does not match KID {kid}")
    if manifest:
        if manifest["sha3_256"] != roll_fp or manifest["len"] != len(raw):
            sys.exit("Reassembled payload does not match the manifest")
    else:
        print("Warning: manifest frame 0000 not scanned; verified against KID only",
              file=sys.stderr)

    sealed = is_sealed_payload(raw) or bool(manifest and manifest.get("sealed"))
    if sealed and unseal:
        pw = resolve_passphrase(args, confirm=False)
        try:
            key_data = unseal_payload(raw, pw)
        except Exception as exc:
            sys.exit(f"Failed to unseal paper key-roll (wrong passphrase or tampered data): {exc}")
        key_fp = fingerprint(key_data)
        if manifest:
            if manifest.get("key_sha3_256") and manifest["key_sha3_256"] != key_fp:
                sys.exit("Unsealed key does not match manifest key_sha3_256")
            if manifest.get("key_len") and manifest["key_len"] != len(key_data):
                sys.exit("Unsealed key length does not match manifest key_len")
    else:
        key_data = raw
        key_fp = roll_fp

    if getattr(args, "expect", None):
        expected = args.expect.replace(" ", "").upper()
        if expected != key_fp:
            sys.exit("SHA3-256 differs from --expect fingerprint")

    return key_data, key_fp, roll_fp, manifest, sealed


def cmd_decode(args):
    data, fp, roll_fp, manifest, sealed = reassemble_frames(args, unseal=True)
    write_secret_file(args.output, data, mode=0o600)
    if args.write_checksum:
        chk_path = args.output + ".sha3_256"
        chk_line = f"{fp}  {os.path.basename(args.output)}\n".encode("ascii")
        write_secret_file(chk_path, chk_line, mode=0o600)
    label, _ = detect_key_type(data)
    if manifest and manifest.get("type"):
        label = manifest["type"]
    seal_note = " [unsealed]" if sealed else ""
    print(f"Wrote {args.output}: {len(data):,} bytes, {label}{seal_note} (mode 600)")
    if args.write_checksum:
        print(f"Wrote {args.output}.sha3_256 (mode 600)")
    print("SHA3-256:")
    for line in fp_groups(fp):
        print("  " + line)


def cmd_verify(args):
    data, fp, roll_fp, manifest, sealed = reassemble_frames(args, unseal=not args.no_unseal)
    if sealed and args.no_unseal:
        label = manifest.get("type", "sealed key-roll") if manifest else "sealed key-roll"
        print(f"Verified sealed roll (unseal skipped): {len(data):,} bytes, {label}")
        print("Roll SHA3-256:")
        for line in fp_groups(roll_fp):
            print("  " + line)
        return
    label, _ = detect_key_type(data)
    if manifest and manifest.get("type"):
        label = manifest["type"]
    seal_note = " [unsealed]" if sealed else ""
    print(f"Verified OK: {len(data):,} bytes, {label}{seal_note} (nothing written)")
    print("SHA3-256:")
    for line in fp_groups(fp):
        print("  " + line)


# ---------------------------------------------------------------- encode ---
def cmd_encode(args):
    with open(args.key, "rb") as fh:
        raw_data = fh.read()
    if not raw_data:
        sys.exit("Key file is empty")
    label, klass = detect_key_type(raw_data)
    if klass == "secret-key" and not args.allow_secret:
        sys.exit(f"{label}: private keys are guarded by default. "
                 "Pass --allow-secret (recommended with --seal) for paper QR relay.")
    if args.type:
        label = args.type

    want_seal = bool(args.seal or args.passphrase_file or args.passphrase_env)
    key_fp = fingerprint(raw_data)
    if want_seal:
        pw = resolve_passphrase(args, confirm=True)
        payload_data = seal_payload(raw_data, pw)
    else:
        payload_data = raw_data

    frames, manifest = build_frames(
        payload_data, label, klass, args.qr_version, args.ecc,
        sealed=want_seal, key_sha3_256=key_fp, key_len=len(raw_data),
    )
    pages = None
    if args.output:
        pages = write_pdf(args.output, frames, manifest, args.qr_version, args.ecc,
                          args.cols, args.rows, args.node)
    if args.frames_out:
        write_secret_file(args.frames_out, ("\n".join(frames) + "\n").encode("ascii"), mode=0o600)
    if args.png_dir:
        import segno
        os.makedirs(args.png_dir, exist_ok=True)
        for f in frames:
            idx = f.split(":")[2]
            segno.make(f, error=args.ecc, mode="alphanumeric", boost_error=False
                       ).save(os.path.join(args.png_dir, f"{manifest['sha3_256'][:8]}_{idx}.png"),
                              scale=4, border=4)
    print(f"Key       {label}, {len(raw_data):,} bytes")
    print(f"Relay     paper-qr ({'SEALED scrypt+AES-256-GCM' if want_seal else 'unencrypted'})")
    print(f"KID       {manifest['sha3_256'][:8]}")
    print(f"Frames    {manifest['frames']} data + 1 manifest, {manifest['chunk']} bytes each")
    print(f"QR        v{args.qr_version}-{args.ecc}, {args.cols}x{args.rows} per sheet")
    if pages is not None:
        print(f"Sheets    {pages} (A4) -> {args.output}")
    if args.frames_out:
        print(f"FramesOut {args.frames_out} (mode 600)")
    print("Key SHA3-256:" if want_seal else "SHA3-256:")
    for line in fp_groups(key_fp):
        print("  " + line)
    if want_seal:
        print("Roll SHA3-256:")
        for line in fp_groups(manifest["sha3_256"]):
            print("  " + line)


def cmd_psk(args):
    data = secrets.token_bytes(args.bytes)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    print(f"Wrote {args.output}: {args.bytes} random bytes (mode 600)")
    print("SHA3-256:")
    for line in fp_groups(fingerprint(data)):
        print("  " + line)


def _add_passphrase_args(parser):
    parser.add_argument("--passphrase-file", help="read seal passphrase from file (first line)")
    parser.add_argument("--passphrase-env", help="read seal passphrase from environment variable")


def main():
    ap = argparse.ArgumentParser(
        description="Wallfacer out-of-band paper QR key-roll (alternative to radio/IP relay)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("encode", help="key file -> printable QR key-roll PDF")
    e.add_argument("key", help="key file (e.g. Rosenpass pqpk/pqsk, PKI ML-DSA/ML-KEM .key, PSK)")
    e.add_argument("-o", "--output", default="keyroll.pdf",
                   help="output PDF path (default keyroll.pdf; pass '' to skip PDF with --frames-out)")
    e.add_argument("--qr-version", type=int, default=40, choices=range(10, 41),
                   metavar="10..40", help="symbol version for full frames (default 40)")
    e.add_argument("--ecc", default="M", choices="LMQH")
    e.add_argument("--cols", type=int, default=3)
    e.add_argument("--rows", type=int, default=4)
    e.add_argument("--node", default="", help="node / owner name printed on the cover")
    e.add_argument("--type", help="override the detected key type label")
    e.add_argument("--png-dir", help="also write one PNG per frame here")
    e.add_argument("--frames-out", help="also write raw WFK1 frames (one per line, mode 600)")
    e.add_argument("--allow-secret", action="store_true",
                   help="permit encoding a detected PQC private key for paper QR relay")
    e.add_argument("--seal", action="store_true",
                   help="passphrase-encrypt payload (scrypt + AES-256-GCM) for paper transport")
    _add_passphrase_args(e)
    e.set_defaults(func=cmd_encode)

    d = sub.add_parser("decode", help="scans / PDF / text dumps -> key file")
    d.add_argument("inputs", nargs="+", help="PNG/JPG scans, PDF, or .txt (one frame per line)")
    d.add_argument("-o", "--output", required=True)
    d.add_argument("--expect", help="SHA3-256 read back from the sender, hex")
    d.add_argument("--write-checksum", action="store_true",
                   help="also write <output>.sha3_256 (mode 600) for gateway startup verification")
    _add_passphrase_args(d)
    d.set_defaults(func=cmd_decode)

    v = sub.add_parser("verify", help="verify scans / PDF / text dumps without writing key")
    v.add_argument("inputs", nargs="+", help="PNG/JPG scans, PDF, or .txt (one frame per line)")
    v.add_argument("--expect", help="SHA3-256 read back from the sender, hex")
    v.add_argument("--no-unseal", action="store_true",
                   help="check WFK1 framing and roll SHA3-256 without prompting for passphrase")
    _add_passphrase_args(v)
    v.set_defaults(func=cmd_verify)

    p = sub.add_parser("psk", help="generate a random pre-shared key file")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--bytes", type=int, default=32)
    p.set_defaults(func=cmd_psk)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

