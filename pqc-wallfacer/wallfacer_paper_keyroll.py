#!/usr/bin/env python3
"""
wf_paper_keyroll.py : Wallfacer out-of-band paper key-roll

Prints a post-quantum key as a numbered set of QR codes on A4 paper, and
reassembles the exact key file from scans of that paper.

Context (ThereminQ-PQC, pqc-wallfacer):
  The Rosenpass static key is Classic McEliece 460896 (524,160 bytes). It
  must never cross the wire or the radio link. It travels out-of-band as a
  physical key-roll; the LoRa / Reticulum link then only carries the 188-byte
  McEliece ciphertexts and fixed-size envelopes inside the 500-byte payload.

Commands
  encode   key file            -> PDF key-roll (plus optional per-frame PNGs)
  decode   scans / text dumps  -> byte-identical key file, SHA3-256 verified
  psk      new random PSK file (32 bytes default) for the envelope layer

Frame format (QR alphanumeric mode, scanner-safe, RFC 9285 Base45 payload)
  WFK1:<KID>:<IDX>:<TOT>:<CRC32>:<BASE45>
  KID   first 8 hex of SHA3-256(key), uppercase
  IDX   0000 = manifest frame, 0001..TOT = data frames
  CRC32 of the decoded payload bytes of that frame

Dependencies
  encode : segno, reportlab
  decode : zxing-cpp + pillow (dense v40 sheets), opencv-python-headless as
           fallback, poppler-utils for PDF input
"""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import zlib

MAGIC = "WFK1"
HEADER_LEN = len(MAGIC) + 1 + 8 + 1 + 4 + 1 + 4 + 1 + 8 + 1  # 33 chars

# Known key sizes, for labelling and for refusing secret keys.
KEY_TYPES = {
    524160: ("Classic McEliece 460896 public key (Rosenpass static)", "public"),
    261120: ("Classic McEliece 348864 public key", "public"),
    1044992: ("Classic McEliece 6688128 public key", "public"),
    1047319: ("Classic McEliece 6960119 public key", "public"),
    1357824: ("Classic McEliece 8192128 public key", "public"),
    1184: ("ML-KEM-768 public key", "public"),
    1568: ("ML-KEM-1024 public key", "public"),
    2592: ("ML-DSA-87 public key", "public"),
    13608: ("Classic McEliece 460896 SECRET key", "secret-key"),
    6492: ("Classic McEliece 348864 SECRET key", "secret-key"),
    32: ("256-bit pre-shared key", "psk"),
    64: ("512-bit pre-shared key", "psk"),
}

CLASS_LABEL = {
    "public": "RESTRICTED : public key, keep off the wire (initiator deniability)",
    "psk": "SECRET : symmetric key material, destroy after enrolment",
    "secret-key": "SECRET : private key material",
    "unknown": "RESTRICTED : unclassified key material",
}

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


def build_frames(data: bytes, label: str, klass: str, version: int, ecc: str):
    cap = qr_capacity(version, ecc)
    per_frame = ((cap - HEADER_LEN) // 3) * 2
    chunks = [data[i:i + per_frame] for i in range(0, len(data), per_frame)]
    tot = len(chunks)
    fp = fingerprint(data)
    kid = fp[:8]
    manifest = {
        "v": 1, "type": label, "class": klass, "len": len(data),
        "sha3_256": fp, "chunk": per_frame, "frames": tot,
        "qr": f"{version}-{ecc}",
    }
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

    c = canvas.Canvas(path, pagesize=A4)
    c.setTitle(f"Wallfacer key-roll {kid}")
    c.setAuthor("ThereminQ-PQC wf_paper_keyroll.py")

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
        c.drawString(margin, margin + 2 * mm,
                     "SHA3-256 " + manifest["sha3_256"][:32] + " " + manifest["sha3_256"][32:])
        c.drawRightString(W - margin, margin + 2 * mm, "WFK1 out-of-band key-roll")

    # Cover sheet
    header_footer(1, "WALLFACER OUT-OF-BAND KEY-ROLL")
    y = H - margin - head - 6 * mm
    rows_info = [
        ("Key type", manifest["type"]),
        ("Length", f"{manifest['len']:,} bytes"),
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
        y -= 6 * mm
    y -= 3 * mm
    c.setFont("Helvetica-Bold", 10)
    c.drawString(margin, y, "SHA3-256 fingerprint (read back by voice or second channel)")
    y -= 6 * mm
    c.setFont("Courier-Bold", 12)
    for line in fp_groups(manifest["sha3_256"]):
        c.drawString(margin, y, line)
        y -= 6 * mm
    y -= 4 * mm
    msize = min(85 * mm, y - margin - foot - 40 * mm)
    draw_qr(c, frames[0], margin, y - msize, msize, None, "M")
    c.setFont("Helvetica", 8)
    c.drawString(margin, y - msize - 4 * mm, "Frame 0000 : manifest")
    bx = margin + msize + 8 * mm
    by = y - 4 * mm
    c.setFont("Helvetica-Bold", 10)
    c.drawString(bx, by, "Handling")
    c.setFont("Helvetica", 9)
    for line in [
        "1. Verify the fingerprint with the sender before use.",
        "2. Scan every sheet; order does not matter.",
        "3. Rebuild:  wf_paper_keyroll.py decode <scans> -o key",
        "4. Decoder refuses any SHA3-256 mismatch.",
        "5. Shred all sheets after enrolment is confirmed.",
        "6. Never transmit this key over radio or IP.",
    ]:
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


def cmd_decode(args):
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
    data = b"".join(frames[i][2] for i in range(1, tot + 1))
    fp = fingerprint(data)
    kid = next(iter(kid_seen))
    if fp[:8] != kid:
        sys.exit(f"Reassembled key fingerprint {fp[:8]} does not match KID {kid}")
    if manifest:
        if manifest["sha3_256"] != fp or manifest["len"] != len(data):
            sys.exit("Reassembled key does not match the manifest")
    else:
        print("Warning: manifest frame 0000 not scanned; verified against KID only",
              file=sys.stderr)
    if args.expect and args.expect.replace(" ", "").upper() != fp:
        sys.exit("SHA3-256 differs from --expect fingerprint")
    with open(args.output, "wb") as fh:
        fh.write(data)
    os.chmod(args.output, 0o600)
    label = KEY_TYPES.get(len(data), ("unknown", ""))[0]
    print(f"Wrote {args.output}: {len(data):,} bytes, {label}")
    print("SHA3-256:")
    for line in fp_groups(fp):
        print("  " + line)


# ---------------------------------------------------------------- encode ---
def cmd_encode(args):
    with open(args.key, "rb") as fh:
        data = fh.read()
    if not data:
        sys.exit("Key file is empty")
    label, klass = KEY_TYPES.get(len(data), (f"{len(data)}-byte key material", "unknown"))
    if klass == "secret-key" and not args.allow_secret:
        sys.exit(f"{label}: secret keys never leave the node. "
                 "Use --allow-secret only for a sealed backup roll.")
    if args.type:
        label = args.type
    frames, manifest = build_frames(data, label, klass, args.qr_version, args.ecc)
    pages = write_pdf(args.output, frames, manifest, args.qr_version, args.ecc,
                      args.cols, args.rows, args.node)
    if args.png_dir:
        import segno
        os.makedirs(args.png_dir, exist_ok=True)
        for f in frames:
            idx = f.split(":")[2]
            segno.make(f, error=args.ecc, mode="alphanumeric", boost_error=False
                       ).save(os.path.join(args.png_dir, f"{manifest['sha3_256'][:8]}_{idx}.png"),
                              scale=4, border=4)
    print(f"Key       {label}, {len(data):,} bytes")
    print(f"KID       {manifest['sha3_256'][:8]}")
    print(f"Frames    {manifest['frames']} data + 1 manifest, {manifest['chunk']} bytes each")
    print(f"QR        v{args.qr_version}-{args.ecc}, {args.cols}x{args.rows} per sheet")
    print(f"Sheets    {pages} (A4) -> {args.output}")
    print("SHA3-256:")
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


def main():
    ap = argparse.ArgumentParser(description="Wallfacer out-of-band paper key-roll")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("encode", help="key file -> printable QR key-roll PDF")
    e.add_argument("key", help="raw key file, e.g. Rosenpass pub/pqpk")
    e.add_argument("-o", "--output", default="keyroll.pdf")
    e.add_argument("--qr-version", type=int, default=40, choices=range(10, 41),
                   metavar="10..40", help="symbol version for full frames (default 40)")
    e.add_argument("--ecc", default="M", choices="LMQH")
    e.add_argument("--cols", type=int, default=3)
    e.add_argument("--rows", type=int, default=4)
    e.add_argument("--node", default="", help="node / owner name printed on the cover")
    e.add_argument("--type", help="override the detected key type label")
    e.add_argument("--png-dir", help="also write one PNG per frame here")
    e.add_argument("--allow-secret", action="store_true",
                   help="permit printing a detected secret key (sealed backup only)")
    e.set_defaults(func=cmd_encode)

    d = sub.add_parser("decode", help="scans / PDF / text dumps -> key file")
    d.add_argument("inputs", nargs="+", help="PNG/JPG scans, PDF, or .txt (one frame per line)")
    d.add_argument("-o", "--output", required=True)
    d.add_argument("--expect", help="SHA3-256 read back from the sender, hex")
    d.set_defaults(func=cmd_decode)

    p = sub.add_parser("psk", help="generate a random pre-shared key file")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--bytes", type=int, default=32)
    p.set_defaults(func=cmd_psk)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
