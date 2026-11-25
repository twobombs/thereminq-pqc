#!/usr/bin/env python3
"""Unit and integration tests for wallfacer_paper_keyroll.py and paper QR workflow."""

import base64
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "wallfacer_paper_keyroll.py"
GATEWAY_ENTRY = ROOT / "infrastructure" / "gateway" / "gateway-entrypoint.sh"
WF_CA = ROOT / "infrastructure" / "pki" / "wf-ca"
BUILD_SH = ROOT / "infrastructure" / "build.sh"

spec = importlib.util.spec_from_file_location("wallfacer_paper_keyroll", SCRIPT)
kr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kr)

HAS_QR_STACK = all(
    importlib.util.find_spec(m) is not None
    for m in ("segno", "reportlab", "zxingcpp", "PIL")
) and shutil.which("pdftoppm") is not None


class Base45AndFramingTests(unittest.TestCase):
    def test_base45_round_trip(self):
        for sample in (b"", b"\x00", b"\xff", b"Wallfacer", os.urandom(257), os.urandom(512)):
            enc = kr.b45encode(sample)
            self.assertEqual(kr.b45decode(enc), sample)
            self.assertTrue(all(c in kr.B45 for c in enc))

    def test_frame_crc_rejects_corruption(self):
        payload = b"post-quantum-key-bytes"
        frame = kr.make_frame("ABCDEF01", 1, 3, payload)
        parsed = kr.parse_frame(frame)
        self.assertEqual(parsed, ("ABCDEF01", 1, 3, payload))
        # Flip last character -> bad CRC or Base45
        bad = frame[:-1] + ("0" if frame[-1] != "0" else "1")
        self.assertIsNone(kr.parse_frame(bad))


class KeyDetectionTests(unittest.TestCase):
    def test_raw_pqc_private_and_public_sizes(self):
        cases = [
            (524160, "public", "460896 public"),
            (13608, "secret-key", "460896 SECRET"),
            (2400, "secret-key", "ML-KEM-768 SECRET"),
            (3168, "secret-key", "ML-KEM-1024 SECRET"),
            (4032, "secret-key", "ML-DSA-65 SECRET"),
            (4896, "secret-key", "ML-DSA-87 SECRET"),
            (128, "secret-key", "SLH-DSA-SHA2-256s SECRET"),
            (32, "psk", "256-bit"),
        ]
        for size, expected_class, substr in cases:
            label, klass = kr.detect_key_type(b"\x42" * size)
            self.assertEqual(klass, expected_class, f"size={size}")
            self.assertIn(substr, label)

    def test_pem_pqc_detection(self):
        # Embed ML-DSA-87 OID in a fake PKCS#8 PEM body
        der = b"\x30\x20\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13" + b"\x04\x10" + b"\xaa" * 16
        b64 = base64.b64encode(der).decode("ascii")
        priv_pem = f"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n".encode()
        pub_pem = f"-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n".encode()
        enc_pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{b64}\n-----END ENCRYPTED PRIVATE KEY-----\n".encode()

        lbl, cls = kr.detect_key_type(priv_pem)
        self.assertEqual(cls, "secret-key")
        self.assertIn("ML-DSA-87", lbl)

        lbl, cls = kr.detect_key_type(pub_pem)
        self.assertEqual(cls, "public")
        self.assertIn("ML-DSA-87", lbl)

        lbl, cls = kr.detect_key_type(enc_pem)
        self.assertEqual(cls, "secret-key")
        self.assertIn("encrypted private key", lbl)


class SealingTests(unittest.TestCase):
    def test_seal_unseal_round_trip(self):
        secret = os.urandom(13608)  # Classic McEliece 460896 secret key size
        blob = kr.seal_payload(secret, "correct-horse-pqc-battery")
        self.assertTrue(kr.is_sealed_payload(blob))
        self.assertEqual(kr.unseal_payload(blob, "correct-horse-pqc-battery"), secret)

    def test_seal_rejects_wrong_passphrase_and_tamper(self):
        secret = os.urandom(4896)  # ML-DSA-87 secret key size
        blob = kr.seal_payload(secret, "right-pass")
        with self.assertRaises(Exception):
            kr.unseal_payload(blob, "wrong-pass")
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(Exception):
            kr.unseal_payload(bytes(tampered), "right-pass")


class PaperRelayWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _run_cli(self, *args, env=None):
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True, text=True, env=run_env,
        )

    def test_refuses_private_key_without_allow_secret(self):
        pqsk = self.tmp / "pqsk"
        pqsk.write_bytes(os.urandom(13608))
        res = self._run_cli("encode", str(pqsk), "-o", "")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--allow-secret", res.stderr)

    def test_refuses_pem_private_key_without_allow_secret(self):
        pem = self.tmp / "overlay.key"
        pem.write_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        res = self._run_cli("encode", str(pem), "-o", "")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--allow-secret", res.stderr)

    def test_sealed_private_key_frame_relay_round_trip(self):
        pqsk = os.urandom(13608)
        key_fp = kr.fingerprint(pqsk)
        sealed = kr.seal_payload(pqsk, "wallfacer-relay-pass")
        frames, manifest = kr.build_frames(
            sealed, "Classic McEliece 460896 SECRET key", "secret-key",
            40, "M", sealed=True, key_sha3_256=key_fp, key_len=len(pqsk),
            capacity=3391,
        )
        # 13,608 B + 56 B seal overhead -> 7 data frames + 1 manifest
        self.assertEqual(manifest["frames"], 7)
        self.assertTrue(manifest["sealed"])
        self.assertEqual(manifest["relay"], "paper-qr")

        frames_txt = self.tmp / "frames.txt"
        frames_txt.write_text("\n".join(frames) + "\n", encoding="ascii")
        pw_file = self.tmp / "pass.txt"
        pw_file.write_text("wallfacer-relay-pass\n", encoding="utf-8")

        # 1. Dry-run verify without passphrase (--no-unseal)
        v_no = self._run_cli("verify", str(frames_txt), "--no-unseal")
        self.assertEqual(v_no.returncode, 0, v_no.stderr)
        self.assertIn("unseal skipped", v_no.stdout)

        # 2. Dry-run verify WITH passphrase and --expect
        v_ok = self._run_cli(
            "verify", str(frames_txt),
            "--passphrase-file", str(pw_file),
            "--expect", key_fp,
        )
        self.assertEqual(v_ok.returncode, 0, v_ok.stderr)
        self.assertIn("Verified OK", v_ok.stdout)

        # 3. Decode with wrong passphrase must fail closed and NOT write file
        out_bad = self.tmp / "pqsk_bad"
        d_bad = self._run_cli(
            "decode", str(frames_txt), "-o", str(out_bad),
            "--passphrase-env", "WF_TEST_PW",
            env={"WF_TEST_PW": "wrong-pass"},
        )
        self.assertNotEqual(d_bad.returncode, 0)
        self.assertFalse(out_bad.exists())

        # 4. Decode with wrong --expect must fail closed and NOT write file
        d_bad_fp = self._run_cli(
            "decode", str(frames_txt), "-o", str(out_bad),
            "--passphrase-file", str(pw_file),
            "--expect", "0" * 64,
        )
        self.assertNotEqual(d_bad_fp.returncode, 0)
        self.assertFalse(out_bad.exists())

        # 5. Decode with valid passphrase, --expect, and --write-checksum
        out_ok = self.tmp / "secret" / "pqsk"
        d_ok = self._run_cli(
            "decode", str(frames_txt), "-o", str(out_ok),
            "--passphrase-file", str(pw_file),
            "--expect", key_fp,
            "--write-checksum",
        )
        self.assertEqual(d_ok.returncode, 0, d_ok.stderr)
        self.assertEqual(out_ok.read_bytes(), pqsk)
        self.assertEqual(stat.S_IMODE(out_ok.stat().st_mode), 0o600)

        chk = self.tmp / "secret" / "pqsk.sha3_256"
        self.assertTrue(chk.exists())
        self.assertEqual(stat.S_IMODE(chk.stat().st_mode), 0o600)
        self.assertTrue(chk.read_text().startswith(key_fp + "  pqsk"))

    def test_missing_frame_and_mixed_kid_refused(self):
        k1 = os.urandom(4896)
        f1, _ = kr.build_frames(k1, "ML-DSA-87 SECRET key", "secret-key", 40, "M", capacity=3391)
        # Drop frame 2
        partial = self.tmp / "partial.txt"
        partial.write_text("\n".join([f1[0], f1[1], f1[3]]) + "\n", encoding="ascii")
        res = self._run_cli("decode", str(partial), "-o", str(self.tmp / "out"))
        self.assertEqual(res.returncode, 2)
        self.assertIn("Missing 1", res.stderr)

        k2 = os.urandom(4896)
        f2, _ = kr.build_frames(k2, "ML-DSA-87 SECRET key", "secret-key", 40, "M", capacity=3391)
        mixed = self.tmp / "mixed.txt"
        mixed.write_text("\n".join(f1 + f2) + "\n", encoding="ascii")
        res = self._run_cli("decode", str(mixed), "-o", str(self.tmp / "out"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Mixed key-rolls", res.stderr)

    def test_psk_creates_mode_600_exclusively(self):
        p = self.tmp / "env.psk"
        r1 = self._run_cli("psk", "-o", str(p))
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(len(p.read_bytes()), 32)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        r2 = self._run_cli("psk", "-o", str(p))
        self.assertNotEqual(r2.returncode, 0)

    @unittest.skipUnless(HAS_QR_STACK, "requires segno, reportlab, zxing-cpp, pillow, poppler-utils")
    def test_full_pdf_qr_encode_decode_private_key(self):
        pqsk = self.tmp / "pqsk"
        raw = os.urandom(13608)
        pqsk.write_bytes(raw)
        pdf = self.tmp / "pqsk_sealed.pdf"
        out = self.tmp / "rebuilt_pqsk"
        env = {"WF_TEST_SEAL": "airgap-paper-qr-secret"}

        enc = self._run_cli(
            "encode", str(pqsk), "-o", str(pdf),
            "--node", "wf-node-01", "--allow-secret", "--seal",
            "--passphrase-env", "WF_TEST_SEAL",
            env=env,
        )
        self.assertEqual(enc.returncode, 0, enc.stderr)
        self.assertTrue(pdf.exists() and pdf.stat().st_size > 1000)

        dec = self._run_cli(
            "decode", str(pdf), "-o", str(out),
            "--passphrase-env", "WF_TEST_SEAL",
            "--expect", kr.fingerprint(raw),
            "--write-checksum",
            env=env,
        )
        self.assertEqual(dec.returncode, 0, dec.stderr)
        self.assertEqual(out.read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)


class InfrastructureShellTests(unittest.TestCase):
    def test_shell_syntax(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(GATEWAY_ENTRY)]).returncode, 0)
        self.assertEqual(subprocess.run(["sh", "-n", str(WF_CA)]).returncode, 0)
        self.assertEqual(subprocess.run(["sh", "-n", str(BUILD_SH)]).returncode, 0)

    def test_wf_ca_fingerprint_matches_keyroll(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "test.key"
            data = os.urandom(128)
            f.write_bytes(data)
            res = subprocess.run(
                ["sh", str(WF_CA), "fingerprint", str(f)],
                capture_output=True, text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn(kr.fingerprint(data), res.stdout)

    def test_gateway_paper_qr_pqsk_verification(self):
        """Exercise the verify_pqsk function from gateway-entrypoint.sh directly."""
        # Extract verify_pqsk from gateway-entrypoint.sh
        script_text = GATEWAY_ENTRY.read_text()
        start = script_text.index("verify_pqsk() {")
        end = script_text.index("\n}\n", start) + 3
        fn_body = script_text[start:end]

        with tempfile.TemporaryDirectory() as td:
            sec = Path(td) / "secret"
            sec.mkdir(mode=0o700)
            pqsk = sec / "pqsk"
            raw = os.urandom(13608)
            pqsk.write_bytes(raw)
            os.chmod(pqsk, 0o600)
            fp = kr.fingerprint(raw)
            (sec / "pqsk.sha3_256").write_text(f"{fp}  pqsk\n", encoding="ascii")

            harness = (
                "set -euo pipefail\n"
                "log() { printf '%s\\n' \"$*\"; }\n"
                "die() { printf 'FATAL %s\\n' \"$*\" >&2; exit 1; }\n"
                + fn_body + "\nverify_pqsk\n"
            )
            base_env = os.environ.copy()
            base_env.update({"WF_SECRET": str(sec), "WF_KEY_RELAY": "paper-qr"})

            # Valid key + .sha3_256 passes
            ok = subprocess.run(["bash", "-c", harness], env=base_env, capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn("verified (relay=paper-qr", ok.stdout)

            # Wrong SHA3-256 via env fails closed
            bad_env = dict(base_env, WF_PQSK_SHA3_256="0" * 64)
            bad = subprocess.run(["bash", "-c", harness], env=bad_env, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("SHA3-256 mismatch", bad.stderr)

            # Unsafe permissions (0644) fail closed
            os.chmod(pqsk, 0o644)
            perm = subprocess.run(["bash", "-c", harness], env=base_env, capture_output=True, text=True)
            self.assertNotEqual(perm.returncode, 0)
            self.assertIn("unsafe mode 644", perm.stderr)


if __name__ == "__main__":
    unittest.main()
