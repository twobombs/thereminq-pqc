# wallfacer_paper_keyroll.py (`wf-keyroll`) : out-of-band paper QR key-roll

Prints a post-quantum key as numbered QR frames on A4 and rebuilds the byte-identical key file from scans. Implements the air-gapped paper QR alternative to the LoRa / Reticulum radio network (and IP) in the Wallfacer workflow:

- **Static public keys**: the Classic McEliece 460896 static key (`pub/pqpk`, 524,160 bytes) never crosses IP or the radio link; the radio only carries 188-byte Rosenpass ciphertexts and fixed-size envelopes inside the 500-byte payload.
- **PQC private keys (radio-network alternative)**: when the radio network is unavailable, denied, or disallowed for private key material, a node's PQC private key (`pqsk`, ML-DSA-87, ML-KEM-768/1024, SLH-DSA-SHA2-256s, or OpenSSL PKCS#8 PEM) can be relayed physically on **2 A4 sheets** using `--allow-secret --seal` (passphrase-encrypted with `scrypt` + `AES-256-GCM`) and verified on gateway startup (`WF_KEY_RELAY=paper-qr`).

## Install

| Role | Packages |
| --- | --- |
| Encode | `pip install segno reportlab cryptography` (`cryptography` needed for `--seal`) |
| Decode | `pip install zxing-cpp pillow cryptography` (`opencv-python-headless` fallback), `poppler-utils` for PDF input |
| Container | `docker compose --profile offline run --rm keyroll wf-keyroll ...` (see `infrastructure/README.md`) |

## Commands

| Task | Command |
| --- | --- |
| Print Rosenpass static public key | `./wallfacer_paper_keyroll.py encode pub/pqpk -o keyroll.pdf --node wf-node-01` |
| Relay PQC private key (sealed, recommended) | `./wallfacer_paper_keyroll.py encode secret/rosenpass/pqsk -o pqsk-sealed.pdf --node wf-node-01 --allow-secret --seal` |
| Relay PKI ML-DSA-87 private key (sealed) | `./wallfacer_paper_keyroll.py encode pki/keys/overlay.key -o overlay-key.pdf --allow-secret --seal --passphrase-file seal.pass` |
| Rebuild PQC private key + gateway checksum | `./wallfacer_paper_keyroll.py decode scans/*.png -o runtime/secret/rosenpass/pqsk --expect <KEY-SHA3-256> --write-checksum` |
| Dry-run verify scans (without writing key) | `./wallfacer_paper_keyroll.py verify scans/*.png --expect <KEY-SHA3-256>` (add `--no-unseal` to check framing only) |
| New envelope PSK | `./wallfacer_paper_keyroll.py psk -o envelope.psk` |
| Print PSK | `./wallfacer_paper_keyroll.py encode envelope.psk -o psk.pdf` |
| Rebuild from phone-app text | `./wallfacer_paper_keyroll.py decode frames.txt -o pqpk` (one frame per line) |
| Per-frame PNGs / text frames as well | add `--png-dir frames/` and/or `--frames-out frames.txt` to `encode` |

Passphrases for `--seal` / sealed `decode` can be supplied interactively on a TTY, via `--passphrase-file <path>`, or via `--passphrase-env <VAR>`. Always transport the passphrase over a separate channel from the printed sheets.

## Frame format

`WFK1:<KID>:<IDX>:<TOT>:<CRC32>:<BASE45>`

| Field | Content |
| --- | --- |
| `KID` | First 8 hex of SHA3-256(framed payload) |
| `IDX` | `0000` manifest (JSON: type, class, relay, length, full SHA3-256, frame count, and seal metadata when `--seal` is used), `0001..TOT` data |
| `CRC32` | Over the decoded payload of that frame; bad frames are dropped, not trusted |
| Payload | RFC 9285 Base45 in QR alphanumeric mode: 97 % of binary density, no scanner charset mangling |
| Seal (`--seal`) | Optional `WFSEAL1` envelope (`scrypt` N=32768, r=8, p=1 + `AES-256-GCM` with header AAD, +56 bytes overhead) |

## Sheet count (A4)

| Key | Bytes | v40-M 3x4 (default) | v40-M 2x3 | v30-M 3x4 |
| --- | --- | --- | --- | --- |
| Classic McEliece 460896 pk | 524,160 | 236 frames, 21 sheets | 41 sheets | 397 frames, 35 sheets |
| Classic McEliece 348864 pk | 261,120 | 118 frames, 11 sheets | 21 sheets | 18 sheets |
| Classic McEliece 460896 sk (`pqsk`) | 13,608 | 8 frames, 2 sheets | 3 sheets | 12 frames, 2 sheets |
| ML-DSA-87 sk (raw / PEM) | 4,896 / ~6,500 | 4 frames, 2 sheets | 2 sheets | 5 frames, 2 sheets |
| ML-KEM-768 / 1024 sk (raw) | 2,400 / 3,168 | 3 frames, 2 sheets | 2 sheets | 4 frames, 2 sheets |
| ML-KEM-768 pk | 1,184 | 2 sheets | 2 sheets | 2 sheets |
| SLH-DSA-SHA2-256s sk (raw) | 128 | 2 sheets | 2 sheets | 2 sheets |
| PSK (256-bit) | 32 | 2 sheets, small symbol | 2 sheets | 2 sheets |

| Layout | Module size | Read with |
| --- | --- | --- |
| v40-M 3x4 | about 0.28 mm | Flatbed scan at 600 dpi |
| v40-M 2x3 | about 0.45 mm | Flatbed at 300 dpi or phone camera |

## Verified

| Test | Result |
| --- | --- |
| 524,160-byte key, encode, PDF rendered at 300 dpi, decode | Byte-identical, 235/235 frames |
| Sheet blurred, rotated 1.5 degrees, salt noise, JPEG q70 | 11/12 frames read; decoder lists the missing frame numbers |
| 13,608-byte Classic McEliece 460896 secret key (`--allow-secret --seal`) | Byte-identical round-trip (7 data frames, 2 A4 sheets); wrong passphrase and tampered ciphertext refused |
| ML-DSA-87 / ML-KEM-768 / ML-KEM-1024 / SLH-DSA / PEM private keys | Detected and refused unless `--allow-secret` |
| 32-byte PSK round trip with `--expect` | Byte-identical; wrong fingerprint refused |
| Gateway paper-QR handoff (`--write-checksum` + `WF_KEY_RELAY=paper-qr`) | Verified SHA3-256 and `0600` mode check before starting Rosenpass |

## Safety rules built in

| Rule | Behaviour |
| --- | --- |
| Secret keys guarded by default | Detected raw PQC private keys (McEliece, ML-KEM, ML-DSA, SLH-DSA) and PEM `PRIVATE KEY` blocks are refused unless `--allow-secret` is explicitly passed |
| Confidentiality in transit | Use `--seal` (`scrypt` + `AES-256-GCM`) when relaying PQC private keys on paper; deliver the passphrase out-of-band from the printed sheets |
| Integrity | CRC32 per frame, KID check, manifest SHA3-256 check, AES-GCM tag (when sealed), optional `--expect` against plaintext key SHA3-256 |
| Authenticity | Not provided by the paper itself: read the SHA3-256 back over a second channel before enrolment |
| Output | Rebuilt key and optional `.sha3_256` checksum written atomically with mode `600` from inode creation; PSK files created exclusively with mode `600` |
