# wf_paper_keyroll.py : out-of-band paper key-roll

Prints a post-quantum key as numbered QR frames on A4 and rebuilds the byte-identical key file from scans. Implements the out-of-band keying step of the Wallfacer design: the Classic McEliece 460896 static key never crosses IP or the LoRa / Reticulum link; the radio only carries 188-byte Rosenpass ciphertexts and fixed-size envelopes inside the 500-byte payload.

## Install

| Role | Packages |
| --- | --- |
| Encode | `pip install segno reportlab` |
| Decode | `pip install zxing-cpp pillow` (`opencv-python-headless` fallback), `poppler-utils` for PDF input |

## Commands

| Task | Command |
| --- | --- |
| Print Rosenpass static key | `./wf_paper_keyroll.py encode pub/pqpk -o keyroll.pdf --node wf-node-01` |
| New envelope PSK | `./wf_paper_keyroll.py psk -o envelope.psk` |
| Print PSK | `./wf_paper_keyroll.py encode envelope.psk -o psk.pdf` |
| Rebuild from scans | `./wf_paper_keyroll.py decode scans/*.png -o pqpk --expect <SHA3-256>` |
| Rebuild from phone-app text | `./wf_paper_keyroll.py decode frames.txt -o pqpk` (one frame per line) |
| Per-frame PNGs as well | add `--png-dir frames/` to `encode` |

## Frame format

`WFK1:<KID>:<IDX>:<TOT>:<CRC32>:<BASE45>`

| Field | Content |
| --- | --- |
| `KID` | First 8 hex of SHA3-256(key) |
| `IDX` | `0000` manifest (JSON: type, length, full SHA3-256, frame count), `0001..TOT` data |
| `CRC32` | Over the decoded payload of that frame; bad frames are dropped, not trusted |
| Payload | RFC 9285 Base45 in QR alphanumeric mode: 97 % of binary density, no scanner charset mangling |

## Sheet count (A4)

| Key | Bytes | v40-M 3x4 (default) | v40-M 2x3 | v30-M 3x4 |
| --- | --- | --- | --- | --- |
| Classic McEliece 460896 pk | 524,160 | 236 frames, 21 sheets | 41 sheets | 397 frames, 35 sheets |
| Classic McEliece 348864 pk | 261,120 | 118 frames, 11 sheets | 21 sheets | 18 sheets |
| ML-KEM-768 pk | 1,184 | 2 sheets | 2 sheets | 2 sheets |
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
| 32-byte PSK round trip with `--expect` | Byte-identical; wrong fingerprint refused |
| 13,608-byte McEliece secret key | Refused unless `--allow-secret` |

## Safety rules built in

| Rule | Behaviour |
| --- | --- |
| Secret keys stay on the node | Detected secret-key sizes refused by default |
| Integrity | CRC32 per frame, KID check, manifest SHA3-256 check, optional `--expect` |
| Authenticity | Not provided by the paper itself: read the SHA3-256 back over a second channel before enrolment |
| Output | Rebuilt key written mode 600; PSK files created exclusively, mode 600 |
