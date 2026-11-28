<img width="1016" height="443" alt="Screenshot from 2026-01-01 15-36-30" src="https://github.com/user-attachments/assets/b5c8d613-5dac-484a-baef-0032dfd8e484" />

# ThereminQ-PQC

Post-Quantum Cryptography (PQC) infrastructure, enclave blueprints, emergency web TLS migration tooling, and legacy PQC/cryptanalysis containers. Built around an **OpenSSL 3.5 / Debian 13 (`trixie`)** baseline with NIST-standardized post-quantum primitives (**ML-DSA**, **ML-KEM**, **SLH-DSA**) and **Classic McEliece** via Rosenpass.

## Repository Overview

| Directory / File | Description | Documentation |
| --- | --- | --- |
| [`pqc-wallfacer/`](pqc-wallfacer/) | Zero-trust post-quantum enclave for safeguarded LLM inference, autonomous agent workspaces, air-gapped key transport, and PQC web ingress | [Overview](pqc-wallfacer/README.md) |
| [`pqc-wallfacer/documentation/`](pqc-wallfacer/documentation/) | Wallfacer doctrine, enclave blueprint, architecture flow, four-layer security model, and arXiv references | [Documentation](pqc-wallfacer/documentation/README.md) |
| [`pqc-wallfacer/infrastructure/`](pqc-wallfacer/infrastructure/) | Hardened Docker enclave stack (8 images), `compose.yaml`, offline PKI, WireGuard + Rosenpass gateway, semantic LLM gatekeeper, Vulkan inference, and ThereminQ UI | [Infrastructure Guide](pqc-wallfacer/infrastructure/README.md) |
| [`pqc-wallfacer/wallfacer_paper_keyroll.py`](pqc-wallfacer/wallfacer_paper_keyroll.py) | Out-of-band A4 paper QR key-roll (`wf-keyroll`) for relaying PQC private keys, static keys, and PSKs without radio or IP | [Paper Key-Roll Guide](pqc-wallfacer/README-paper-keyroll.md) |
| [`pqc-wallfacer/web-ingress/`](pqc-wallfacer/web-ingress/) | Emergency dual-stack PQC certificate migration kit (classical + ML-DSA) for nginx, Apache httpd, edge containers, and Kubernetes ingress | [Web Ingress Guide](pqc-wallfacer/web-ingress/README.md) |
| [`pqc-legacy-apps/`](pqc-legacy-apps/) | Legacy experimental PQC & cryptanalysis containers (`dockerfiles/`, `miscfiles/`, `runfiles/`) | See [Legacy Apps](#legacy-containerized-apps-pqc-legacy-apps) |

---

## Wallfacer PQC Enclave (`pqc-wallfacer/`)

### 1. Architecture & Doctrine (`pqc-wallfacer/documentation/`)

Defines the four-layer zero-trust architecture detailed in [`The_Wallfacer_Doctrine.pdf`](pqc-wallfacer/documentation/The_Wallfacer_Doctrine.pdf), [`Wallfacer_Enclave_Blueprint.pdf`](pqc-wallfacer/documentation/Wallfacer_Enclave_Blueprint.pdf), and [`wallfacer-architecture-flow.jpeg`](pqc-wallfacer/documentation/wallfacer-architecture-flow.jpeg):

1. **Layer 1 — Dark Perimeter (WireGuard & Rosenpass)**: Hybrid post-quantum VPN tunnel (Classic McEliece / ML-KEM-768) with nftables default-drop enforcement, PSK hold-down, and out-of-band key establishment (LoRa / Reticulum radio or paper QR relay).
2. **Layer 2 — Private PQC PKI**: Offline OpenSSL 3.5 Certificate Authority using ML-DSA-87, SLH-DSA, and ML-KEM-768 with cold-storage roots.
3. **Layer 3 — Artifact Provenance Guard**: Fail-closed ML-DSA-87 signature verification (`wf-sign` / `wf-verify`) for peer bundles, container artifacts, and GGUF model weights.
4. **Layer 4 — Semantic API Gatekeeper**: Allow-list policy, syntax/entropy firewall, and CPU-hosted Merlin semantic classifier sitting in front of air-gapped local LLM inference.

### 2. Enclave Container Infrastructure (`pqc-wallfacer/infrastructure/`)

First-slice hardened container stack built on `debian:trixie-slim` (OpenSSL 3.5) with [`build.sh`](pqc-wallfacer/infrastructure/build.sh) and [`compose.yaml`](pqc-wallfacer/infrastructure/compose.yaml):

| Image | Role |
| --- | --- |
| `wallfacer/base` | OpenSSL 3.5 policy, `wf-verify`, unprivileged `wf` user |
| `wallfacer/pki` | Offline CA (`wf-ca`) and bundle/model signer (`wf-sign`), no network |
| `wallfacer/keyroll` | Air-gapped paper QR encoder/decoder/verifier (`wf-keyroll`), no network |
| `wallfacer/gateway` | WireGuard + Rosenpass tunnel, nftables default-drop, PSK settle/stale hold-down, paper-QR key verification |
| `wallfacer/gatekeeper` | Tool-call allow-list, syntax/entropy LLM firewall, Merlin CPU classifier, OpenAI-compatible `/v1` proxy |
| `wallfacer/inference` | `llama.cpp` Vulkan server with fail-closed ML-DSA-87 GGUF verification |
| `wallfacer/ui` | Hardened ThereminQ Jupyter desktop (noVNC, Jupyter, VS Code, PyQrack) with zero egress |
| `wallfacer/ui-door` | `socat` relay exposing UI ports exclusively on the WireGuard interface |

See [`pqc-wallfacer/infrastructure/README.md`](pqc-wallfacer/infrastructure/README.md) for `.env` build pins, runtime layout, and first-run steps.

### 3. Out-of-Band Paper QR Key-Roll (`pqc-wallfacer/wallfacer_paper_keyroll.py`)

An air-gapped physical alternative to the LoRa / Reticulum radio network (`WF_KEY_RELAY=paper-qr`) for moving post-quantum keys on numbered A4 QR sheets using `WFK1` Base45 frames with per-frame CRC32 and SHA3-256 manifest verification:

- **Supported key material**: Classic McEliece 460896/348864 static public keys (`pqpk`) and secret keys (`pqsk`), ML-DSA-65/87, ML-KEM-768/1024, SLH-DSA-SHA2-256s, OpenSSL PKCS#8 PEM private keys, and 256-bit PSKs.
- **Secret-key safeguards**: Raw and PEM PQC private keys are refused by default unless `--allow-secret` is explicitly passed; optional `--seal` wraps keys in a `WFSEAL1` (`scrypt` + `AES-256-GCM`) passphrase envelope (fitting `pqsk` onto 2 A4 sheets).
- **Fail-closed gateway handoff**: Supports dry-run `verify`, atomic mode `0600` writes, `--write-checksum`, and startup SHA3-256 + permission checks in `gateway-entrypoint.sh` (`WF_KEY_RELAY=paper-qr`, `WF_PQSK_SHA3_256`), plus `wf-ca fingerprint` for PKI keys.
- **Containerized workflow**: Available offline via `docker compose --profile offline run --rm keyroll wf-keyroll ...`.

See [`pqc-wallfacer/README-paper-keyroll.md`](pqc-wallfacer/README-paper-keyroll.md) for sheet counts, scanning guidance, and CLI examples.

### 4. Dual-Stack PQC Web Ingress Migration Kit (`pqc-wallfacer/web-ingress/`)

Emergency migration kit for existing websites under the assumption that RSA and ECC certificate authorities are no longer trustworthy. Adds an **ML-DSA** certificate chain alongside the existing classical chain on **nginx**, **Apache httpd**, hardened **edge containers**, and **Kubernetes ingress** without breaking existing clients:

- **CLI tooling**:
  - [`pqc-eval`](pqc-wallfacer/web-ingress/bin/pqc-eval) — Live endpoint readiness grader (`L0 NO-PQC` -> `L1 PQC-KEX` -> `L2 DUAL` -> `L3 PQC-ONLY`) reporting hybrid key exchange and per-client chain selection.
  - [`pqc-ca`](pqc-wallfacer/web-ingress/bin/pqc-ca) — Offline private ML-DSA web PKI (ML-DSA-87 root, name-constrained intermediate, ML-DSA-65 leaf signing from CSRs, CRL, trust bundle + SHA3-256 fingerprints compatible with `wf-keyroll`).
  - [`pqc-webconf`](pqc-wallfacer/web-ingress/bin/pqc-webconf) — In-place nginx and Apache config inventory, CSR emission, dry-run diff, atomic migration across three profiles (`compat`, `pqc-first`, `pqc-only`), automatic restore on config-test failure, removal, and byte-exact rollback.
  - [`pqc-k8s`](pqc-wallfacer/web-ingress/bin/pqc-k8s) & [`k8s/`](pqc-wallfacer/web-ingress/k8s/base/kustomization.yaml) — Kubernetes Ingress inventory, site planning, Secret generation, and Kustomize manifests (dual-stack `LoadBalancer`, PDB, NetworkPolicy) for placing a PQC edge in front of any ingress controller or Gateway.
- **Edge & toolbox images**: `pqc-web/edge-nginx`, `pqc-web/edge-apache` (read-only rootfs, uid 33, zero capabilities, live certificate reload without restart), and `pqc-web/tools` (OpenSSL 3.5 toolbox for hosts on older OpenSSL).
- **Client & browser validation**: Includes strict OpenSSL 3.5 client profile ([`client-pqc-strict.cnf`](pqc-wallfacer/web-ingress/profiles/client-pqc-strict.cnf)) and end-to-end **Chromium 156** compatibility testing via the `CACertificates` enterprise policy (see [`docs/CLIENTS.md`](pqc-wallfacer/web-ingress/docs/CLIENTS.md) and [`docs/MIGRATION.md`](pqc-wallfacer/web-ingress/docs/MIGRATION.md)).

---

## Legacy Containerized Apps (`pqc-legacy-apps/`)

Earlier experimental PQC and cryptanalysis containers previously located at the repository root:

- **`dockerfiles/`**: Dockerfiles for a CUDA desktop base (`Dockerfile`), `FindAFactor` prime factorization (`Dockerfile-findafactor`), Open Quantum Safe (OQS) Nginx (`Dockerfile-nginx`), and OQS OpenSSH (`Dockerfile-ssh`).
- **`miscfiles/`**: Legacy Nginx/OpenSSL configuration files (`nginx.conf`, `pqcnginx.conf`, `pqcssl.conf`) and `curveinfo.php`.
- **`runfiles/`**: Entrypoint scripts (`run`, `run-findafactor.sh`, `run-pqc`).

---

## Verification & Test Suites

| Component | Test Command / Suite | Coverage |
| --- | --- | --- |
| Gatekeeper & LLM Firewall | `python3 -m unittest test_gatekeeper` (in `pqc-wallfacer/infrastructure/gatekeeper/`) | 29 unit tests (allow-list, syntax/entropy firewall, gatekeeper decisions) |
| Paper QR Key-Roll | `python3 -m unittest test_paper_keyroll.py` (in `pqc-wallfacer/`) | 15 unit & E2E tests (PDF/QR round-trip, `--allow-secret --seal`, `wf-ca fingerprint`, gateway `verify_pqsk`) |
| PQC Web Ingress | `./tests/run-tests.sh` (in `pqc-wallfacer/web-ingress/`) | 54 host (`webconf-e2e.sh`) + 33 edge (`edge-e2e.sh`) + 18 Chromium 156 (`chromium-e2e.sh`) + 33 Kubernetes (`k8s-offline.sh` + `validate_k8s.py`) checks |

## License

Licensed under the [GNU General Public License v3.0](LICENSE).


<img width="2560" height="8800" alt="The Wallfacer Manifesto" src="https://github.com/user-attachments/assets/20619ee7-f895-4f00-a567-0e1a4c4ddfec" />
