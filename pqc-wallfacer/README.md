<img width="2752" height="1536" alt="11053" src="https://github.com/user-attachments/assets/85977c28-6ea9-41fe-b1e5-32d532f18a8f" />

# Wallfacer PQC Enclave (`pqc-wallfacer`)

Zero-trust, post-quantum cryptographic enclave for safeguarded LLM inference and autonomous agent workspaces.

## Components

- **[`documentation/`](documentation/README.md)** — Architectural doctrine, blueprints, and the four-layer security model (Dark Perimeter, Private PQC PKI, Artifact Provenance Guard, Semantic API Gatekeeper).
- **[`infrastructure/`](infrastructure/README.md)** — Hardened Docker images (`base`, `pki`, `keyroll`, `gateway`, `gatekeeper`, `inference`, `ui`, `ui-door`), `compose.yaml`, and build scripts.
- **[`wallfacer_paper_keyroll.py`](wallfacer_paper_keyroll.py)** ([guide](README-paper-keyroll.md)) — Out-of-band A4 paper QR code key-roll (`wf-keyroll`), providing an air-gapped physical alternative to the LoRa / Reticulum radio network for relaying PQC private keys (`--allow-secret --seal`), Rosenpass static keys, and PSKs into the Wallfacer workflow (`WF_KEY_RELAY=paper-qr`).

