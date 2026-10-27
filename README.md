<img width="1016" height="443" alt="Screenshot from 2026-01-01 15-36-30" src="https://github.com/user-attachments/assets/b5c8d613-5dac-484a-baef-0032dfd8e484" />

# ThereminQ-PQC

This repository provides a collection of containerized applications for Post-Quantum Cryptography (PQC), along with tools for quantum-inspired cryptanalysis. The project aims to centralize PQC implementations and provide a testbed for evaluating their security.

## Repository Structure

The repository is organized into the following primary directories:

- **`pqc-wallfacer/`**: Contains the documentation and architectural blueprints for the Wallfacer enclave, a highly secure, post-quantum cryptographic execution environment designed to safeguard critical application execution, specifically focusing on Large Language Model (LLM) orchestration and autonomous agent workspaces. It enforces strict provenance, authentication, and execution policies using modern post-quantum cryptography standards.
- **`pqc-legacy-apps/`**: Contains legacy containerized applications and scripts, previously located at the root of the repository. This includes:
  - **`dockerfiles/`**: Dockerfiles for building legacy PQC and cryptanalysis environments (CUDA base, Nginx with PQC, SSH with PQC, and a FindAFactor tool).
  - **`miscfiles/`**: Configuration files and scripts used by the legacy Docker containers.
  - **`runfiles/`**: Entrypoint scripts for the legacy Docker containers.


<img width="2560" height="8800" alt="The Wallfacer Manifesto" src="https://github.com/user-attachments/assets/20619ee7-f895-4f00-a567-0e1a4c4ddfec" />
