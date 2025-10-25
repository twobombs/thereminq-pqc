# ThereminQ-PQC

This repository provides a collection of containerized applications for Post-Quantum Cryptography (PQC), along with tools for quantum-inspired cryptanalysis. The project aims to centralize PQC implementations and provide a testbed for evaluating their security.

## Repository Structure

The repository is organized into the following directories:

- **`dockerfiles/`**: Contains Dockerfiles for building the various PQC and cryptanalysis environments.
- **`miscfiles/`**: Includes configuration files and scripts used by the Docker containers.
- **`runfiles/`**: Contains entrypoint scripts for the Docker containers.

---

## Dockerfiles

This directory contains the Dockerfiles for building the project's container images.

### `Dockerfile`
- **Purpose**: Sets up a base CUDA environment using the `twobombs/cudacluster:2204dev` image. This container is intended for GPU-accelerated workloads.
- **Usage**: This Dockerfile is likely used as a base for other images or for running CUDA-based applications.

### `Dockerfile-findafactor`
- **Purpose**: Creates an environment for the `FindAFactor` tool, a Python-based application for prime factorization. It installs Python, build tools, and the `FindAFactor` package from its GitHub repository.
- **Build Command**: `docker build -t thereminq-pqc:findafactor -f dockerfiles/Dockerfile-findafactor .`
- **Run Command**: `docker run --rm -it thereminq-pqc:findafactor`

### `Dockerfile-nginx`
- **Purpose**: Configures an Nginx web server with support for Post-Quantum Cryptography using the Open Quantum Safe (OQS) provider. It sets up TLS v1.3 with PQC key exchange algorithms.
- **Build Command**: `docker build -t thereminq-pqc:nginx -f dockerfiles/Dockerfile-nginx .`
- **Run Command**: `docker run --rm -it -p 443:443 thereminq-pqc:nginx`

### `Dockerfile-ssh`
- **Purpose**: Sets up an SSH server with PQC support, using a custom build of OpenSSH integrated with the OQS library.
- **Build Command**: `docker build -t thereminq-pqc:ssh -f dockerfiles/Dockerfile-ssh .`
- **Run Command**: `docker run --rm -it -p 2222:22 thereminq-pqc:ssh`

---

## Miscellaneous Files (`miscfiles/`)

This directory contains various configuration files used by the Docker images.

- **`curveinfo.php`**: A PHP script that checks the SSL curve used by the client's connection and indicates whether it is post-quantum secure.
- **`nginx.conf`**: A minimal Nginx configuration file.
- **`pqcnginx.conf`**: The Nginx server block configuration for the PQC-enabled web server, specifying the TLS protocols and PQC key exchange curves.
- **`pqcssl.conf`**: A minimal SSL configuration file.

---

## Run Files (`runfiles/`)

This directory contains the entrypoint scripts for the Docker containers.

- **`run`**: A simple script (`tail -f /dev/null`) used to keep a container running indefinitely. This is used in the Nginx and SSH containers.
- **`run-findafactor.sh`**: The entrypoint for the `findafactor` container. This script continuously generates large numbers by multiplying two large prime numbers and then attempts to factor them using the `FindAFactor` tool.
- **`run-pqc`**: The entrypoint for the base CUDA container. It sets up a virtual desktop environment (Xvfb, XFCE, VNC, and xRDP) and starts a terminal.
