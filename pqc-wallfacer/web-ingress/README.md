<img width="2752" height="1536" alt="12343" src="https://github.com/user-attachments/assets/24698239-8c62-40bc-9cb3-d254c5fd7048" />


# PQC web ingress migration (`pqc-wallfacer/web-ingress`)

Emergency migration kit for existing websites under the assumption that RSA and ECC certificate authorities are no longer trustworthy (CA keys forgeable). It adds a post-quantum certificate chain next to the existing classical one, on nginx and Apache httpd, on plain hosts, in containers and in front of Kubernetes ingress, and evaluates the result from the client side.

Companion to the [Wallfacer enclave](../infrastructure/README.md): same OpenSSL 3.5 baseline, same offline-root discipline, and root fingerprints can be carried out of band with [`wf-keyroll`](../README-paper-keyroll.md).

## Contents

| Path | Purpose |
| --- | --- |
| [`bin/pqc-eval`](bin/pqc-eval) | Probe live endpoints: hybrid key exchange, which chain which client gets, readiness level L0..L3 |
| [`bin/pqc-ca`](bin/pqc-ca) | Private ML-DSA PKI: offline root, name-constrained intermediate, CSR signing, CRL, trust bundle |
| [`bin/pqc-webconf`](bin/pqc-webconf) | nginx / Apache host configs: inventory, migrate (dry run, apply, auto-restore), remove, rollback |
| [`bin/pqc-k8s`](bin/pqc-k8s) | Kubernetes: controller and Ingress inventory, site plan, secrets, sites volume patch |
| [`docker/nginx`](docker/nginx/Dockerfile), [`docker/apache`](docker/apache/Dockerfile) | Dual-stack TLS edge images (`pqc-web/edge-nginx`, `pqc-web/edge-apache`) |
| [`docker/tools`](docker/tools/Dockerfile) | OpenSSL 3.5 toolbox (`pqc-web/tools`) for hosts whose OpenSSL is older |
| [`k8s/`](k8s/base/kustomization.yaml) | Kustomize base (edge Deployment, dual-stack LoadBalancer, PDB, NetworkPolicy) and overlays |
| [`profiles/profiles.env`](profiles/profiles.env) | The three server TLS profiles, shared by every tool and image |
| [`profiles/client-pqc-strict.cnf`](profiles/client-pqc-strict.cnf) | OpenSSL client profile that requires ML-DSA authentication |
| [`docs/MIGRATION.md`](docs/MIGRATION.md) | Runbook: order of work, gates, rollback |
| [`docs/KUBERNETES.md`](docs/KUBERNETES.md) | Edge in front of an ingress controller or Gateway |
| [`docs/CLIENTS.md`](docs/CLIENTS.md) | Root distribution, client support, downgrade exposure |
| [`docs/REFERENCE.md`](docs/REFERENCE.md) | Environment variables, CLI options, output fields, sizes, codepoints |
| [`tests/`](tests/run-tests.sh) | End-to-end tests (Docker) |

## Model

One TLS listener carries two certificate chains. OpenSSL picks the chain from the signature algorithms the client offers, after the server's preference order.

| Part | Classical half | Post-quantum half |
| --- | --- | --- |
| Key exchange | X25519, P-256, P-384 | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 (hybrid) |
| Server certificate | Existing RSA / ECDSA chain (ACME, cert-manager, commercial CA) | ML-DSA-65 leaf, ML-DSA-87 intermediate, from `pqc-ca` |
| Trust anchor | Public WebPKI roots (presumed forgeable) | Private ML-DSA-87 root, distributed to clients |
| Clients served | Browsers without the root, every client without ML-DSA support | OpenSSL 3.5+, Go 1.27+, Chromium 156 with the root via policy, other clients with ML-DSA and the root |

Hybrid key exchange alone protects recorded traffic against later decryption. Authentication is only post-quantum for clients that verify the ML-DSA chain and do not also accept classical roots for the same name (see [CLIENTS.md](docs/CLIENTS.md#downgrade-exposure)).

## Profiles

| Profile | TLS | Groups | Chain preference | Default OpenSSL 3.5 client gets | Browsers get | Use for |
| --- | --- | --- | --- | --- | --- | --- |
| `compat` | 1.2, 1.3 | hybrid, then classical | classical first | classical | classical (Chromium: X25519MLKEM768) | Public sites; week-one default |
| `pqc-first` | 1.2, 1.3 | hybrid, then classical | ML-DSA first | ML-DSA | Chromium: ML-DSA, so it fails without the root | Managed fleets with the root deployed everywhere |
| `pqc-only` | 1.3 | hybrid only | ML-DSA only | ML-DSA | Chromium with the root: works; others fail | APIs, service-to-service, managed browsers |

In `compat`, a client gets the ML-DSA chain only when it offers ML-DSA and nothing classical, as [`client-pqc-strict.cnf`](profiles/client-pqc-strict.cnf) does.

## Readiness levels (`pqc-eval`)

| Level | Meaning |
| --- | --- |
| `L0 NO-PQC` | No hybrid key exchange accepted |
| `L1 PQC-KEX` | Hybrid key exchange, no ML-DSA chain |
| `L2 DUAL` | Hybrid key exchange, ML-DSA chain for PQC clients, classical chain for the rest |
| `L3 PQC-ONLY` | ML-DSA chain only; classical authentication refused |

OpenSSL 3.5 puts X25519MLKEM768 in its default groups, so a server reaches L1 by running on OpenSSL 3.5 unless its config pins classical groups (`ssl_ecdh_curve X25519:prime256v1`, `SSLOpenSSLConfCmd Curves ...`). `pqc-webconf inventory` flags those pins.

## Paths

| Situation | Path | Doc |
| --- | --- | --- |
| nginx / Apache host, linked OpenSSL >= 3.5 (Debian 13 and newer) | `pqc-webconf migrate` in place | [MIGRATION.md](docs/MIGRATION.md#path-a-in-place-on-the-host) |
| nginx / Apache host, older OpenSSL (Ubuntu 24.04 ships 3.0) | Edge container on the same host or in front of it | [MIGRATION.md](docs/MIGRATION.md#path-b-edge-container-in-front) |
| Kubernetes, any ingress controller or Gateway | Edge Deployment in front of the controller, re-encrypting to it | [KUBERNETES.md](docs/KUBERNETES.md) |

## Quick start

```sh
# toolbox with OpenSSL 3.5 (any Docker host)
docker build -f docker/tools/Dockerfile -t pqc-web/tools .
docker run --rm pqc-web/tools pqc-eval www.example.org api.example.org:8443
```

```sh
# host path: inventory, CSRs, offline signing, dry run, apply
pqc-webconf inventory --server nginx --emit-csr /etc/pqc/certs
pqc-ca sign /etc/pqc/certs/www.example.org/csr.pem /etc/pqc/certs/www.example.org     # on the CA host
pqc-webconf migrate --server nginx --profile compat                                   # diff only
pqc-webconf migrate --server nginx --profile compat --apply --reload
pqc-eval --ca pqc-web-root.pem www.example.org
```

```sh
# edge path: sites/<site>/{pqc,classic}/tls.{crt,key}
docker run -d -p 443:8443 -p 80:8080 --read-only --tmpfs /tmp:uid=33,gid=33 --cap-drop ALL \
  -e PQC_PROFILE=compat -e PQC_UPSTREAM=http://10.0.0.5:80 -v /etc/pqc/sites:/etc/pqc/sites:ro pqc-web/edge-nginx
```

```sh
# Kubernetes path
pqc-k8s inventory
pqc-k8s plan -o plan.tsv
pqc-k8s secrets plan.tsv ./pqc-certs > k8s/overlays/example/secrets.yaml
pqc-k8s sites-patch plan.tsv > k8s/overlays/example/sites-patch.yaml
kubectl apply -k k8s/overlays/example
```

## Test status

`tests/run-tests.sh` builds the images on `debian:trixie-slim` (OpenSSL 3.5.9, nginx 1.26.3, Apache 2.4.71, curl 8.14.1) and runs every suite. Nothing is pushed.

| Suite | Checks | Covers | Result |
| --- | --- | --- | --- |
| `webconf-e2e.sh` (nginx + Apache host) | 54 | pqc-ca issuance, inventory, CSR emission, dry run, all 3 profiles on 4 nginx servers and 3 Apache vhosts verified by pqc-eval, certbot-style shared snippets, pinned classical groups, certificates inherited from `http{}` / main server, one-line and multi-line directives, continuation lines, skipped key-in-cert vhost, idempotent re-run, profile switch, remove, byte-exact rollback chain, auto-restore on failed config test | pass |
| `edge-e2e.sh` (both edge images) | 33 | all 3 profiles, 2 SNI sites, read-only rootfs, no capabilities, uid 33, Host / X-Forwarded-* / TLS headers to upstream, 421 for unknown SNI, 301 on HTTP, strict client profile, ML-DSA certificate rotation without restart | pass |
| `chromium-e2e.sh` (Chromium 156) | 18 | both edges x 3 profiles x root sets (classical, PQC, both) delivered by `CACertificates` policy; page load and negotiated group | pass |
| `k8s-offline.sh` + `validate_k8s.py` | 8 + 25 | pqc-k8s against a stub kubectl, secret round trip, manifest structure, restricted Pod Security, dual-stack Service, sites patch merge | pass |
| Live cluster | not run | kustomize build, LoadBalancer, NetworkPolicy, re-encrypt into a real controller | needs a cluster |
| IPv6 listeners | not run | the test kernel has no IPv6; `[::]` listeners are parsed but were dropped from the fixtures | needs an IPv6 host |
| Other browsers | not run | Firefox, Safari, Chrome on Windows / macOS / Android | manual |

## Limits

| Item | Detail |
| --- | --- |
| Public browser trust | No public root program accepts ML-DSA X.509 roots. Chrome's public path is Merkle Tree Certificates, bootstrapping from Q1 2027. Until then browsers authenticate with the classical chain unless the private root is installed by policy. |
| Chromium offers ML-DSA first | Chromium 156 lists mldsa44/65/87 ahead of ECDSA and RSA. Under `pqc-first` and `pqc-only` every Chromium without the PQC root fails; public sites stay on `compat`. |
| Root import on Linux | NSS `certutil` rejects ML-DSA roots (`SEC_ERROR_ADDING_CERT`). Use the Chrome `CACertificates` policy. |
| Key exchange groups per address | Groups and the protocol floor come from the default server of each IP:port, not from the SNI-selected one. Migrate the default server too; `pqc-webconf migrate` warns when a shared address is half migrated. |
| Handshake size | ML-DSA-87 intermediate + ML-DSA-65 leaf adds 17.7 KB of authentication data (measured server flight 19.1 KB), above a 10-segment initial congestion window. Use an ML-DSA-65 intermediate for 14.4 KB. See [REFERENCE.md](docs/REFERENCE.md#handshake-size). |
| HTTP/3 (QUIC) | Not migrated; `pqc-webconf inventory` marks QUIC listeners. |
| OCSP | `pqc-ca` publishes a CRL only. nginx `ssl_stapling` logs a warning for the ML-DSA certificate and continues. |
| cert-manager | Cannot issue ML-DSA (Go crypto before 1.27). Keep cert-manager for the classical half; issue the ML-DSA half with `pqc-ca`. |
| Composite / hybrid certificates | Not used. Two separate chains selected by signature algorithm are what nginx, Apache and OpenSSL 3.5 support today. |
