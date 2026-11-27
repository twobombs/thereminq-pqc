# Reference

## Edge images

`pqc-web/edge-nginx` (nginx 1.26) and `pqc-web/edge-apache` (Apache 2.4.71), both on Debian 13 with OpenSSL 3.5. They run as uid 33 (`www-data`), listen on unprivileged ports, and write only to `/tmp` (`--read-only --tmpfs /tmp:uid=33,gid=33` or an `emptyDir`).

| Variable | Default | Effect |
| --- | --- | --- |
| `PQC_PROFILE` | `compat` | `compat`, `pqc-first`, `pqc-only` |
| `PQC_UPSTREAM` | none (required) | `http://` or `https://` URL for every site; `<site>/upstream` file overrides per site |
| `PQC_UPSTREAM_CA` | empty | CA file to verify an `https://` upstream; empty disables verification |
| `PQC_SITES_DIR` | `/etc/pqc/sites` | `<site>/pqc/tls.{crt,key}` required, `<site>/classic/tls.{crt,key}` optional |
| `PQC_LISTEN_TLS` | `8443` | TLS port |
| `PQC_LISTEN_HTTP` | `8080` | HTTP port: `/healthz` and redirect |
| `PQC_FORWARDED_PORT` | `443` | Public TLS port, sent upstream as `X-Forwarded-Port` |
| `PQC_HTTP_REDIRECT` | `yes` | `no` proxies plain HTTP to the upstream instead of redirecting |
| `PQC_PROXY_PROTOCOL` | `no` | `yes` expects PROXY protocol on the TLS port |
| `PQC_IPV6` | `auto` | `auto` listens on `[::]` too when the container has IPv6 |
| `PQC_HSTS` | empty | Value for `Strict-Transport-Security`, e.g. `max-age=31536000` |
| `PQC_RELOAD_INTERVAL` | `60` | Seconds between checks of the sites directory; `0` disables reload |
| `PQC_CLIENT_MAX_BODY` | `0` (nginx) | `client_max_body_size`; `0` leaves limits to the upstream |
| `PQC_PROXY_TIMEOUT` | `300s` / `300` | Upstream read and send timeout |

| Behaviour | Detail |
| --- | --- |
| Server names | Union of the DNS SANs of both certificates of a site |
| Default TLS server | Uses the first site's certificates, answers 421; decides groups and protocol floor for the address |
| Site validation | ML-DSA key type, key/certificate match, expiry warning under 7 days; invalid sites are skipped and logged |
| Headers to upstream | `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-PQC-TLS-Protocol`; nginx also `X-PQC-TLS-Group` |
| Subcommands | `run` (default), `render` (print the generated config), anything else is executed |

## `pqc-webconf`

| Command | Options |
| --- | --- |
| `inventory` | `--server nginx\|apache`, `--conf FILE`, `--format table\|json`, `--emit-csr DIR` |
| `migrate` | `--server`, `--profile`, `--cert-root DIR` (`/etc/pqc/certs`), `--site-map FILE`, `--only a,b`, `--exclude a,b`, `--allow-missing-certs`, `--apply`, `--reload`, `--test-cmd`, `--reload-cmd`, `--backup-root DIR` (`/var/backups/pqc-webconf`) |
| `remove` | `--server`, `--conf`, `--apply`, `--reload`, `--test-cmd`, `--reload-cmd`, `--backup-root` |
| `rollback` | `<backup-dir>`, `--force`, `--test-cmd`, `--reload`, `--reload-cmd` |

| Marker | Meaning |
| --- | --- |
| `# >>> pqc-webconf profile=<p> site=<s> >>>` ... `# <<< pqc-webconf <<<` | Managed block, replaced on every run |
| `#pqc-webconf# <directive>` | Directive disabled by `pqc-only`, re-enabled by `remove` or another profile |

Environment: `PQC_CERT_ROOT`, `PQC_BACKUP_ROOT`, `PQC_PROFILES_FILE`.

## `pqc-eval`

| Option | Default | Effect |
| --- | --- | --- |
| `--ca FILE` | none | PQC root for verifying the ML-DSA chain |
| `--classic-ca FILE` | system store | CA bundle for the classical chain |
| `--sni NAME` | target host | SNI and hostname check |
| `--format` | `table` | `table`, `tsv`, `json` |
| `--timeout S` | `8` | Per handshake |
| `--require L0..L3` | none | Exit 1 when any target is below the level |
| `-f FILE` | none | Targets, one `host[:port]` or `[v6]:port` per line |

| Field | Meaning |
| --- | --- |
| `level` | `L0 NO-PQC`, `L1 PQC-KEX`, `L2 DUAL`, `L3 PQC-ONLY`, `ERR unreachable` |
| `profile` | Inferred: `compat`, `pqc-first`, `pqc-only` |
| `hybrid_groups` | Hybrid groups the server accepted, each tested alone |
| `classical_kex_accepted` | TLS 1.3 with classical groups only succeeded |
| `tls12_accepted` | TLS 1.2 succeeded |
| `legacy_auth`, `legacy_verify` | Chain served to a classical-only client, verification result |
| `pqc_auth`, `pqc_verify` | Chain served to an ML-DSA-only client, verification against `--ca` |
| `default_client_gets` | Chain an OpenSSL 3.5 client with default settings receives |
| `pqc_handshake_bytes` | Bytes read by the client in the ML-DSA handshake |
| `pqc_leaf_days`, `legacy_leaf_days` | Remaining validity |

## `pqc-ca`

| Variable | Default |
| --- | --- |
| `PQC_CA_DIR` | `./pqc-ca` |
| `PQC_CA_ALG` | `ML-DSA-87` (root and intermediate) |
| `PQC_LEAF_ALG` | `ML-DSA-65` |
| `PQC_LEAF_DAYS` / `PQC_LEAF_MAX_DAYS` | `30` / `90` |
| `PQC_ROOT_DAYS` / `PQC_INT_DAYS` | `3650` / `730` |

## `pqc-k8s`

| Command | Output |
| --- | --- |
| `inventory` | Controllers (flags retired ingress-nginx), Ingress TLS secrets with algorithm and days, Gateways |
| `plan [-o FILE]` | `<site> <ns>/<secret> <hosts...>` per Ingress TLS block |
| `csr <plan> <dir>` | `pqc-ca key-csr` commands |
| `secrets <plan> <pqc-dir>` | `<site>-pqc` (Opaque) and `<site>-classic` Secret YAML |
| `sites-patch <plan>` | Deployment patch with the projected `sites` volume |

Options: `-n NAMESPACE` (`pqc-edge`), `--deployment NAME` (`pqc-edge`).

## Profiles

| Profile | MinProtocol | Groups | SignatureAlgorithms order |
| --- | --- | --- | --- |
| `compat` | TLSv1.2 | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, P-384 | ECDSA, Ed25519, RSA-PSS, RSA-PKCS1, then ML-DSA-65/87/44 |
| `pqc-first` | TLSv1.2 | as `compat` | ML-DSA-65/87/44, then classical |
| `pqc-only` | TLSv1.3 | hybrid only | ML-DSA-65/87/44 only |

ML-DSA signatures exist in TLS 1.3 only, so TLS 1.2 clients always receive the classical chain.

## Handshake size

Authentication bytes the server sends: leaf DER + intermediate DER + CertificateVerify signature. The root is never sent.

| Root + intermediate | Leaf | Leaf DER | Intermediate DER | Signature | Total |
| --- | --- | --- | --- | --- | --- |
| ML-DSA-87 | ML-DSA-65 (default) | 6,869 | 7,488 | 3,309 | 17,666 |
| ML-DSA-87 | ML-DSA-87 | 7,509 | 7,489 | 4,627 | 19,625 |
| ML-DSA-65 | ML-DSA-65 | 5,551 | 5,531 | 3,309 | 14,391 |
| ML-DSA-65 | ML-DSA-44 | 4,910 | 5,531 | 2,420 | 12,861 |
| ML-DSA-44 | ML-DSA-44 | 4,022 | 4,002 | 2,420 | 10,444 |

Measured on the default chain through nginx: 19,114 bytes read by the client for the whole server flight (adds the ML-KEM key share and handshake framing). A typical ECDSA P-256 chain is around 2 KB.

## Group codepoints

nginx `$ssl_curve` prints hybrid groups as hex codepoints.

| Codepoint | Group |
| --- | --- |
| `0x11eb` | SecP256r1MLKEM768 |
| `0x11ec` | X25519MLKEM768 |
| `0x11ed` | SecP384r1MLKEM1024 |
| `X25519`, `prime256v1`, `secp384r1` | classical |

## Tested versions

| Component | Version |
| --- | --- |
| Base image | `debian:trixie-slim` |
| OpenSSL | 3.5.9 |
| nginx | 1.26.3 |
| Apache httpd | 2.4.71 |
| curl | 8.14.1 |
| Python | 3.13 |
