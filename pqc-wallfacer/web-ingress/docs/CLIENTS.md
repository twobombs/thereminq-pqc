# Clients

The ML-DSA chain only protects clients that verify it. This page covers root distribution, which clients can use the chain, and the downgrade exposure that remains while classical roots are trusted.

## Which chain a client gets

| Client offers | `compat` | `pqc-first` | `pqc-only` |
| --- | --- | --- | --- |
| Classical signature algorithms only (most browsers, OpenSSL < 3.5, older Go, Java) | classical | classical | handshake fails |
| Classical + ML-DSA (OpenSSL 3.5 defaults: curl, Python, wget, git on Debian 13) | classical | ML-DSA | ML-DSA |
| ML-DSA only (`client-pqc-strict.cnf`, `curl --sigalgs mldsa65:mldsa87:mldsa44`) | ML-DSA | ML-DSA | ML-DSA |

A client that receives the ML-DSA chain without having the root fails verification. In `pqc-first` this hits every OpenSSL 3.5 client that lacks the root, which is why `pqc-first` waits for distribution.

## Client support

| Client | Hybrid key exchange | ML-DSA chain verification | Notes |
| --- | --- | --- | --- |
| OpenSSL 3.5+ (curl, Python, wget, git, PHP, Ruby linked to it) | default | yes | Debian 13: OpenSSL 3.5. Ubuntu 24.04: OpenSSL 3.0 (no ML-DSA) |
| Go 1.27+ | default since 1.24 | yes (`crypto/mldsa`, `crypto/tls`) | Earlier Go cannot parse ML-DSA certificates |
| Chrome / Chromium | default since 131 (desktop) | reported for user-added private roots from mid 2026 | No ML-DSA in the public root store; verify on your build |
| Firefox, Safari, Edge | hybrid key exchange shipped | verify per version | Test with the root installed before relying on it |
| Java | depends on version and provider | verify per version | |

Verify any client against a `pqc-only` endpoint: a successful handshake proves ML-DSA verification end to end.

## Installing the root

Get `pqc-web-root.pem` and its `FINGERPRINTS` from `pqc-ca trust`; compare the SHA3-256 line out of band before installing.

| Platform | Command |
| --- | --- |
| Debian / Ubuntu | `install -m 0644 pqc-web-root.pem /usr/local/share/ca-certificates/pqc-web-root.crt && update-ca-certificates` |
| RHEL / Fedora | `install -m 0644 pqc-web-root.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust` |
| Container images | Same as the base distribution, in the Dockerfile |
| Single program | `curl --cacert pqc-web-root.pem`, `SSL_CERT_FILE=...`, `REQUESTS_CA_BUNDLE=...` |
| Kubernetes workloads | ConfigMap with the root, mounted and pointed to by `SSL_CERT_FILE` |
| Managed browsers | Enterprise policy for user-added roots |

A system store that only OpenSSL < 3.5 reads gains nothing: those clients cannot verify ML-DSA and keep getting the classical chain.

## Downgrade exposure

With RSA/ECC presumed broken, an active attacker can forge a classical certificate for any name. A client that trusts both the public roots and the PQC root accepts the forged classical chain whenever the attacker offers it, whatever the server profile.

| Client setup | Passive recording (harvest now) | Active impersonation |
| --- | --- | --- |
| Classical-only client | protected if it negotiates a hybrid group, otherwise exposed | exposed |
| PQC root added, public roots kept, default sigalgs | protected (hybrid group) | exposed: attacker serves a forged classical chain |
| PQC root only, `client-pqc-strict.cnf` (ML-DSA only, hybrid only, TLS 1.3) | protected | protected |

Closing the gap needs both halves of the strict setup: offer only ML-DSA and trust only the PQC root for these names. For service-to-service traffic, that means `pqc-only` endpoints and strict clients.

```sh
# strict client, any OpenSSL 3.5 program
OPENSSL_CONF=/etc/pqc/client-pqc-strict.cnf curl --cacert /etc/pqc/pqc-web-root.pem https://api.example.org/

# curl only
curl --cacert pqc-web-root.pem --sigalgs mldsa65:mldsa87:mldsa44 --curves X25519MLKEM768 https://api.example.org/
```

Browsers have no per-site way to refuse classical roots; for browser users, `compat` protects recorded traffic (hybrid key exchange) but not against active impersonation, until browsers ship a post-quantum PKI.
