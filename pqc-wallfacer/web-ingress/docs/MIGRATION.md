# Migration runbook

Order of work for moving existing websites to a dual certificate stack within one week. Each phase has an exit gate; do not start a phase before the previous gate holds for every site in scope.

## Phases

| # | Phase | Output | Exit gate |
| --- | --- | --- | --- |
| 1 | Inventory | Site list, server versions, linked OpenSSL, current readiness | Every public name has a `pqc-eval` row and an owner |
| 2 | PKI | Offline root, issuing intermediate, published fingerprints | Root fingerprint confirmed out of band by a second person |
| 3 | Root distribution starts | Root in managed client trust stores | Root present on the pilot client group |
| 4 | Certificates | ML-DSA key + certificate per site | `pqc-ca show` lists every SAN of the site |
| 5 | Deploy `compat` | Dual chain live | `pqc-eval` reports `L2 DUAL`, `profile=compat` for every site |
| 6 | Tighten | `pqc-first` or `pqc-only` where clients allow | `pqc-eval --require L2` (or `L3`) in monitoring |
| 7 | Drills | Rotation, rollback and revocation exercised once | Rotation picked up without restart; rollback restores byte-exact |

`compat` changes nothing for existing clients, so phase 5 can run as soon as certificates exist. Phases 3 and 6 move at the pace of the client fleet.

## 1. Inventory

```sh
# live endpoints (runs anywhere with Docker)
docker run --rm -v "$PWD:/w" pqc-web/tools pqc-eval -f /w/targets.txt --format tsv > before.tsv

# each web host
pqc-webconf inventory --server nginx     # or --server apache
pqc-webconf inventory --server nginx --format json > inventory-$(hostname).json

# each cluster
pqc-k8s inventory
```

| Inventory finding | Consequence |
| --- | --- |
| Linked OpenSSL < 3.5 | Path B (edge container) or an OS upgrade; in-place migration is refused |
| `groups pinned without hybrid ML-KEM` | Site is L0 today; migration fixes it through `ssl_conf_command Groups` |
| `certificate/key count mismatch` | Key embedded in the certificate file; split it before migrating |
| `certificates inherited from the enclosing level` | Handled: pqc-webconf copies the inherited pair into the server |
| `QUIC/HTTP3 listener` | Not covered; keep HTTP/3 on the classical stack or disable it until verified |
| ingress-nginx controller | Retired upstream since March 2026; put the edge in front now, replace the controller separately |

## 2. PKI

Run on an offline host (the `pqc-web/tools` image with `--network none` is enough).

```sh
export PQC_CA_DIR=/secure/pqc-ca
pqc-ca init-root "Example PQC Web Root 2026"
pqc-ca init-int  "Example PQC Web Issuing 2026" --permit-dns example.org,example.net
pqc-ca trust            # writes trust/pqc-web-root.pem and trust/FINGERPRINTS
# move root/root.key to cold storage now
```

| Setting | Default | Note |
| --- | --- | --- |
| Root algorithm | ML-DSA-87, 3650 days | `PQC_CA_ALG`, `PQC_ROOT_DAYS` |
| Intermediate | ML-DSA-87, 730 days, `pathlen:0`, `EKU serverAuth` | `PQC_INT_DAYS`; `PQC_CA_ALG=ML-DSA-65` saves 3.3 KB per handshake |
| Name constraints | none unless `--permit-dns` | Strongly recommended: limits what a stolen intermediate key can sign, which makes a private root acceptable to install broadly |
| Leaf | ML-DSA-65, 30 days, max 90 | `PQC_LEAF_ALG`, `PQC_LEAF_DAYS`, `PQC_LEAF_MAX_DAYS` |
| Classical CSRs | refused | Only ML-DSA keys are signed |
| SANs | copied from the CSR after validation | Not covered by the name constraints: refused |

Fingerprint transport: print `FINGERPRINTS` and carry the SHA3-256 line out of band, or encode `pqc-web-root.pem` with `wf-keyroll encode` (public material: no `--allow-secret`, no `--seal`) and decode with `--expect <SHA3-256>`. The SHA3-256 line is taken over the PEM file, the same value `wf-ca fingerprint` and `wf-keyroll` print.

## 3. Root distribution

See [CLIENTS.md](CLIENTS.md). Start with the clients that will move to `pqc-first` / `pqc-only` first: internal tooling, service accounts, partner integrations.

## 4. Certificates

Keys are generated where they are used; only CSRs travel.

```sh
# on the web host (pqc-webconf prints these lines with --emit-csr)
pqc-ca key-csr www.example.org www.example.org example.org --out /etc/pqc/certs

# on the CA host
pqc-ca sign www.example.org.csr.pem ./out/www.example.org --days 30

# back on the web host: cert.pem chain.pem fullchain.pem next to privkey.pem
install -m 0644 out/www.example.org/fullchain.pem /etc/pqc/certs/www.example.org/
```

| File | Content | Used by |
| --- | --- | --- |
| `privkey.pem` | ML-DSA private key, mode 0600 | server |
| `fullchain.pem` | leaf + intermediate (root never sent) | server |
| `cert.pem`, `chain.pem` | leaf, intermediate | inspection, other servers |

`pqc-webconf migrate` expects `<cert-root>/<site>/fullchain.pem` and `privkey.pem`, where `<site>` is the first non-wildcard `server_name` / `ServerName`. Override per site with `--site-map` (`<site> <dir>` lines).

## 5. Deploy

### Path A: in place on the host

Requires nginx or mod_ssl linked against OpenSSL >= 3.5 (`pqc-webconf inventory` shows it).

```sh
pqc-webconf migrate --server nginx --profile compat                       # dry run: plan table + diff
pqc-webconf migrate --server nginx --profile compat --apply               # write, nginx -t, keep backup
pqc-webconf migrate --server nginx --profile compat --apply --reload      # same, then reload
pqc-eval --ca pqc-web-root.pem www.example.org example.org
```

What `migrate` writes per TLS server / VirtualHost, inside a marked block before the closing brace or `</VirtualHost>`:

| nginx | Apache | Purpose |
| --- | --- | --- |
| `ssl_certificate` + `ssl_certificate_key` | `SSLCertificateFile` + `SSLCertificateKeyFile` | ML-DSA pair next to the existing pair |
| `ssl_conf_command MinProtocol` | `SSLOpenSSLConfCmd MinProtocol` | protocol floor of the profile |
| `ssl_conf_command Options ServerPreference` | `SSLOpenSSLConfCmd Options ServerPreference` | server order decides the chain |
| `ssl_conf_command Groups` | `SSLOpenSSLConfCmd Groups` | hybrid groups first |
| `ssl_conf_command SignatureAlgorithms` | `SSLOpenSSLConfCmd SignatureAlgorithms` | chain preference of the profile |

Both servers apply these commands after their own TLS directives, so `ssl_protocols`, `ssl_ecdh_curve`, `SSLProtocol` and `SSLHonorCipherOrder` in shared snippets (certbot `options-ssl-*.conf`) are overridden without editing the snippet and without duplicate-directive errors.

| Case | Behaviour |
| --- | --- |
| Certificates inherited from `http{}` / main server | Copied into the block, because a server-level certificate list replaces the inherited one |
| `ssl_conf_command` inherited from `http{}` | Non-conflicting lines (e.g. `Options PrioritizeChaCha`) copied for the same reason |
| `pqc-only` | Classical certificate directives in the server are disabled (`#pqc-webconf# ` prefix), not deleted |
| Classical certificate comes from an included file (`pqc-only`) | Site skipped; the shared file is never edited |
| Certificate and key directive counts differ | Site skipped |
| Site already has an ML-DSA certificate outside pqc-webconf | Site skipped |
| ML-DSA files missing, expired, wrong key, SAN gap | Site skipped with the reason (`--allow-missing-certs` plans anyway) |
| Re-run, other profile | Old block stripped first; result is the same as a single run |

Apply sequence: atomic write of every changed file, backup with SHA-256 manifest under `/var/backups/pqc-webconf/<server>-<UTC>/`, config test (`nginx -t` / `apache2ctl -t`), automatic restore when the test fails, optional reload.

### Path B: edge container in front

For hosts whose server cannot be upgraded this week. The edge terminates both chains and proxies to the existing server, which keeps its config.

| Step | Command |
| --- | --- |
| Move the old listener | Old server to HTTP on port 8081, bound to the Docker bridge address (`172.17.0.1:8081`) or to all addresses with a firewall rule |
| Lay out sites | `/etc/pqc/sites/<site>/pqc/tls.{crt,key}` from pqc-ca, `/etc/pqc/sites/<site>/classic/tls.{crt,key}` from the existing chain, readable by uid 33 |
| Run | see below |
| Verify | `pqc-eval --ca pqc-web-root.pem www.example.org` |

```sh
docker run -d --name pqc-edge --restart unless-stopped \
  -p 443:8443 -p 80:8080 --add-host host.docker.internal:host-gateway \
  --read-only --tmpfs /tmp:uid=33,gid=33,mode=0750 --cap-drop ALL --security-opt no-new-privileges \
  -e PQC_PROFILE=compat -e PQC_UPSTREAM=http://host.docker.internal:8081 \
  -v /etc/pqc/sites:/etc/pqc/sites:ro pqc-web/edge-nginx
```

Publish ports instead of using host networking: the edge runs as uid 33 without capabilities, so it cannot bind 443 itself.

The edge reads server names from the certificates, re-renders and reloads when files under the sites directory change (`PQC_RELOAD_INTERVAL`, default 60 s), and rejects a new configuration that fails `nginx -t` / `apache2 -t` while keeping the running one. Variables: [REFERENCE.md](REFERENCE.md#edge-images).

### Path C: Kubernetes

[KUBERNETES.md](KUBERNETES.md).

## 6. Tighten

| Move | Precondition | Check |
| --- | --- | --- |
| `compat` to `pqc-first` | Every client that offers ML-DSA has the root (OpenSSL 3.5 tooling, Go 1.27+, browsers with ML-DSA support) | `pqc-eval` `default_client_gets=ML-DSA-*`; client error rates flat |
| to `pqc-only` | Every client is PQC-capable and has the root | `pqc-eval` `L3 PQC-ONLY`, `classical_kex_accepted=no` |
| Monitoring | Any | `pqc-eval --require L2 -f targets.txt` in a cron or CI job; log `$ssl_curve` (nginx) to measure hybrid share |

## 7. Drills

| Drill | How | Expected |
| --- | --- | --- |
| Rotation (edge) | Replace `pqc/tls.crt` + `tls.key` | New serial served within `PQC_RELOAD_INTERVAL`, no restart |
| Rotation (host) | Overwrite `fullchain.pem` + `privkey.pem`, reload | New serial served |
| Revocation | `pqc-ca revoke <cert>`; publish `int/crl.pem` | CRL-checking clients refuse the old leaf |
| Rollback (host) | `pqc-webconf rollback <backup-dir>` (newest first for a chain) | Files byte-exact to before; config test passes |
| Rollback (edge) | Point DNS / LB back to the old listener | Classical-only service as before |

## Rollback reference

| Situation | Command |
| --- | --- |
| Undo the last apply | `pqc-webconf rollback /var/backups/pqc-webconf/<server>-<UTC> --reload` |
| Undo several applies | Roll back each backup, newest first (`--force` when later applies touched the same file) |
| Strip every managed block, keep everything else | `pqc-webconf remove --server nginx --apply --reload` (semantic: whitespace around disabled lines may differ) |
| Edge | Remove the container / scale the Deployment to 0 and restore DNS or the LB target |
