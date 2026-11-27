# Kubernetes: PQC edge in front of ingress

The edge Deployment terminates TLS with both chains and forwards to the existing ingress controller (or Gateway). Routing, rewrites and annotations stay in the controller. Nothing inside the controller has to support ML-DSA.

```
client ──TLS 1.3: hybrid KEX, ML-DSA or classical chain──▶ Service pqc-edge (LoadBalancer, IPv4 + IPv6)
                                                              │
                                                       pqc-edge pods (nginx or Apache, OpenSSL 3.5)
                                                              │  re-encrypt (default) or HTTP
                                                              ▼
                                         ingress controller Service ──▶ Ingress / HTTPRoute ──▶ workloads
```

## Why an edge and not the controller

| Controller | Hybrid key exchange | ML-DSA server certificate | Note |
| --- | --- | --- | --- |
| ingress-nginx | when built on OpenSSL 3.5 | not configurable per Ingress | Retired upstream, no fixes since March 2026 |
| Go-based (Traefik and others) | yes since Go 1.24 | needs Go 1.27+ and controller support | Check the controller's release notes |
| Envoy-based (Gateway API implementations) | depends on the TLS library build | depends | Verify with `pqc-eval` |
| `pqc-web/edge-*` | yes | yes, dual chain | This kit |

The edge works with all of them and can stay while the controller is replaced.

## Upstream modes

| `PQC_UPSTREAM` | Controller sees | Controller changes | Use when |
| --- | --- | --- | --- |
| `https://<controller-svc>:443` (default) | TLS with SNI = original host, classical chain | none | Default; keeps controller-side `ssl-redirect`, HSTS and TLS-based routing working |
| `http://<controller-svc>:80` | plain HTTP with `X-Forwarded-Proto: https` | trust forwarded headers from the edge pod range (ingress-nginx: `use-forwarded-headers: "true"`, `proxy-real-ip-cidr`) | Lower CPU; otherwise `ssl-redirect` loops |

Re-encrypt verification: by default the edge does not verify the controller's certificate (the hop is in-cluster and the classical chain is presumed forgeable anyway). Set `PQC_UPSTREAM_CA` to a CA file to verify. The edge offers hybrid groups on that hop too (nginx `proxy_ssl_conf_command Groups`); the controller uses them when its OpenSSL supports them.

## Steps

| # | Step | Command |
| --- | --- | --- |
| 1 | Inventory | `pqc-k8s inventory` |
| 2 | Plan | `pqc-k8s plan -o plan.tsv`, then edit (one line per site: `<site> <ns>/<secret> <hosts...>`) |
| 3 | Keys + CSRs | `pqc-k8s csr plan.tsv ./pqc-certs \| sh` on the provisioning host |
| 4 | Sign | `pqc-ca sign ./pqc-certs/<site>/csr.pem ./pqc-certs/<site>` on the CA host, for each site |
| 5 | Secrets | `pqc-k8s secrets plan.tsv ./pqc-certs > k8s/overlays/<cluster>/secrets.yaml` |
| 6 | Volume patch | `pqc-k8s sites-patch plan.tsv > k8s/overlays/<cluster>/sites-patch.yaml` |
| 7 | Images | Build, push to the internal registry, set `images:` in the overlay (pin by digest) |
| 8 | Apply | `kubectl apply -k k8s/overlays/<cluster>` |
| 9 | Verify before cutover | `pqc-eval --ca pqc-web-root.pem --sni www.example.org <edge-LB-address>` for every site |
| 10 | Cutover | Point DNS (A + AAAA) to the edge LB, or move the LB address from the controller Service to the edge Service |
| 11 | Verify after cutover | `pqc-eval --ca pqc-web-root.pem -f targets.txt --require L2` |

`secrets.yaml` contains private keys. Generate it on the provisioning host, apply it, and do not commit it; for GitOps, use the cluster's secret management (sealed or external secrets) with the same names and keys.

## Objects

| Object | Name | Notes |
| --- | --- | --- |
| Namespace | `pqc-edge` | Pod Security `restricted` |
| ConfigMap | `pqc-edge` | Edge environment; `kubectl rollout restart deploy/pqc-edge -n pqc-edge` after a change |
| Deployment | `pqc-edge` | 2 replicas, uid 33, read-only rootfs, no capabilities, `RuntimeDefault` seccomp, `/tmp` in memory |
| Service | `pqc-edge` | `LoadBalancer`, `PreferDualStack` IPv4 + IPv6, `externalTrafficPolicy: Local`, 443 to 8443, 80 to 8080 |
| PodDisruptionBudget | `pqc-edge` | `minAvailable: 1` |
| NetworkPolicy | `pqc-edge` | In: 8443/8080. Out: DNS and namespace `ingress-nginx` (edit the label for other controllers) |
| Secret | `<site>-pqc` | `Opaque`, keys `tls.crt` (leaf + intermediate) and `tls.key` |
| Secret | `<site>-classic` | `kubernetes.io/tls`, copy of the Ingress secret; optional in the volume |

Projected volume layout inside the pod: `/etc/pqc/sites/<site>/{pqc,classic}/tls.{crt,key}`, mode 0440, group 33.

## Classical half from cert-manager

`pqc-k8s secrets` copies the Ingress secret once; a renewal by cert-manager does not reach the copy. For a lasting setup, create a `Certificate` in `pqc-edge` with `secretName: <site>-classic` for the same hosts. cert-manager renews it in place and the edge reloads it.

## Rotation

Kubernetes updates projected secret files in place (symlink swap). The edge checksums the sites directory every `PQC_RELOAD_INTERVAL` seconds (30 in the ConfigMap), re-renders, tests and reloads. Re-apply `<site>-pqc` with the new certificate before the old one expires; `pqc-eval` shows remaining days in `pqc_leaf_days`.

## Dual-stack networking

| Cluster | Result |
| --- | --- |
| IPv4 + IPv6 dual-stack | Service gets both families; the edge listens on `[::]` when the pod has IPv6 (`PQC_IPV6=auto`) |
| IPv4 only | `PreferDualStack` falls back to IPv4; no change needed |
| Cloud LB with PROXY protocol | Set `PQC_PROXY_PROTOCOL=yes` and the provider's LB annotation, so client addresses survive |

## Rollback

| Situation | Action |
| --- | --- |
| Before cutover | `kubectl delete -k k8s/overlays/<cluster>` |
| After cutover | Point DNS / LB back to the controller Service; the controller was never changed |
