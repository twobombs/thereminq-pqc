# Wallfacer enclave containers — first slice

Container images for the first build phases of the Wallfacer requirements (roots of trust, dark perimeter, provenance guard, gatekeeper, local inference). Requirement IDs refer to *Wallfacer Architecture — Infrastructure Requirements*.

## Images

| Image | Role | Base | Network | Requirements |
| --- | --- | --- | --- | --- |
| `wallfacer/base` | OpenSSL 3.5 policy, `wf-verify`, uid 10001 `wf` | debian:trixie-slim | — | PKI-01, PKI-05, PRV-05 |
| `wallfacer/pki` | Offline CA (`wf-ca`) and artifact/bundle signer (`wf-sign`) | base | none | PKI-02..09, PRV-01..04, MSH-05 |
| `wallfacer/gateway` | WireGuard + Rosenpass, nftables default drop, PSK hold-down | base + Rosenpass built from tag | host | NET-01..09, MSH-01..06, MSH-12 |
| `wallfacer/gatekeeper` | Allow-list, LLM firewall, Merlin on CPU, chat proxy | base + Python 3.13 venv | `agent_net`, `model_net` | GATE-01..08, FW-01..04, FW-08 |
| `wallfacer/inference` | llama.cpp server on Vulkan, fail-closed GGUF loader | base + llama.cpp built from tag | `model_net` | CMP-01, CMP-02, CMP-09, PRV-05, WF-02 |
| `wallfacer/ui` | ThereminQ Jupyter desktop: noVNC, Jupyter, VS Code, PyQrack | `twobombs/thereminq-tensors:jupyter` by digest | `ui_int` | CMP-01, CMP-03, CMP-07 |
| `wallfacer/ui-door` | socat relay publishing UI ports on the WireGuard address only | base + socat | `ui_pub`, `ui_int` | NET-01, NET-02 |

## Build inputs (`.env`)

| Variable | Used by | Default | Note |
| --- | --- | --- | --- |
| `DEBIAN_IMAGE` | base, inference build | `debian:trixie-slim` | Pin by `@sha256:` digest |
| `RUST_IMAGE` | gateway build | `rust:slim-trixie` | |
| `ROSENPASS_VERSION` | gateway | `v0.2.2` | Git tag |
| `MERLIN_REF` | gatekeeper | none (required) | kontext-security/merlin commit |
| `LLAMA_CPP_REF` | inference | none (required) | llama.cpp release tag |
| `TORCH_VERSION` | gatekeeper | `2.9.0` | CPU wheel index only |
| `MERLIN_HF_REVISION` | gatekeeper | `21b6f2cc…eea5` | Build arg; checkpoint SHA-256 `075d68f8…4c86` checked at build and every start |
| `THEREMINQ_JUPYTER_IMAGE` | ui | none (required) | `twobombs/thereminq-tensors:jupyter@sha256:…`; `build.sh` refuses a tag without digest |

`./build.sh` builds in dependency order, pushes nothing, and prints the image IDs to sign.

## Runtime layout (`./runtime`)

| Path | Contents | Mounted into |
| --- | --- | --- |
| `pki/` | `root/`, `root-slh/`, `tls/`, `keys/` | pki (offline host only) |
| `trust/overlay.pub.pem` | ML-DSA-87 public key that signs peer bundles | gateway |
| `trust/artifact.pub.pem` | ML-DSA-87 public key that signs models | inference |
| `bundle/` | `SERIAL`, `peers.conf`, `peers/<name>/`, manifest + sig | gateway (ro) |
| `secret/rosenpass/` | This node's `rp genkey` output; never leaves the node | gateway (ro) |
| `models/current/` | One `.gguf`, `model.meta`, optional `chat_template.jinja`, manifest + sig | inference (ro) |
| `policy.json` | Gatekeeper allow-list (`gatekeeper/policy.example.json` as template) | gatekeeper (ro) |
| `secret/jupyter_token` | ≥ 32 characters, e.g. `openssl rand -hex 32` | ui (compose secret) |
| `secret/vnc_password` | ≥ 8 characters, not `00000000` | ui (compose secret) |
| `ui/work/` | Notebooks and results that survive restarts | ui at `/notebooks/work` |

`peers.conf` format, one peer per line: `<name> <endpoint|-> <allowed-ips>`; `-` means the peer dials in.

## First run

| Step | Where | Command |
| --- | --- | --- |
| 1 | Offline host | `docker compose --profile offline run --rm pki wf-ca init-root "Wallfacer Root"` |
| 2 | Offline host | `… pki wf-ca init-root-slh "Wallfacer SLH Root"` |
| 3 | Offline host | `… pki wf-ca init-tls "Wallfacer TLS 2026"`, then move `root/root.key` to cold storage |
| 4 | Offline host | `… pki wf-ca signing-key artifact` and `… signing-key overlay` |
| 5 | Each node | `rp genkey runtime/secret/rosenpass` and `rp pubkey runtime/secret/rosenpass pub` |
| 6 | Offline host | Collect `pub/` dirs into `bundle/peers/<name>/`, write `peers.conf` and `SERIAL`, then `… pki wf-sign /sign/bundle /pki/keys/overlay.key` |
| 7 | Quarantine host | Put GGUF + `model.meta` (name, quant, source URL, licence, upstream hash) in a dir, then `wf-sign <dir> /pki/keys/artifact.key` |
| 8 | Quarantine host | `docker pull twobombs/thereminq-tensors:jupyter`, record the digest, import the image into the enclave host, set `THEREMINQ_JUPYTER_IMAGE` |
| 9 | Enclave host | Copy public keys to `runtime/trust/`, bundle and model into `runtime/`, write the two UI secrets, then `docker compose up -d` |

## UI (ThereminQ Jupyter desktop)

| Endpoint (over WireGuard) | Service | Auth |
| --- | --- | --- |
| `http://<WF_UI_BIND>:6080` | noVNC desktop: XFCE, Chrome on local Jupyter, VS Code, terminal | VNC password |
| `http://<WF_UI_BIND>:8888` | Jupyter notebook server, `/notebooks` | Jupyter token |
| inside the UI: `OPENAI_BASE_URL` | Gatekeeper `/v1` → signed model in `inference` | firewall + sanitizer |

Traffic path: WireGuard peer → `rosenpass0` → gateway forward rule to bridge `wf-ui` (`WF_FORWARD_IF=wf-ui`) → `ui-door` → `ui_int` → `ui`. The UI container has no route out; `ui-door` can reach the tunnel and the UI only, because the gateway forward policy drops everything else leaving `wf-ui`.

| Upstream `run-boards` behaviour | In `wallfacer/ui` |
| --- | --- |
| Jupyter `token=''`, `password=''` on 0.0.0.0 | Token from secret via `JUPYTER_TOKEN`, ≥ 32 chars |
| VNC password file `00000000` baked in | Removed at build; written from secret at start |
| xrdp on 3389, PulseAudio system daemon | Not started |
| `GITS-SAC.sh`: downloads Qwen GGUF shards from Hugging Face, serves them unsigned on 9931 | Not started; Ai goes to the signed model via the gatekeeper |
| TensorBoard on 127.0.0.1 | Not started (start it from a notebook when needed) |
| VS Code defaults | Telemetry, updates and extension auto-update off |
| `QRACK_LIB_PATH` | Set to `/usr/local/lib/qrack/libqrack_pinvoke.so` |
| GPU | `/dev/dri` + `/dev/kfd` passed for PyQrack OpenCL / Vulkan |

## Gatekeeper API

| Route | Body | Result |
| --- | --- | --- |
| `POST /v1/tool-call` | `user_request`, `history`, `current_action{name, arguments}`, `tool_descriptions` | `allow` · `deny` · `approval_required` |
| `POST /v1/tool-output` | `output` | `allow` with sanitized text · `deny` (`WF_OUTPUT_MODE=block`) · `flag` |
| `POST /v1/chat/completions` | OpenAI-style `messages` | Firewall + sanitize, forwarded to inference with `stream=false`; 403 on firewall hit |
| `GET /healthz` | — | 200 when Merlin is loaded, else 503 |

Decision order for tool calls: shape check → allow-list (tool, every argument by full-match regex) → syntax + entropy on `user_request` and `scan_args` → sanitize → Merlin with timeout → threshold → consequential rule.

| Deny reason | Meaning |
| --- | --- |
| `tool_not_allowed`, `argument_not_allowed:*`, `argument_pattern:*` | Outside the allow-list |
| `firewall` | Syntax or entropy layer hit; `findings` lists rule and span |
| `merlin_unsafe` | Calibrated score at or above `threshold` |
| `merlin_unavailable`, `merlin_error`, `merlin_timeout` | Fail closed |

| Firewall setting | Default | Effect |
| --- | --- | --- |
| `WF_FW_WINDOW` | 128 chars | Entropy window; shorter text is left to the syntax layer |
| `WF_FW_STEP` | 16 chars | Window stride |
| `WF_FW_ENTROPY` | 5.0 bits/char | Above this a window is a hit |

## Gateway hold-down

| Condition | nftables state |
| --- | --- |
| Startup, or any peer without a Rosenpass PSK | All traffic on `rosenpass0` dropped |
| All peers have a PSK for ≥ `WF_PSK_SETTLE` (180 s) | Released; no session derived before the first PSK can survive WireGuard's 180 s reject limit |
| Any peer PSK unchanged for > `WF_PSK_STALE` (300 s) | Re-engaged |
| `rp` exits | Container exits; restart comes back held down |

Public interface accepts only UDP to the Rosenpass port and port + 1 (WireGuard); everything else is dropped without reply.

## Test status

| Item | Status |
| --- | --- |
| Firewall layers and gatekeeper decisions | 29 unit tests pass (`python3 -m unittest test_gatekeeper`), Merlin stubbed |
| `wf-sign` / `wf-verify` file-set, traversal, tamper, wrong-key, unsigned logic | Passed with an Ed25519 stand-in on OpenSSL 3.0 |
| Shell syntax | All scripts pass `dash -n` / `bash -n` |
| ML-DSA-87 sign/verify, `wf-ca` issuance and CRL | Not run: needs OpenSSL 3.5; `openssl ca` with `default_md = default` on ML-DSA is the first thing to confirm |
| Image builds, Rosenpass `rp` handshake, Vulkan device access, Merlin `to_dict()` field names | Not run: no Docker daemon in the build environment |
| UI secret guards (short token, missing secret, default VNC password) | Refuse to start, as intended |
| UI desktop start, `x0vncserver -localhost`, Docker DNAT through the gateway forward chain | Not run: needs the image and a host |

Measured entropy in tests: English ≈ 4.2 bits/char, random Base64 > 5.0 at 128-char windows, hex ≤ 4.0 (caught by `hex_run` instead).

## Not in this slice

| Requirement | Gap |
| --- | --- |
| MSH-03, MSH-04 | Overlay controller and TPM-sealed enrollment; bundles are assembled and signed by hand (step 6) |
| MSH-07..MSH-10 | Constant-rate padding daemon |
| QKD-01..QKD-11 | ETSI GS QKD 014 client and hybrid key mix |
| PRV-02, PRV-06 | OCI referrer signatures and internal registry; `build.sh` prints image IDs for manual signing |
| GATE-06 | Injection classifier on tool outputs; only the firewall layers run today |
| FW-05, WF-03, WF-04 | Paraphrase step, statistical weight audit, canary probing |
| HW-* | Host-level: measured boot, disk encryption, BMC isolation |
| NVIDIA on Vulkan | Container needs the host's NVIDIA Vulkan ICD JSON and driver libraries mounted; only Mesa RADV ships in the image |
| UI hardening | Runs as root with no capabilities (upstream layout assumes `/root`); Chrome runs `--no-sandbox` as upstream; classic VNC auth uses only 8 password characters, so the tunnel is the real boundary |
| UI packages | No egress, so `pip install` inside notebooks fails; new packages come in through a rebuilt, re-signed image |
| Gateway host | The gateway's forward policy drops all routed Docker traffic on the host; run no other container stacks there |
