"""Wallfacer semantic gatekeeper (GATE-01..GATE-08, FW-01..FW-04, FW-08).

The single choke point between agent containers and everything else.

    POST /v1/tool-call          allow-list -> firewall -> Merlin -> approval rule
    POST /v1/tool-output        firewall on tool output before it re-enters agent context
    POST /v1/chat/completions   firewall + sanitizer, then forward to the local model
    GET  /v1/models             passthrough to the local model (client discovery)
    GET  /healthz

Every decision is one JSON line on stdout. Anything unexpected is a deny.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import firewall

LISTEN = os.environ.get("WF_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("WF_PORT", "8443"))
POLICY_PATH = os.environ.get("WF_POLICY", "/etc/wallfacer/policy.json")
UPSTREAM = os.environ.get("WF_UPSTREAM", "http://inference:8080")
MERLIN_DIR = os.environ.get("WF_MERLIN_DIR", "/opt/merlin-model")
OUTPUT_MODE = os.environ.get("WF_OUTPUT_MODE", "block")     # block | flag
MAX_BODY = int(os.environ.get("WF_MAX_BODY", str(1 << 20)))

_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get("WF_WORKERS", "4")))


def log(event: dict) -> None:
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sys.stdout.write(json.dumps(event, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def digest(obj) -> str:
    return hashlib.sha384(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:24]


# ---------- policy (GATE-04, GATE-07, GATE-08) ----------

class Policy:
    def __init__(self, path: str):
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        self.threshold = float(raw.get("threshold", 0.5))
        self.timeout_s = float(raw.get("timeout_s", 2.0))
        self.tools: dict[str, dict] = {}
        for name, spec in raw.get("tools", {}).items():
            self.tools[name] = {
                "args": {k: re.compile(v) for k, v in spec.get("args", {}).items()},
                "scan_args": set(spec.get("scan_args", [])),
                "consequential": bool(spec.get("consequential", False)),
            }

    def check(self, action: dict) -> str | None:
        """Return a deny reason, or None when the call is inside the allow-list."""
        spec = self.tools.get(action.get("name"))
        if spec is None:
            return "tool_not_allowed"
        args = action.get("arguments", {})
        if not isinstance(args, dict):
            return "arguments_not_object"
        for key, value in args.items():
            pattern = spec["args"].get(key)
            if pattern is None:
                return f"argument_not_allowed:{key}"
            text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            if not pattern.fullmatch(text):
                return f"argument_pattern:{key}"
        return None


POLICY = Policy(POLICY_PATH)


# ---------- Merlin (GATE-02, GATE-03, GATE-05) ----------

def _load_merlin():
    from merlin_guard import Invocation, MerlinGuard   # reference package, not a generic pipeline
    return Invocation, MerlinGuard.from_pretrained(MERLIN_DIR)


try:
    _INVOCATION, _GUARD = _load_merlin()
    MERLIN_ERROR = None
except Exception as exc:   # gatekeeper still starts, but every tool call is denied
    _INVOCATION, _GUARD = None, None
    MERLIN_ERROR = repr(exc)


def merlin_unsafe_score(inv: dict) -> float:
    """Calibrated probability of 'unsafe'. Raises on anything it cannot interpret."""
    verdict = _GUARD.predict(_INVOCATION(
        user_request=inv["user_request"],
        history=inv["history"],
        current_action=inv["current_action"],
        tool_descriptions=inv["tool_descriptions"],
    )).to_dict()
    for key in ("unsafe_probability", "probability_unsafe", "p_unsafe", "score", "probability"):
        if isinstance(verdict.get(key), (int, float)):
            return float(verdict[key])
    label = str(verdict.get("label", verdict.get("verdict", ""))).lower()
    if label in ("safe", "unsafe"):
        return 1.0 if label == "unsafe" else 0.0
    raise ValueError(f"unrecognised Merlin verdict shape: {sorted(verdict)}")


# ---------- decisions ----------

def decide_tool_call(inv: dict) -> dict:
    for field, kind in (("user_request", str), ("history", list),
                        ("current_action", dict), ("tool_descriptions", list)):
        if not isinstance(inv.get(field), kind):
            return {"decision": "deny", "reason": f"bad_field:{field}"}
    action = inv["current_action"]

    reason = POLICY.check(action)
    if reason:
        return {"decision": "deny", "reason": reason}

    findings = firewall.scan(inv["user_request"])
    spec = POLICY.tools[action["name"]]
    for key in spec["scan_args"]:
        value = action.get("arguments", {}).get(key)
        if isinstance(value, str):
            findings += firewall.scan(value)
    if findings:
        return {"decision": "deny", "reason": "firewall",
                "findings": [f.to_dict() for f in findings[:10]]}

    if _GUARD is None:
        return {"decision": "deny", "reason": "merlin_unavailable", "detail": MERLIN_ERROR}
    inv = dict(inv, user_request=firewall.sanitize(inv["user_request"]))
    try:
        score = _EXECUTOR.submit(merlin_unsafe_score, inv).result(timeout=POLICY.timeout_s)
    except concurrent.futures.TimeoutError:
        return {"decision": "deny", "reason": "merlin_timeout"}
    except Exception as exc:
        return {"decision": "deny", "reason": "merlin_error", "detail": repr(exc)}

    if score >= POLICY.threshold:
        return {"decision": "deny", "reason": "merlin_unsafe", "score": round(score, 4)}
    if spec["consequential"]:
        return {"decision": "approval_required", "reason": "consequential_tool", "score": round(score, 4)}
    return {"decision": "allow", "score": round(score, 4)}


def decide_tool_output(body: dict) -> dict:
    text = body.get("output")
    if not isinstance(text, str):
        return {"decision": "deny", "reason": "bad_field:output"}
    findings = firewall.scan(text)
    if findings:
        return {"decision": "deny" if OUTPUT_MODE == "block" else "flag", "reason": "firewall",
                "findings": [f.to_dict() for f in findings[:10]]}
    return {"decision": "allow", "output": firewall.sanitize(text)}


def prepare_chat(body: dict) -> tuple[dict | None, dict]:
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return None, {"decision": "deny", "reason": "bad_field:messages"}
    clean = []
    for m in msgs:
        if not isinstance(m, dict) or not isinstance(m.get("content"), str):
            return None, {"decision": "deny", "reason": "unsupported_message_shape"}
        if m.get("role") in ("user", "tool"):
            findings = firewall.scan(m["content"])
            if findings:
                return None, {"decision": "deny", "reason": "firewall",
                              "findings": [f.to_dict() for f in findings[:10]]}
        clean.append({"role": m.get("role"), "content": firewall.sanitize(m["content"])})
    out = {k: v for k, v in body.items() if k not in ("messages", "stream")}
    out["messages"] = clean
    out["stream"] = False
    return out, {"decision": "allow"}


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    server_version = "wallfacer-gatekeeper"
    sys_version = ""

    def log_message(self, *_):   # decisions are logged as JSON instead
        pass

    def _send(self, code: int, obj) -> None:
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            obj = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return None
        return obj if isinstance(obj, dict) else None

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200 if _GUARD is not None else 503,
                       {"merlin": _GUARD is not None, "tools": len(POLICY.tools)})
        elif self.path == "/v1/models":          # OpenAI clients (Jupyter, VS Code) list models first
            try:
                with urllib.request.urlopen(f"{UPSTREAM}/v1/models", timeout=10) as r:
                    self._send(r.status, r.read())
            except (urllib.error.URLError, TimeoutError) as exc:
                self._send(502, {"error": "upstream_unavailable", "detail": repr(exc)})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        body = self._body()
        if body is None:
            self._send(400, {"decision": "deny", "reason": "bad_request"})
            return
        if self.path == "/v1/tool-call":
            result = decide_tool_call(body)
            tool = (body.get("current_action") or {}).get("name") if isinstance(body.get("current_action"), dict) else None
            event = {"route": "tool-call", "tool": tool, "input": digest(body), **result}
            if result["decision"] != "allow":
                event["context"] = body          # GATE-05: blocked calls logged with full context
            log(event)
            self._send(200, result)
        elif self.path == "/v1/tool-output":
            result = decide_tool_output(body)
            log({"route": "tool-output", "input": digest(body),
                 **{k: v for k, v in result.items() if k != "output"}})
            self._send(200, result)
        elif self.path == "/v1/chat/completions":
            forward, verdict = prepare_chat(body)
            log({"route": "chat", "input": digest(body), **verdict})
            if forward is None:
                self._send(403, verdict)
                return
            req = urllib.request.Request(f"{UPSTREAM}/v1/chat/completions",
                                         data=json.dumps(forward).encode(),
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=float(os.environ.get("WF_UPSTREAM_TIMEOUT", "300"))) as r:
                    self._send(r.status, r.read())
            except urllib.error.HTTPError as exc:
                self._send(exc.code, exc.read())
            except (urllib.error.URLError, TimeoutError) as exc:
                self._send(502, {"error": "upstream_unavailable", "detail": repr(exc)})
        else:
            self._send(404, {"error": "not_found"})


def main() -> None:
    log({"route": "startup", "merlin": _GUARD is not None, "merlin_error": MERLIN_ERROR,
         "tools": sorted(POLICY.tools), "threshold": POLICY.threshold, "output_mode": OUTPUT_MODE})
    ThreadingHTTPServer((LISTEN, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
