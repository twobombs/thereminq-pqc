"""Wallfacer LLM firewall: syntax, entropy and sanitizer layers (FW-02, FW-03, FW-04).

Pure standard library, no model. Order of use in the gatekeeper:
    findings = scan(text)            # syntax + entropy on the raw text
    clean    = sanitize(text)        # breaks exact-match / hash triggers before the model sees it
"""

from __future__ import annotations

import math
import os
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

ENTROPY_WINDOW = int(os.environ.get("WF_FW_WINDOW", "128"))
ENTROPY_STEP = int(os.environ.get("WF_FW_STEP", "16"))
ENTROPY_MAX = float(os.environ.get("WF_FW_ENTROPY", "5.0"))

# Unicode categories removed by the sanitizer: format (zero-width, bidi overrides), control,
# private use and surrogates. Newline and tab survive.
_STRIP_CATEGORIES = {"Cf", "Cc", "Co", "Cs"}
_KEEP = {"\n", "\t"}


@dataclass(frozen=True)
class Finding:
    layer: str      # "syntax" or "entropy"
    rule: str
    start: int
    end: int
    detail: str = ""

    def to_dict(self) -> dict:
        return {"layer": self.layer, "rule": self.rule, "start": self.start,
                "end": self.end, "detail": self.detail}


# ---------- FW-02 syntax layer ----------

_DELIMITER = re.compile(r"\|\||>>>|###")
_DIGIT_RUN = re.compile(r"\d{32,}")
_HEX_RUN = re.compile(r"\b(?:0x)?[0-9A-Fa-f]{48,}\b")
_HEX_BYTES = re.compile(r"(?:\b0x[0-9A-Fa-f]{2}\b[\s,]*){16,}")
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")


def _looks_like_base64(s: str) -> bool:
    """Filter path-like and word-like runs out of the Base64 candidates."""
    body = s.rstrip("=")
    if s.count("/") * 8 > len(body):          # file paths: many separators
        return False
    has_digit = any(c.isdigit() for c in body)
    has_upper = any(c.isupper() for c in body)
    has_lower = any(c.islower() for c in body)
    return has_digit and has_upper and has_lower


def syntax_findings(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _DELIMITER.finditer(text):
        out.append(Finding("syntax", "delimiter", m.start(), m.end(), m.group(0)))
    for m in _DIGIT_RUN.finditer(text):
        out.append(Finding("syntax", "digit_run", m.start(), m.end(), f"{m.end() - m.start()} digits"))
    for m in _HEX_RUN.finditer(text):
        out.append(Finding("syntax", "hex_run", m.start(), m.end(), f"{m.end() - m.start()} chars"))
    for m in _HEX_BYTES.finditer(text):
        out.append(Finding("syntax", "hex_dump", m.start(), m.end()))
    for m in _B64_CANDIDATE.finditer(text):
        if _looks_like_base64(m.group(0)):
            out.append(Finding("syntax", "base64_blob", m.start(), m.end(), f"{m.end() - m.start()} chars"))
    return out


# ---------- FW-03 entropy layer ----------

def shannon(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def entropy_findings(text: str, window: int = ENTROPY_WINDOW, step: int = ENTROPY_STEP,
                     limit: float = ENTROPY_MAX) -> list[Finding]:
    """Flag windows above `limit` bits/char. Text shorter than one window is not judged:
    entropy estimates on short strings are unreliable, so FW-02 has to catch those."""
    out: list[Finding] = []
    if len(text) < window:
        return out
    last_end = -1
    for i in range(0, len(text) - window + 1, step):
        h = shannon(text[i:i + window])
        if h > limit:
            if i <= last_end and out:            # merge overlapping hits into one finding
                prev = out[-1]
                out[-1] = Finding("entropy", "high_entropy", prev.start, i + window, prev.detail)
            else:
                out.append(Finding("entropy", "high_entropy", i, i + window, f"{h:.2f} bits/char"))
            last_end = i + window
    return out


def scan(text: str) -> list[Finding]:
    return syntax_findings(text) + entropy_findings(text)


# ---------- FW-04 sanitizer ----------

_SPACES = re.compile(r"[ \t ]+")
_BLANK_LINES = re.compile(r"\n{3,}")


def sanitize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if ch in _KEEP or unicodedata.category(ch) not in _STRIP_CATEGORIES)
    t = _SPACES.sub(" ", t)
    t = "\n".join(line.strip() for line in t.split("\n"))
    t = _BLANK_LINES.sub("\n\n", t)
    return t.strip()
