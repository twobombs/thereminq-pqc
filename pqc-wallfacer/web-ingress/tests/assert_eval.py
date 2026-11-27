#!/usr/bin/env python3
"""assert_eval.py <pqc-eval json file> key=value [key=value ...]

Checks every target in a pqc-eval --format json report. Values may be prefixes ending in '*'.
Exit 0 when all match, 1 otherwise; prints one line per mismatch."""
import json
import sys

report = json.load(open(sys.argv[1]))
want = dict(a.split("=", 1) for a in sys.argv[2:])
bad = 0
for r in report:
    for k, v in want.items():
        got = r.get(k, "")
        ok = got.startswith(v[:-1]) if v.endswith("*") else got == v
        if not ok:
            print(f"  MISMATCH {r['target']} {k}: want {v!r} got {got!r}")
            bad += 1
sys.exit(1 if bad else 0)
