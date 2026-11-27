#!/usr/bin/env python3
"""validate_k8s.py <k8s dir> [generated dir]

Offline checks for the manifests (needs PyYAML): every document parses, carries apiVersion/kind/metadata,
the restricted Pod Security settings are present, and the generated sites patch merges onto the base
Deployment the way a strategic merge patch would (volume 'sites' replaced by name)."""
import glob
import os
import sys

import yaml

base = sys.argv[1]
gen = sys.argv[2] if len(sys.argv) > 2 else None
fails = 0


def check(cond, msg):
    global fails
    print(("  ok   " if cond else "  FAIL ") + msg)
    fails += 0 if cond else 1


docs = {}
for f in sorted(glob.glob(os.path.join(base, "**", "*.yaml"), recursive=True)):
    for d in yaml.safe_load_all(open(f)):
        if not d:
            continue
        if d.get("kind") == "Kustomization":
            for r in d.get("resources", []):
                p = os.path.normpath(os.path.join(os.path.dirname(f), r))
                check(os.path.exists(p) or r == "secrets.yaml", f"{os.path.relpath(f, base)}: resource {r} exists")
            continue
        check(all(k in d for k in ("apiVersion", "kind", "metadata")), f"{os.path.relpath(f, base)}: {d.get('kind')} has apiVersion/kind/metadata")
        docs[(d["kind"], d["metadata"]["name"])] = d

dep = docs[("Deployment", "pqc-edge")]
pod = dep["spec"]["template"]["spec"]
c = pod["containers"][0]
check(pod["securityContext"]["runAsNonRoot"] and pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault", "pod: non-root + RuntimeDefault seccomp")
check(c["securityContext"]["readOnlyRootFilesystem"] and c["securityContext"]["capabilities"]["drop"] == ["ALL"]
      and c["securityContext"]["allowPrivilegeEscalation"] is False, "container: read-only rootfs, no capabilities, no escalation")
svc = docs[("Service", "pqc-edge")]
check(svc["spec"]["ipFamilyPolicy"] == "PreferDualStack" and svc["spec"]["ipFamilies"] == ["IPv4", "IPv6"], "service: dual-stack IPv4 + IPv6")
check({p["port"] for p in svc["spec"]["ports"]} == {443, 80}, "service: 443 and 80")
cm = docs[("ConfigMap", "pqc-edge")]
check(cm["data"]["PQC_PROFILE"] in ("compat", "pqc-first", "pqc-only"), "configmap: valid profile")
check(docs[("Namespace", "pqc-edge")]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted", "namespace: PSA restricted")

if gen:
    patch = yaml.safe_load(open(os.path.join(gen, "sites-patch.yaml")))
    vols = {v["name"]: v for v in pod["volumes"]}
    for v in patch["spec"]["template"]["spec"]["volumes"]:
        vols[v["name"]] = v
    srcs = vols["sites"]["projected"]["sources"]
    paths = [i["path"] for s in srcs for i in s["secret"]["items"]]
    check(len(srcs) == 4 and all(p.count("/") == 2 for p in paths), "merged deployment: 2 sites x (pqc, classic) projected")
    check(all(s["secret"].get("optional") for s in srcs if s["secret"]["name"].endswith("-classic")), "classic halves optional")
    secs = [d for d in yaml.safe_load_all(open(os.path.join(gen, "secrets.yaml"))) if d]
    names = {s["metadata"]["name"] for s in secs}
    needed = {s["secret"]["name"] for s in srcs if not s["secret"].get("optional")}
    check(needed <= names, "every required secret is generated")
    check(all(s["type"] == "Opaque" for s in secs if s["metadata"]["name"].endswith("-pqc")), "ML-DSA secrets are Opaque")

print(f"\nvalidate_k8s: {'0 failed' if not fails else str(fails) + ' failed'}")
sys.exit(1 if fails else 0)
