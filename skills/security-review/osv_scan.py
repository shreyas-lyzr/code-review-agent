#!/usr/bin/env python3
"""Query OSV.dev for known vulnerabilities in dependencies. Pure stdlib.

Usage:
  python3 osv_scan.py package.json                # npm manifest (deps + devDeps)
  python3 osv_scan.py requirements.txt            # PyPI requirements
  python3 osv_scan.py --eco Go go.mod             # Go modules (best-effort)
  python3 osv_scan.py --pkg lodash --version 4.17.20 --eco npm

Exit code: 0 = no known vulns, 1 = vulns found, 2 = usage/parse error.
"""
import json
import re
import sys
import urllib.request

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


def parse_requirements(path):
    pkgs = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
        if m:
            pkgs.append((m.group(1).split("[")[0], m.group(2), "PyPI"))
    return pkgs


def parse_package_json(path):
    data = json.load(open(path, encoding="utf-8"))
    pkgs = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            exact = re.match(r"^v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$", ver.lstrip("^~"))
            if exact:
                pkgs.append((name, exact.group(1), "npm"))
            else:
                print(f"  (skip {name}@{ver} — not an exact/parsable version; scan the lockfile-resolved version)")
    return pkgs


def parse_go_mod(path):
    pkgs = []
    in_require = False
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if s.startswith("require ("):
            in_require = True
            continue
        if in_require and s == ")":
            in_require = False
            continue
        m = re.match(r"^(?:require\s+)?([\w./\-]+)\s+v([\w.\-+]+)", s)
        if (in_require or s.startswith("require")) and m and "indirect" not in s:
            pkgs.append((m.group(1), m.group(2), "Go"))
        elif in_require and m:
            pkgs.append((m.group(1), m.group(2), "Go"))
    return pkgs


def osv_query(pkgs):
    queries = [
        {"package": {"name": n, "ecosystem": eco}, "version": v} for n, v, eco in pkgs
    ]
    req = urllib.request.Request(
        OSV_URL,
        data=json.dumps({"queries": queries}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read()).get("results", [])


def vuln_detail(vuln_id):
    try:
        with urllib.request.urlopen(OSV_VULN_URL + vuln_id, timeout=15) as r:
            d = json.loads(r.read())
        sev = ""
        for s in d.get("severity", []):
            sev = f" severity={s.get('score', '')}"
            break
        return f"{d.get('summary', '(no summary)')}{sev}"
    except Exception:
        return "(detail fetch failed)"


def main():
    args = sys.argv[1:]
    pkgs = []
    if "--pkg" in args:
        name = args[args.index("--pkg") + 1]
        ver = args[args.index("--version") + 1]
        eco = args[args.index("--eco") + 1] if "--eco" in args else "npm"
        pkgs = [(name, ver, eco)]
    elif args:
        path = args[-1]
        if path.endswith("requirements.txt"):
            pkgs = parse_requirements(path)
        elif path.endswith("package.json"):
            pkgs = parse_package_json(path)
        elif path.endswith("go.mod"):
            pkgs = parse_go_mod(path)
        else:
            print("unsupported manifest; use --pkg/--version/--eco", file=sys.stderr)
            sys.exit(2)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    if not pkgs:
        print("no exact-versioned packages found to scan")
        return

    print(f"scanning {len(pkgs)} package(s) against OSV.dev…")
    results = osv_query(pkgs)
    found = 0
    for (name, ver, eco), res in zip(pkgs, results):
        vulns = res.get("vulns") or []
        if not vulns:
            print(f"  OK    {eco}:{name}@{ver}")
            continue
        found += len(vulns)
        for v in vulns:
            vid = v.get("id", "?")
            print(f"  VULN  {eco}:{name}@{ver}  {vid}  {vuln_detail(vid)}")
    if found:
        print(f"\n{found} known vulnerability record(s) found — cite the IDs above in the review.")
        sys.exit(1)
    print("no known vulnerabilities for the scanned versions")


if __name__ == "__main__":
    main()
