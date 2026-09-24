"""Regex inventory of console/logger/response/throw/UI-toast calls in a TS/JS tree.
Usage as module: rows = scan(root)  ->  list of {file,line,lang,kind,call,level,src}
"""
import os, re

SKIP_DIRS = {"node_modules", ".next", "dist", "build", "out", "coverage", "storybook-static", ".git", "__tests__", "e2e", "cypress", "vendor", ".turbo", ".vercel", "public", "__mocks__"}
EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
PATTERNS = [
    ("print", re.compile(r"\bconsole\.(log|error|warn|info|debug|trace|dir|table|group)\s*\(")),
    ("print", re.compile(r"\bprocess\.(stdout|stderr)\.write\s*\(")),
    ("logger", re.compile(r"\b(?:this\.)?(logger|log|winston|pino|bunyan|logging|Logger|LOG|serverLogger|apiLogger)\.(debug|info|warn|warning|error|fatal|trace|log|verbose|silly)\s*\(")),
    ("sink", re.compile(r"\bthrow\s+new\s+([A-Za-z_.]*(?:Error|Exception))\s*\(")),
    ("sink", re.compile(r"\bres\.status\s*\([^)]*\)\s*\.(json|send|end)\s*\(")),
    ("sink", re.compile(r"\bres\.(json|send)\s*\(")),
    ("sink", re.compile(r"\b(NextResponse|Response)\.json\s*\(")),
    ("sink", re.compile(r"\bnew\s+(NextResponse|Response)\s*\(")),
    ("sink", re.compile(r"\breply\.(send|code|status)\s*\(")),
    ("sink", re.compile(r"\bnext\s*\(\s*(?:new\s+)?[A-Za-z]*Error")),
    ("ui", re.compile(r"\btoast(?:\.(error|success|info|warning|warn|message|custom|loading))?\s*\(")),
    ("ui", re.compile(r"\b(?:message|notification|notify)\.(error|success|warning|warn|info|open)\s*\(")),
    ("ui", re.compile(r"\b(alert|setError|setErrorMessage|setErrorMsg|setApiError|showError|showToast|enqueueSnackbar)\s*\(")),
]

def _segment(text, start, max_len=500):
    depth = 0; i = text.find("(", start)
    if i < 0: return text[start:start + 120]
    j = i
    while j < len(text) and j - start < max_len:
        ch = text[j]
        if ch == "(": depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0: j += 1; break
        j += 1
    return " ".join(text[start:j].split())

def scan(root):
    rows = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in sorted(filenames):
            if not fn.endswith(EXT) or fn.endswith(".d.ts") or ".test." in fn or ".spec." in fn or ".stories." in fn or fn.endswith(".min.js"):
                continue
            path = os.path.join(dirpath, fn); rel = os.path.relpath(path, root)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if text and max(len(l) for l in text.splitlines()[:200] or [""]) > 3000:
                continue  # minified/generated
            for kind, rx in PATTERNS:
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    seg = _segment(text, m.start())
                    call = m.group(0).rstrip("( \t")
                    call = call.replace(" ", "")
                    level = ""
                    if kind == "logger":
                        level = m.group(2).lower().replace("warning", "warn")
                    elif kind == "print":
                        level = (m.group(1) or "").lower()
                    rows.append({"file": rel, "line": line, "lang": "ts", "kind": kind, "call": call, "level": level, "src": seg[:400]})
    return rows

if __name__ == "__main__":
    import sys, json
    r = scan(sys.argv[1]); json.dump(r, open(sys.argv[2], "w"), indent=1); print("rows", len(r))
