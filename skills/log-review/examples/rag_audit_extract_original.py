"""AST inventory of print/logger calls and exception-text sinks in rag app code."""
import ast, json, os, re, sys
ROOT = "/Users/zeus/lyzr-workspace/rag"
SKIP = ("/.venv/", "/node_modules/", "/tests/", "/__tests__/")
LOGGER_RE = re.compile(r"^(logger|logging|log|self\.logger|self\._logger|_logger|LOGGER)\.(debug|info|warning|warn|error|exception|critical)$")
out = {"print": [], "logger": [], "sinks": []}

def name_of(node):
    if isinstance(node, ast.Attribute):
        base = name_of(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Name):
        return node.id
    return None

for dp, dn, fn in os.walk(ROOT):
    if any(s in dp + "/" for s in SKIP): continue
    for f in fn:
        if not f.endswith(".py") or f.startswith("test_") or f == "conftest.py": continue
        path = os.path.join(dp, f); rel = os.path.relpath(path, ROOT)
        try: src = open(path, encoding="utf-8").read(); tree = ast.parse(src)
        except Exception as e: print("PARSE FAIL", rel, e, file=sys.stderr); continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                n = name_of(node.func)
                seg = ast.get_source_segment(src, node) or ""
                seg1 = " ".join(seg.split())
                if n == "print":
                    out["print"].append({"file": rel, "line": node.lineno, "src": seg1})
                elif n and LOGGER_RE.match(n):
                    out["logger"].append({"file": rel, "line": node.lineno, "level": n.split(".")[-1], "src": seg1})
                elif n in ("HTTPException", "JSONResponse", "fastapi.HTTPException") or (n and n.endswith("Exception")) or (n and n.endswith("Error")):
                    out["sinks"].append({"file": rel, "line": node.lineno, "call": n, "src": seg1})
json.dump(out, open(f"{os.environ['S']}/rag_audit.json", "w"), indent=1)
print("prints:", len(out["print"]), "logger calls:", len(out["logger"]), "raise/response sinks:", len(out["sinks"]))
