"""Generic AST inventory: print-family calls, logger calls, raise/response sinks.
ROOT=<repo> OUT=<json> python audit_extract.py
"""
import ast, json, os, re

ROOT = os.environ["ROOT"]; OUT = os.environ["OUT"]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "tests", "test", "__pycache__", ".mypy_cache"}
LOGGER_RE = re.compile(r"^(logger|logging|log|self\.logger|self\._logger|_logger|LOGGER|_log|LOG|self\.log)\.(debug|info|warning|warn|error|exception|critical)$")
PRINT_FAMILY = {"print", "pprint", "pprint.pprint", "sys.stdout.write", "sys.stderr.write", "traceback.print_exc",
                "traceback.print_exception", "click.echo", "typer.echo", "rich.print", "console.print", "os.write"}
SINK_RE = re.compile(r"(HTTPException|JSONResponse|PlainTextResponse|StreamingResponse|Response|Error|Exception|Failure)$")

def dotted(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None

out = {"print": [], "logger": [], "sinks": [], "files": 0, "skipped": []}
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in sorted(filenames):
        if not fn.endswith(".py"): continue
        path = os.path.join(dirpath, fn); rel = os.path.relpath(path, ROOT)
        source = open(path, encoding="utf-8").read()
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as e:
            out["skipped"].append(f"{rel}: {e}"); continue
        out["files"] += 1
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call): continue
            n = dotted(node.func)
            if not n: continue
            seg = ast.get_source_segment(source, node) or ""
            seg1 = " ".join(seg.split())
            row = {"file": rel, "line": node.lineno, "src": seg1}
            if n in PRINT_FAMILY:
                out["print"].append({**row, "call": n})
            elif LOGGER_RE.match(n):
                out["logger"].append({**row, "level": n.split(".")[-1]})
            elif SINK_RE.search(n.split(".")[-1]):
                out["sinks"].append({**row, "call": n})
json.dump(out, open(OUT, "w"), indent=1)
print("files", out["files"], "prints", len(out["print"]), "logger", len(out["logger"]), "sinks", len(out["sinks"]), "skipped", out["skipped"])
