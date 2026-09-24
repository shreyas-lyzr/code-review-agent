"""Run every extractor on one repo, merge, flag priority rows, collect control signals.
Usage: python audit_run.py <repo_root> <repo_name> <scratch_dir>
Writes <scratch>/<name>_audit.json and <scratch>/<name>_priority.txt
"""
import json, os, re, subprocess, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tsaudit

ROOT, NAME, S = sys.argv[1], sys.argv[2], sys.argv[3]
HERE = os.path.dirname(os.path.abspath(__file__))
SKIP = {".git", ".venv", "venv", "node_modules", "tests", "test", "__pycache__", "vendor", ".next", "dist", "build"}

def count(ext_pred):
    n = 0
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in SKIP and not d.startswith(".")]
        n += sum(1 for f in fn if ext_pred(f))
    return n

files = {"py": count(lambda f: f.endswith(".py")), "go": count(lambda f: f.endswith(".go") and not f.endswith("_test.go")),
         "ts": count(lambda f: f.endswith((".ts", ".tsx", ".js", ".jsx")) and not f.endswith(".d.ts"))}
rows = []
if files["py"]:
    out = f"{S}/{NAME}_py.json"
    subprocess.run([sys.executable, f"{HERE}/audit_extract.py"], env={**os.environ, "ROOT": ROOT, "OUT": out}, check=True, capture_output=True)
    d = json.load(open(out))
    for r in d["print"]: rows.append({**r, "lang": "py", "kind": "print", "level": ""})
    for r in d["logger"]: rows.append({**r, "lang": "py", "kind": "logger", "call": "logger." + r["level"]})
    for r in d["sinks"]: rows.append({**r, "lang": "py", "kind": "sink", "level": ""})
if files["go"]:
    out = f"{S}/{NAME}_go.json"
    p = subprocess.run(["go", "run", "-C", f"{HERE}/goaudit", ".", ROOT, out], capture_output=True, text=True)
    if p.returncode != 0: print("go extractor failed:", p.stderr[:400])
    else: rows += json.load(open(out))
if files["ts"]:
    rows += tsaudit.scan(ROOT)

# --- classification signals -------------------------------------------------
STRONG = re.compile(r"(?i)(password|passwd|pwd\b|secret|token|api[_-]?key|apikey|private_key|credential|authorization|bearer|cookie|session_id|x-api-key|dsn|conn(ection)?[_ ]?str|mongo_url|redis_url|database_url|\.env\b|environ|os\.getenv|headers|kwargs|\*\*|model_dump|\.dict\(\)|json\.dumps|vars\(|repr\(|payload|request\.body|req\.body|request\.json|config\b|settings\b|params\b|creds\b|auth\b|jwt|signature|presign|x-amz|sig=)")
WEAK = re.compile(r"(?i)(\burl\b|\buri\b|host|endpoint|path|query|filter|\bid\b|email|user|org|tenant|schema|column|collection|table|body|response|resp\b|data\b|result|row|record|document|doc\b|message|msg\b|content|prompt|text)")
EXC = {
    "py": re.compile(r"(\{(e|err|exc|ex|error|exception|ex_|e2|inner|[a-z_]*_error|[a-z_]*_exc)(\b|[\.\)\[:!}])|str\((e|err|exc|ex|error|exception)\)|repr\((e|err|exc|ex|error)\)|format_exc\(\)|logger\.exception|exc_info=True|%s|\{[a-z_]*err[a-z_]*\}|\{[a-z_]*detail[a-z_]*\}|\{[a-z_]*msg[a-z_]*\}|\{[a-z_]*reason[a-z_]*\}|\{traceback)"),
    "go": re.compile(r"(\berr\b|err\.Error\(\)|%v|%w|%s|%\+v|%#v|errors\.|\.Error\(\))"),
    "ts": re.compile(r"(\b(e|err|error|exception|ex|reason|detail|details)\b|\.message\b|\.stack\b|\.response\b|\.data\b|JSON\.stringify)"),
}
INTERP = {
    "py": re.compile(r"(f\"|f'|%\s*\(|%[sdr]|\.format\(|,\s*[a-zA-Z_][\w\.\[\]\(\)]*\s*[,)]|\+\s*[a-zA-Z_])"),
    "go": re.compile(r"(%[a-zA-Z+#]|,\s*[a-zA-Z_][\w\.\(\)\[\]]*\s*[,)]|\+\s*[a-zA-Z_])"),
    "ts": re.compile(r"(\$\{|,\s*[a-zA-Z_][\w\.\(\)\[\]]*\s*[,)]|\+\s*[a-zA-Z_]|JSON\.stringify)"),
}
SCRIPT_PATH = re.compile(r"(^|/)(scripts?|tools?|bin|examples?|docs?|migrations?|benchmarks?|cmd/[^/]*(tool|cli|migrate|seed|script)|hack|dev|local|notebooks?|samples?|playground|storybook)(/|$)")
HTTP_SINK = re.compile(r"(HTTPException|JSONResponse|PlainTextResponse|Response\b|http\.Error|\.JSON$|AbortWithStatusJSON|AbortWithError|\.String$|\.Data$|\.Encode$|\.Write$|\.WriteString$|\.Send|res\.status|res\.json|res\.send|NextResponse|reply\.|respond|Respond|render|Render|writeError|WriteError|sendError|SendError|handleError)")
UI_KINDS = {"ui"}

for r in rows:
    r["id"] = f'{r["file"]}:{r["line"]}'
    s = r["src"]; lang = r["lang"]
    r["strong"] = bool(STRONG.search(s)); r["weak"] = bool(WEAK.search(s))
    r["exc"] = bool(EXC[lang].search(s)); r["interp"] = bool(INTERP[lang].search(s))
    r["script"] = bool(SCRIPT_PATH.search(r["file"]))
    r["http"] = r["kind"] == "sink" and bool(HTTP_SINK.search(r.get("call", "")))
    score = 0
    if r["kind"] == "print" and not r["script"] and r["interp"]: score += 3
    if r["strong"] and r["interp"]: score += 5 if re.search(r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|private_key|credential|authorization|bearer|cookie|dsn|conn(ection)?[_ ]?str|mongo_url|redis_url|database_url|x-api-key|headers|kwargs|\*\*|model_dump|\.dict\(\)|json\.dumps|vars\(|repr\(|environ|os\.getenv)", s) else 3
    if r["http"] and (r["exc"] or r["strong"]): score += 3
    if r["kind"] == "logger" and r["exc"] and r["level"] in ("error", "exception", "warning", "warn", "info", "fatal", "print", ""): score += 1
    if re.search(r"format_exc\(\)|debug\.Stack\(\)|\.stack\b|print_exc", s) and not (r["kind"] == "logger" and r["level"] == "debug"): score += 2
    if r["script"]: score = max(0, score - 3)
    r["score"] = score

def sig(pattern, exts, flags=re.I):
    rx = re.compile(pattern, flags); hits = []
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in SKIP and not d.startswith(".")]
        for f in fn:
            if not f.endswith(exts): continue
            p = os.path.join(dp, f)
            try: txt = open(p, encoding="utf-8", errors="replace").read()
            except Exception: continue
            for m in rx.finditer(txt):
                hits.append(f"{os.path.relpath(p, ROOT)}:{txt.count(chr(10), 0, m.start()) + 1}")
                if len(hits) > 40: return hits
    return hits

PY = (".py",); GO = (".go",); TS = (".ts", ".tsx", ".js", ".jsx")
signals = {
    "py_root_logger": sig(r"logging\.basicConfig\(|dictConfig\(|getLogger\(\)\.(setLevel|addHandler)", PY),
    "py_print_guard": sig(r"builtins\.print\s*=", PY),
    "py_exception_handler": sig(r"exception_handler\(|add_exception_handler\(", PY),
    "py_detail_passthrough": sig(r"detail\s*=\s*(str\(\s*(e|err|exc|ex|error)\s*\)|f\"[^\"]*\{(e|err|exc|ex|error)[\}\.]|f'[^']*\{(e|err|exc|ex|error)[\}\.]|(e|err|exc|ex|error)\.detail|repr\()", PY),
    "py_hide_input": sig(r"hide_input_in_errors", PY),
    "py_access_log_off": sig(r"access_log\s*=\s*False|--no-access-log|getLogger\(\"uvicorn\.access\"\)\.setLevel|uvicorn\.access.*(WARNING|ERROR|disabled)", PY + (".sh", "Dockerfile", ".yml", ".yaml")),
    "py_format_exc_nondebug": sig(r"^(?!.*logger\.debug).*format_exc\(\)", PY, re.M),
    "py_log_level_default": sig(r"LOG_LEVEL[\"'],\s*[\"'](DEBUG|INFO|WARNING|ERROR)[\"']", PY),
    "py_debug_forced": sig(r"setLevel\(logging\.DEBUG\)|level\s*=\s*logging\.DEBUG|set_verbose\s*=\s*True|_turn_on_debug\(\)|echo\s*=\s*True", PY),
    "py_httpx_silenced": sig(r"getLogger\(\"httpx\"\)\.setLevel", PY),
    "go_recover": sig(r"gin\.Recovery\(|recover\(\)|middleware\.Recoverer|Recover\(\)", GO),
    "go_err_in_response": sig(r"(JSON|String|Error|WriteString|Data|Send|SendString)\([^\n]*err\.Error\(\)", GO),
    "go_structured_logger": sig(r"zap\.New|slog\.New|logrus\.New|zerolog\.New|log\.New\(|zap\.Must", GO),
    "ts_server_console": sig(r"console\.(log|error|warn|info|debug)\(", TS) if any(x in ("app/api", "pages/api", "server", "api") for x in os.listdir(ROOT) if os.path.isdir(os.path.join(ROOT, x))) else [],
    "dockerignore": [".dockerignore"] if os.path.exists(os.path.join(ROOT, ".dockerignore")) else [],
    "dockerignore_env": sig(r"^\s*\.?\*?\.env", (".dockerignore",), re.M) if os.path.exists(os.path.join(ROOT, ".dockerignore")) else [],
    "gitignore_env": sig(r"^\s*\.?\*?\.env", (".gitignore",), re.M),
    "dockerfile_copy_all": sig(r"^COPY\s+\.\s+", ("Dockerfile",), re.M),
    "env_committed": [f for f in os.listdir(ROOT) if f == ".env" or (f.startswith(".env.") and "example" not in f and "sample" not in f and "template" not in f)],
}

def git(*a):
    return subprocess.run(["git", "-C", ROOT, *a], capture_output=True, text=True).stdout.strip()

meta = {"repo": NAME, "root": ROOT, "commit": git("rev-parse", "--short", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"), "date": git("log", "-1", "--format=%cs"), "files": files}
rows.sort(key=lambda r: (r["file"], r["line"]))
json.dump({"meta": meta, "rows": rows, "signals": signals}, open(f"{S}/{NAME}_audit.json", "w"), indent=1)
prio = sorted([r for r in rows if r["score"] > 0], key=lambda r: (-r["score"], r["file"], r["line"]))[:160]
with open(f"{S}/{NAME}_priority.txt", "w") as f:
    for r in prio:
        f.write(f'{r["id"]} [{r["lang"]}/{r["kind"]}/{r.get("level","")}/score={r["score"]}] {r["src"][:220]}\n')
kinds = collections.Counter(r["kind"] for r in rows)
print(f'{NAME}: commit {meta["commit"]} files {files} rows {len(rows)} {dict(kinds)} priority {len(prio)}')
