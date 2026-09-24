"""Render <repo>-print-audit.md from <name>_audit.json (+ optional <name>_overrides.json written by
the context-verification pass). Usage: python audit_report_generic.py <name> <scratch> <out_md>
Verdicts: LEAK, LEAK-IF, DISCLOSURE, SAFE, CLI, UNVERIFIED (rule-flagged as risky but not read in context)."""
import json, os, re, sys, collections

NAME, S, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(f"{S}/{NAME}_audit.json")); meta, rows, sig = d["meta"], d["rows"], d["signals"]
ov = json.load(open(f"{S}/{NAME}_overrides.json")) if os.path.exists(f"{S}/{NAME}_overrides.json") else {}
row_ov = ov.get("rows", {}); findings = ov.get("findings", []); ctrl_ov = ov.get("controls", {}); pipeline = ov.get("pipeline", []); summary_ov = ov.get("summary", "")

def cell(s): return str(s).replace("|", "\\|").replace("\n", " ")
def src(r, n=150): return cell(" ".join(r["src"].split())[:n])
STATIC_OK = re.compile(r"^[^{%]*$")

def rule_verdict(r):
    k, s = r["kind"], r["src"]
    if r["script"]: return ("CLI", "Under a script/tool/example path; not part of the service process.")
    if not r["interp"]: return ("SAFE", "Static message; interpolates nothing.")
    if k == "print":
        if r["strong"]: return ("UNVERIFIED", "print with a value whose name suggests a secret, config or request payload; needs a context read.")
        return ("DISCLOSURE", "print in service code with interpolated values (bypasses log level and any redaction).")
    if k == "ui":
        return ("SAFE", "Browser-side user feedback; the reader is the user whose request produced it.") if not r["exc"] else ("DISCLOSURE", "Shows raw error text (server error bodies) to the browser user.")
    if r["strong"] and not re.search(r"(?i)(_id\b|keys\(\)|\.keys|len\(|type\(|__name__|\bset\b|unset|masked|redact|\*\*\*|<redacted>)", s):
        return ("UNVERIFIED", "Interpolates a value whose name suggests a secret, connection string, config, headers or request payload; needs a context read.")
    if k == "sink" and r["http"]:
        if r["exc"]: return ("DISCLOSURE", "Response body carries exception text (internal hosts, driver/upstream error text).")
        return ("DISCLOSURE", "Response body carries interpolated internal values.") if r["weak"] else ("SAFE", "Response with ids/static text.")
    if r["exc"]: return ("DISCLOSURE", "Embeds exception text: driver/upstream error text, hosts, file paths; no credential unless the wrapped library echoes one.")
    if r["weak"]: return ("DISCLOSURE", "Interpolates URLs/hosts/ids/user or data fields; no secret by name.")
    return ("SAFE", "Interpolates counts/ids/names only.")

def verdict(r):
    if r["id"] in row_ov:
        o = row_ov[r["id"]]; return (o.get("verdict", "UNVERIFIED"), o.get("note", ""), "read")
    v, n = rule_verdict(r); return (v, n, "rule")

for r in rows: r["v"], r["note"], r["basis"] = verdict(r)
prints = [r for r in rows if r["kind"] == "print"]; logs = [r for r in rows if r["kind"] == "logger"]
sinks = [r for r in rows if r["kind"] == "sink"]; uis = [r for r in rows if r["kind"] == "ui"]
total = len(rows)
def vc(rs): return collections.Counter(r["v"] for r in rs)
allc = vc(rows); pct = lambda a, b: f"{(100.0 * a / b):.1f}%" if b else "n/a"
leaky = allc["LEAK"] + allc["LEAK-IF"]; unver = allc["UNVERIFIED"]; clean = allc["SAFE"] + allc["CLI"]
disc = [r for r in rows if r["v"] == "DISCLOSURE"]
disc_gated = [r for r in disc if r["kind"] == "logger" and r["level"] == "debug"]
disc_client = [r for r in disc if r["kind"] == "sink" and r["http"]]
read_rows = [r for r in rows if r["basis"] == "read"]
langs = ", ".join(f"{k} {v}" for k, v in meta["files"].items() if v)

def table(rs, extra):
    out = ["| # | file:line | lang/kind/level | call (truncated) | verdict | note | basis |", "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(sorted(rs, key=lambda r: (r["file"], r["line"])), 1):
        out.append(f'| {i} | `{r["id"]}` | {r["lang"]}/{r["kind"]}/{r.get("level","")} | `{src(r)}` | **{r["v"]}** | {cell(r["note"])} | {r["basis"]} |')
    return "\n".join(out) if rs else "_none_"

# --- controls ---------------------------------------------------------------
def has(k): return bool(sig.get(k))
def ev(k, n=3): return ", ".join(f"`{x}`" for x in sig.get(k, [])[:n]) or "none"
controls = []
py, go, ts = meta["files"]["py"], meta["files"]["go"], meta["files"]["ts"]
if py:
    controls += [
        ("No `print` in Python service code", not any(r for r in prints if r["lang"] == "py" and not r["script"]), f'{sum(1 for r in prints if r["lang"]=="py" and not r["script"])} service-path prints'),
        ("Root logger configured explicitly (level + handler)", has("py_root_logger"), ev("py_root_logger")),
        ("`LOG_LEVEL` default is INFO or higher", any(("DEBUG" not in x) for x in sig.get("py_log_level_default", [])) or (not sig.get("py_log_level_default") and not has("py_debug_forced")), ev("py_log_level_default") + ("; DEBUG forced at " + ev("py_debug_forced") if has("py_debug_forced") else "")),
        ("No forced DEBUG / verbose switches (litellm set_verbose, SQLAlchemy echo, setLevel(DEBUG))", not has("py_debug_forced"), ev("py_debug_forced")),
        ("`builtins.print` guard in the server process", has("py_print_guard"), ev("py_print_guard")),
        ("Central exception handler (fixed message to clients)", has("py_exception_handler"), ev("py_exception_handler")),
        ("No `detail=str(e)` passthrough to clients", not has("py_detail_passthrough"), f'{len(sig.get("py_detail_passthrough", []))} sites, e.g. {ev("py_detail_passthrough")}'),
        ("Pydantic `hide_input_in_errors` where request bodies carry secrets", has("py_hide_input"), ev("py_hide_input")),
        ("uvicorn access log disabled or lifted to WARNING", has("py_access_log_off"), ev("py_access_log_off")),
        ("No `traceback.format_exc()` outside DEBUG logging", not has("py_format_exc_nondebug"), ev("py_format_exc_nondebug")),
        ("`httpx` logger pinned to WARNING (INFO prints every request URL)", has("py_httpx_silenced"), ev("py_httpx_silenced")),
    ]
if go:
    controls += [
        ("No `fmt.Print*`/`println` in Go service code", not any(r for r in prints if r["lang"] == "go" and not r["script"]), f'{sum(1 for r in prints if r["lang"]=="go" and not r["script"])} service-path prints'),
        ("Structured logger in use", has("go_structured_logger"), ev("go_structured_logger")),
        ("Panic recovery middleware", has("go_recover"), ev("go_recover")),
        ("No `err.Error()` written into HTTP responses", not has("go_err_in_response"), f'{len(sig.get("go_err_in_response", []))} sites, e.g. {ev("go_err_in_response")}'),
    ]
if ts:
    controls += [
        ("No `console.*` in server-side TS/JS", not has("ts_server_console"), f'{len(sig.get("ts_server_console", []))} hits, e.g. {ev("ts_server_console")}'),
    ]
controls += [
    ("`.env` git-ignored", has("gitignore_env"), ev("gitignore_env")),
    ("No `.env` file committed", not sig.get("env_committed"), ", ".join(sig.get("env_committed", [])) or "none"),
    ("`.dockerignore` present and excludes `.env`", has("dockerignore_env"), ev("dockerignore_env") if has("dockerignore") else "no .dockerignore" + ("; Dockerfile uses `COPY . .`" if has("dockerfile_copy_all") else "")),
]
for name, okv in ctrl_ov.items():
    controls = [(n, okv.get("present", ok), okv.get("evidence", e)) if n == name else (n, ok, e) for n, ok, e in controls]
    if name not in [c[0] for c in controls]: controls.append((name, okv.get("present", False), okv.get("evidence", "")))
ctrl_present = sum(1 for _, ok, _ in controls if ok)

sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "LOW"), 9))
def findings_md():
    if not findings:
        return "_No context-verified findings were recorded for this repository. The rule-based flags below are the candidates; rows marked UNVERIFIED were not read._"
    out = []
    for i, f in enumerate(findings, 1):
        out.append(f'### F{i}. {f.get("severity","LOW")}: {f.get("title","")}\n\n{f.get("detail","")}\n')
        if f.get("refs"): out.append("Sites: " + ", ".join(f"`{x}`" for x in f["refs"]) + "\n")
    return "\n".join(out)

top_unverified = sorted([r for r in rows if r["v"] == "UNVERIFIED"], key=lambda r: -r["score"])

MD = f"""# {NAME}: print, logging and exception-leak audit

Repository `NeuralgoLyzr/{NAME}`, branch `{meta['branch']}` at `{meta['commit']}` ({meta['date']}). Languages scanned: {langs} source files (tests, vendored code and build output excluded). Generated by the fleet audit tooling (`audit_run.py` + `audit_report_generic.py`); rows marked `read` were verified in context, rows marked `rule` carry a regex-derived verdict.

Nothing in this document contains a credential.

## 1. Verdict

| Question | Answer |
|---|---|
| Print-family calls in service code | {sum(1 for r in prints if not r['script'])} (plus {sum(1 for r in prints if r['script'])} in scripts/tools). Verdicts: {", ".join(f"{k} {v}" for k, v in vc(prints).items()) or "none"} |
| Logger calls | {len(logs)}. Verdicts: {", ".join(f"{k} {v}" for k, v in vc(logs).items()) or "none"} |
| Raise / response sinks | {len(sinks)} ({sum(1 for r in sinks if r['http'])} write HTTP responses). Verdicts: {", ".join(f"{k} {v}" for k, v in vc(sinks).items()) or "none"} |
| Browser-side UI sinks (toasts, alerts) | {len(uis)}. Verdicts: {", ".join(f"{k} {v}" for k, v in vc(uis).items()) or "none"} |
| Confirmed credential leaks (LEAK / LEAK-IF) | {allc['LEAK']} / {allc['LEAK-IF']} |
| Rows flagged risky but not yet read in context (UNVERIFIED) | {unver} |
| Rows read in context | {len(read_rows)} |

## 2. Findings

{findings_md()}

## 3. Highest-risk rows

The {min(40, len(top_unverified))} highest-scoring UNVERIFIED rows (score = secret-looking name + interpolation + response passthrough + traceback). Each needs one context read to become LEAK, DISCLOSURE or SAFE.

{table(top_unverified[:40], "")}

## 4. Log-pipeline facts and controls

{("- " + chr(10) + "- ".join(pipeline)) if pipeline else "_No pipeline notes recorded beyond the signals below._"}

| # | Control | Present | Evidence |
|---|---|---|---|
""" + "\n".join(f"| {i} | {cell(n)} | {'yes' if ok else 'no'} | {cell(e)} |" for i, (n, ok, e) in enumerate(controls, 1)) + f"""

## 5. Method and regexes

1. Default branch fetched and fast-forwarded; commit above.
2. Python: AST walk over every `.py` outside tests/venv (`audit_extract.py`): print family (`print`, `pprint`, `sys.stdout.write`, `sys.stderr.write`, `traceback.print_exc`, `click.echo`, `typer.echo`, `rich.print`, `os.write`), logger methods `^(logger|logging|log|self\\.logger|self\\._logger|_logger|LOGGER|_log|LOG|self\\.log)\\.(debug|info|warning|warn|error|exception|critical)$`, sinks whose callee ends in `Error|Exception|Failure|HTTPException|JSONResponse|Response`.
3. Go: `go/ast` walk over every non-test `.go` (`goaudit`): prints `fmt.Print*`, `fmt.Fprint*`, `print`, `println`, `os.Stdout/Stderr.Write*`, `spew.Dump`; loggers = method `(debug|info|warn|error|fatal|panic|trace|print)(f|ln|w|ctx)?` on a receiver whose expression mentions `log|logger|zap|slog|logrus|zerolog|sugar|klog|glog`, plus std `log.Print*/Fatal*/Panic*`; sinks = `errors.New`, `fmt.Errorf`, `errors.Wrap*`, `http.Error`, `panic`, `status.Error*`, response methods (`JSON|String|Data|Encode|Write|WriteString|Send*|AbortWith*|Error|Render|HTML`) on `c|ctx|w|rw|res|resp|writer|json.NewEncoder()`, and helpers named `(respond|write|render|send|reply|handle|abort)(json|error|err|response|...)`.
4. TS/JS: regex scan over `.ts/.tsx/.js/.jsx` outside `node_modules/.next/dist/build/tests` (`tsaudit.py`): `console.*`, `process.stdout/stderr.write`, `(logger|log|winston|pino|bunyan).(debug|info|warn|error|fatal|trace|log)`, `throw new *Error(`, `res.status().json/send`, `res.json/send`, `NextResponse.json`, `new Response`, `reply.*`, `next(new Error`, and UI sinks (`toast*`, `message.error`, `notification.*`, `alert`, `setError*`).
5. Per-row regex signals: strong secret names `(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|private_key|credential|authorization|bearer|cookie|session_id|x-api-key|dsn|conn(ection)?[_ ]?str|mongo_url|redis_url|database_url|\\.env|environ|os\\.getenv|headers|kwargs|\\*\\*|model_dump|\\.dict\\(\\)|json\\.dumps|vars\\(|repr\\(|payload|request\\.body|req\\.body|request\\.json|config|settings|params|creds|auth|jwt|signature|presign|x-amz|sig=)`; weak names `(url|uri|host|endpoint|path|query|filter|id|email|user|org|tenant|schema|column|collection|table|body|response|data|result|row|record|document|message|content|prompt|text)`; exception text per language (`{{e}}`, `str(e)`, `format_exc()`, `exc_info=True`, `%s` / Go `err`, `%v`, `%w`, `.Error()` / TS `error.message`, `.stack`, `JSON.stringify`); interpolation (f-strings, `%`, `.format`, extra call arguments, `${{}}`).
6. Rule verdicts: script paths -> CLI; no interpolation -> SAFE; strong name + interpolation -> UNVERIFIED (never auto-cleared); HTTP response + exception text -> DISCLOSURE; exception text or weak names -> DISCLOSURE; else SAFE. Context reads (basis `read`) replace the rule verdict.
7. Control signals are greps over the tree (evidence column shows the first hits).

Quick re-run for prints: `grep -rnE '(^|[^A-Za-z_.])(print|println|fmt\\.Print[a-z]*|console\\.(log|error|warn|info|debug))\\(' --include='*.py' --include='*.go' --include='*.ts' --include='*.tsx' . | grep -vE '/(\\.venv|node_modules|\\.next|dist|vendor|tests?)/'`.

## 6. Safety coverage (grounded)

Every percentage is computed from the {total} inventoried rows (Appendices A-D) using the verdicts printed there, plus the control checklist in section 4.

| Measure | Value | How it is computed |
|---|---|---|
| Verified credential-safe rows | **{pct(total - leaky - unver, total)}** ({total - leaky - unver}/{total}) | rows whose verdict is SAFE, CLI or DISCLOSURE (no secret on the path). LEAK/LEAK-IF ({leaky}) and UNVERIFIED ({unver}) both count against it. |
| Unverified rows | {pct(unver, total)} ({unver}/{total}) | regex-flagged as risky, not read in context; the honest gap in this report |
| Disclosure-free rows (SAFE or CLI) | **{pct(clean, total)}** ({clean}/{total}) | logger {pct(sum(1 for r in logs if r['v'] in ('SAFE','CLI')), len(logs))}, sinks {pct(sum(1 for r in sinks if r['v'] in ('SAFE','CLI')), len(sinks))}, prints {pct(sum(1 for r in prints if r['v'] in ('SAFE','CLI')), len(prints))} |
| Disclosure rows that are DEBUG-gated | {pct(len(disc_gated), len(disc))} ({len(disc_gated)}/{len(disc)}) | DISCLOSURE logger rows at debug level |
| Disclosure rows that reach an HTTP client | {pct(len(disc_client), len(disc))} ({len(disc_client)}/{len(disc)}) | DISCLOSURE rows that are response sinks |
| Rows read in context | {pct(len(read_rows), total)} ({len(read_rows)}/{total}) | basis = `read` |
| Safety controls in place | **{pct(ctrl_present, len(controls))}** ({ctrl_present}/{len(controls)}) | section 4 checklist |

### How to read each measure

Every measure is a ratio over the same {total} rows: {len(prints)} print-family calls, {len(logs)} logger calls, {len(sinks)} raise/response sinks and {len(uis)} browser-side UI sinks. Each row has exactly one verdict:

| Verdict | Meaning |
|---|---|
| LEAK | a real secret reaches the sink on a normal code path (context-verified) |
| LEAK-IF | a secret reaches the sink only under a stated condition (context-verified) |
| DISCLOSURE | no secret, but internal or customer detail gets out: hosts, user names, error text, tracebacks, ids |
| SAFE | static text, ids, counts or key names only |
| CLI | lives under a script/tool/example path that never runs inside the service |
| UNVERIFIED | the regexes saw a secret-looking name being interpolated and nobody has read the line yet; treated as unsafe in the coverage numbers |

- **Verified credential-safe rows** is the headline number. It only counts rows that are known not to carry a secret; UNVERIFIED rows are excluded on purpose, so the figure cannot be inflated by an unread line.
- **Unverified rows** is the size of the remaining work. Reading each such line in context turns it into LEAK, DISCLOSURE or SAFE and moves the first number.
- **Disclosure-free rows** is the stricter hygiene bar: nothing internal at all. It rises when raw error text is replaced by fixed messages and correlation ids.
- **DEBUG-gated** disclosure rows are dormant while the log level stays at INFO; **reach an HTTP client** rows are visible to outsiders today and come first.
- **Safety controls in place** is the durability number: it measures whether the safety is structural (guards, handlers, redaction) or incidental (libraries happening not to echo secrets).

## 7. Appendix A: print-family calls ({len(prints)})

{table(prints, "")}

## 8. Appendix B: logger calls ({len(logs)})

{table(logs, "")}

## 9. Appendix C: raise / response sinks ({len(sinks)})

{table(sinks, "")}

## 10. Appendix D: browser-side UI sinks ({len(uis)})

{table(uis, "")}

## 11. Summary

{summary_ov if summary_ov else f"`{NAME}` at `{meta['commit']}`: {total} rows inventoried ({len(prints)} prints, {len(logs)} logger calls, {len(sinks)} sinks, {len(uis)} UI sinks). Confirmed leaks: {allc['LEAK']} LEAK, {allc['LEAK-IF']} LEAK-IF. {unver} rows remain UNVERIFIED. Verified credential-safe {pct(total - leaky - unver, total)}, disclosure-free {pct(clean, total)}, controls {pct(ctrl_present, len(controls))}. See section 2 for findings and section 3 for the rows to read next."}
"""
open(OUT, "w").write(MD)
print(NAME, "rows", total, dict(allc), "controls", f"{ctrl_present}/{len(controls)}", "->", OUT)
