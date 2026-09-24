---
name: log-review
description: Audit a repository for credentials and internal detail leaking through print statements, logger calls, raised errors, HTTP error responses, tracebacks and other sinks, then produce a graded markdown report with grounded coverage percentages. Use when asked to check a service for secrets in logs, review print/log/exception hygiene, or produce a "brutal" log audit like the rag and data-query reports.
---

# log-review

Produce `<repo>-print-audit.md`: every print-family call, logger call and raise/response sink in a repository, each with a verdict, plus ranked findings, the log-pipeline facts that decide severity, and coverage percentages computed from the same rows. The rag and data-query audits (2026-09-23) are the reference for depth and tone.

## Hard rules

- Never print, echo, cat, copy or quote an actual credential, connection string with credentials, token, key or `.env` value, in tool output, in the report, in commits or in chat. Use placeholders such as `mongodb://<user>:<redacted>@<host>/<db>`. When you must inspect a secret-bearing file, read only the key names (`sed -E 's/=.*//'`).
- Probes use fake values only (`FAKEPW_9f8e7d`, `AIzaSyFAKE...`, `AKIAFAKE...`), never real ones, never against production hosts. A probe that needs a host points at `127.0.0.1:9` or `example.invalid`.
- Do not rotate credentials, do not change infrastructure, do not edit the audited repo. The deliverable is the report. Fixes are a separate, explicitly requested task.
- Every claim in the report carries a `file:line`, a probe result, or a library fact you verified. Rows you did not read stay `UNVERIFIED`; never inflate a coverage number by guessing.
- Bash on this machine is zsh: `set -- $var` does not word-split (use `${=var}`); never `cd` in parallel calls (use `git -C`, absolute paths, subshells); there is no `timeout` binary.

## Deliverables

1. `<workspace>/<repo>-print-audit.md` (sections listed under "Report structure").
2. A short chat summary: verdict on prints, on logger calls, on exceptions, the ranked findings with `file:line`, and what was not verified.
3. A memory note if the audit found an open HIGH/MEDIUM item someone will act on later.

## Procedure

### 0. Checkout

```
git -C <repo> fetch origin && git -C <repo> checkout <default> && git -C <repo> pull --ff-only
git -C <repo> rev-parse --short HEAD ; git -C <repo> log -1 --format=%cs
```
Record commit, branch, date. Note any PR merged since a previous audit (`git log --format='%h %s' <old>..HEAD`) and what it touched.

### 1. Inventory (mechanical)

```
S=<scratch dir>; K="$(dirname "$(find . -path '*skills/log-review/scripts/audit_run.py' 2>/dev/null | head -1)")"   # scripts ship in this agent repo at skills/log-review/scripts
python3 $K/audit_run.py <repo_root> <repo_name> $S
```
`audit_run.py` runs the three extractors and writes `<name>_audit.json` (rows + control signals) and `<name>_priority.txt` (top 160 rows by risk score):

- Python: `audit_extract.py`, an `ast` walk over every `.py` outside tests/venv. Print family = `print`, `pprint`, `sys.stdout.write`, `sys.stderr.write`, `traceback.print_exc`, `click.echo`, `typer.echo`, `rich.print`, `os.write`. Logger = `^(logger|logging|log|self\.logger|self\._logger|_logger|LOGGER|_log|LOG|self\.log)\.(debug|info|warning|warn|error|exception|critical)$`. Sinks = callee ending in `Error|Exception|Failure|HTTPException|JSONResponse|Response`. Multi-line calls are captured whole, which a line regex cannot do.
- Go: `goaudit/` (`go/ast`). Prints `fmt.Print*`, `fmt.Fprint*`, `print`, `println`, `os.Stdout/Stderr.Write*`, `spew.Dump`; loggers = level method on a receiver mentioning `log|logger|zap|slog|logrus|zerolog|sugar|klog|glog`, plus std `log.Print*/Fatal*/Panic*`; sinks = `errors.New`, `fmt.Errorf`, `errors.Wrap*`, `http.Error`, `panic`, `status.Error*`, response methods on `c|ctx|w|rw|res|resp|writer|json.NewEncoder()`, helpers named `(respond|write|render|send|reply|handle|abort)(json|error|err|response|...)`.
- TS/JS: `tsaudit.py` (regex with paren balancing). `console.*`, `process.stdout/stderr.write`, `(logger|log|winston|pino|bunyan).(level)`, `throw new *Error(`, `res.status().json/send`, `res.json/send`, `NextResponse.json`, `new Response`, `reply.*`, `next(new Error`, and UI sinks (`toast*`, `message.error`, `notification.*`, `alert`, `setError*`).

Per-row signals: `strong` (secret-looking name), `weak` (url/host/id/data names), `exc` (exception text per language), `interp` (interpolation present), `script` (scripts/tools/examples path), `http` (response sink). Quick manual re-run for prints only:
```
grep -rnE '(^|[^A-Za-z_.])(print|println|fmt\.Print[a-z]*|console\.(log|error|warn|info|debug))\(' --include='*.py' --include='*.go' --include='*.ts' --include='*.tsx' . | grep -vE '/(\.venv|node_modules|\.next|dist|vendor|tests?)/'
```
Also grep for sinks the AST pass cannot see: `traceback\.print_exc|print_exception|sys\.(stderr|stdout)\.write|click\.echo|typer\.echo|rich\.print|pprint\(|os\.write\(`.

### 2. Establish the log-pipeline facts (these decide every severity)

Python: root logger config (`logging.basicConfig`, `dictConfig`, `getLogger().setLevel/addHandler`) and the `LOG_LEVEL` default; any forced DEBUG (`setLevel(logging.DEBUG)`, litellm `set_verbose`/`_turn_on_debug`, SQLAlchemy `echo=True`); a `builtins.print` guard and its bypass env var; central `exception_handler`; `detail=str(e)` count; pydantic `hide_input_in_errors`; uvicorn access log (`--no-access-log`, `access_log=False`, `uvicorn.access` level); `httpx` logger level (httpx logs every request URL at INFO; litellm sets it to WARNING at import, which is a fragile side effect); Celery worker `--loglevel` and whether the root logger is hijacked; `traceback.format_exc()` outside DEBUG; `.dockerignore` and `COPY . .`; `.env` committed or not; where `LOG_LEVEL` is set in CI/Dockerfiles/env files (keys only).
Go: recovery middleware, structured logger, `err.Error()` written into responses.
TS: `console.*` in server code (`app/api`, `pages/api`, `server`).
Also: which HTTP clients are used (httpx, requests, aiohttp; their error text includes the full URL with query string, see facts) and whether any URL can carry a secret (presigned URLs, `?key=`).

### 3. Read the priority rows in context

Open `<name>_priority.txt`. For each row read the surrounding function and answer: what does the interpolated value actually hold (trace the variable to its source: request body, env, DB document, driver object); at what level does it emit; is it inside a guard; where does a raised error go (grep the exception class to its `detail=` or handler); does a traceback (`exc_info=True`, `logger.exception`, `format_exc()`) carry an exception whose text embeds a URL or body. Record the verdict and a one-sentence note keyed by `file:line`. Read the callers of every custom error class that embeds `{e}` or a response body. For prints, decide CLI (`scripts/`, `__main__`, demo helpers) versus service path. Also read the config/settings module, the auth module, and every place a request body with credentials is parsed.

### 4. Probe libraries with fake values (only when the code path exists)

`skills/log-review/probes/` (relative to this agent repo root):
- `litellm_gemini_key_probe.py`, `litellm_gemini_key_probe_paths.py`: does `str(e)`/`repr(e)`/cause chain/DEBUG log contain the key on auth-error, unknown-model and timeout paths.
- `http_client_url_in_exception_probe.py`, `aiohttp_status_error_probe.py`: does the client's error text include the URL query string.
- `driver_error_text_probe.py`: SQLAlchemy `make_url` with `@ : / ?` in the password; psycopg connect and bad-conninfo text; oracledb connect text.
- `mongo_public_attribute_graph_probe.py`: BFS over underscore-free attributes of a client handle looking for the password (for exec sandboxes).
- `boto3_before_send_hook_probe.py`: what a `before-send` event handler can read from a signed request.
Run them with the repo's own venv (`uv sync --frozen --python 3.12`; private git deps need `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=url.https://github.com/.insteadOf GIT_CONFIG_VALUE_0=ssh://git@github.com/`). Print booleans, never values.

### 5. Write the overrides and render

Create `<name>_overrides.json` (schema below) from step 3 and 4, then:
```
python3 $K/audit_report_generic.py <repo_name> $S <workspace>/<repo_name>-print-audit.md
```
For a deep, hand-verified report (every row judged, narrative findings, custom control checklist) copy `examples/data_query_report_handverified.py` or `examples/rag_report_handverified.py` and edit its `OVERRIDES` table and narrative; those generators print the coverage section from the same verdict functions that fill the tables. Re-render after every edit; never hand-edit the markdown.

Overrides schema:
```json
{"rows": {"file:line": {"verdict": "LEAK|LEAK-IF|DISCLOSURE|SAFE|CLI", "note": "one sentence, cites what the value holds"}},
 "findings": [{"severity": "HIGH|MEDIUM|LOW|INFO", "title": "...", "detail": "...", "refs": ["file:line"]}],
 "controls": {"<control name>": {"present": true, "evidence": "file:line"}},
 "pipeline": ["fact about the logging pipeline", "..."],
 "summary": "closing summary"}
```

### 6. Check the output

Scan the report for secret-looking strings before delivering: `grep -nE 'AIza[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|mongodb(\+srv)?://[^<*]+:[^<*]+@|X-Amz-Signature=[0-9a-f]{10,}'` must return nothing except the documented fake values. Check table rows render (`\|` inside code spans is fine).

## Verdict vocabulary and rules

| Verdict | Meaning |
|---|---|
| LEAK | a real secret reaches the sink on a normal code path (context-verified) |
| LEAK-IF | reaches the sink only under a stated condition: DEBUG level, a character in a password, a URI written with userinfo |
| DISCLOSURE | no secret; internal hosts, user names, internal URLs, error bodies, tracebacks, customer data or PII get out |
| SAFE | static text, ids, counts, key names, redacted values |
| CLI | operator script or `__main__`/demo block that never runs in the service process |
| UNVERIFIED | regex saw a secret-looking name being interpolated; nobody read the line; counts as unsafe in coverage |

Rule verdicts (used only where no context read exists): script path -> CLI; no interpolation -> SAFE; strong name + interpolation -> UNVERIFIED; HTTP response + exception text -> DISCLOSURE; exception text or weak names -> DISCLOSURE; else SAFE. A context read always replaces the rule verdict and is marked `basis = read`.

What makes a row LEAK rather than DISCLOSURE: the value is a password, token, API key, private key, presigned URL, session token, or a config/connection object that embeds one. Presigned URLs and OAuth codes are credentials with a TTL; still LEAK, note the TTL. Hostnames, user names, ids, emails (PII), column names and query text are DISCLOSURE.

## Verified library facts (reuse, cite the version)

| Fact | Verified |
|---|---|
| LiteLLM 1.91.5 masks `key=` in Gemini URLs: fake key absent from `str(e)`, `repr(e)`, cause chain and 98 DEBUG lines on auth-error, unknown-model and timeout paths; its DEBUG curl dump masks headers | probe, 2026-09-23 |
| LiteLLM sets the `httpx` logger to WARNING at import (`litellm/_logging.py`); without it httpx logs `HTTP Request: <method> <full URL>` at INFO | read + probe |
| `httpx.HTTPStatusError`, `requests.HTTPError`, `requests.ConnectionError` and `aiohttp.ClientResponseError` texts include the full URL with query string; httpx/aiohttp connect-level errors do not | probe (aiohttp 3.14.3) |
| `logger.exception` / `exc_info=True` prints the traceback, whose last line is the exception text: a redacted message does not protect a presigned URL raised by `raise_for_status()` | rag `extract/endpoints.py:388` |
| pymongo 4.8 and 4.18 `MongoClient`/`Database` repr and motor 3.7 delegate exclude username/password; no underscore-free attribute path reaches the credential (53 nodes, depth 5) | probe |
| pymongo `InvalidURI` and `ServerSelectionTimeoutError` texts carry hosts, not passwords; pymongo redacts auth commands in its DEBUG command logging | probe + docs |
| psycopg 3.2/3.3 connect and bad-conninfo errors, oracledb `DPY-6005`, pyodbc/cloudrift `SQLConnectionError("... at <server>: ...")` carry host/user/error code, never the password | probe + read |
| SQLAlchemy `make_url`: a password containing `@` is split at the first `@` and the tail becomes the host name, which libpq then echoes (`could not translate host name`); `URL` repr masks the password; `ArgumentError` on an unparsable URL echoes the whole URL | probe (2.0.31/2.0.38) |
| boto3 `before-send` event handlers (registered through a public path) see `Authorization` (access key id) and `X-Amz-Security-Token` (session token verbatim); the secret key never appears | probe (boto3 1.40) |
| Celery 5.6.3 / kombu 5.6.2 mask the broker password in the banner, `as_uri()` and `humanize()`; the host stays; `celery -q/--quiet` suppresses the banner; `--loglevel=info` puts a handler at INFO on the root logger | probe + read |
| uvicorn's access log records path and query string; `x-api-key` travels in a header and is not logged | read |
| pydantic v2 embeds `input_value` in `ValidationError` text unless `hide_input_in_errors=True`; a model-level validator error carries the whole input dict | read |
| Python tracebacks never include local variables; `traceback.format_exc()` carries file paths and the exception chain text only | fact |

## Report structure

1. Verdict table (prints, logger calls, exceptions to clients, non-log sinks, sandbox if any).
2. Ranked findings F1..Fn with severity, every site as `file:line`, the mechanism, the probe or read that proves it, and a fix shape.
3. Log-pipeline facts that decide severity (table: fact, where, consequence).
4. Method and regexes (checkout commit, extractors, regexes verbatim, probes run, counts table, verdict totals).
5. Print inventory, then Appendix A logger calls, B exception-text rows, C HTTP passthroughs, D raised errors, E non-log sinks: every row with `#`, `file:line`, level/call, truncated call, verdict, note, basis (`read`/`rule`).
6. Recommendations, ordered.
7. Safety coverage (grounded), with the "How to read each measure" block.
8. Summary.

### Coverage measures (all computed from the same rows)

- Credential-safe rows: verdict not LEAK/LEAK-IF (and not UNVERIFIED in the generic report). The headline.
- Unverified rows: the honest gap.
- Disclosure-free rows: SAFE or CLI, split by logger / sinks / prints.
- Disclosure rows DEBUG-gated vs live at INFO+ or in HTTP responses (response rows come first).
- Rows read in context.
- Safety controls in place: checklist with file:line evidence. Python controls: no print in service code; root logger configured; `LOG_LEVEL` default INFO+; no forced DEBUG; `builtins.print` guard; central exception handler; no `detail=str(e)`; `hide_input_in_errors`; access log off; no `format_exc()` outside DEBUG; `httpx` logger pinned. Go: no `fmt.Print*`; structured logger; recovery middleware; no `err.Error()` in responses. TS: no server-side `console.*`. All: `.env` git-ignored; none committed; `.dockerignore` excludes `.env`.
Always include the explanation block: a high credential-safe share with a low controls share means the service is safe because libraries happen not to echo secrets, not because the code strips them.

## Severity guidance

HIGH: a secret stored or returned to a principal who does not own it (rag: owner API key echoed in `LiveSourceResponse` to shared readers), or logged at default level. MEDIUM: presigned URLs or other TTL credentials in logs; raw exception text/tracebacks to clients; error text or handles sent to an LLM provider; exec sandboxes with `print` and no stdout guard. MEDIUM (DEBUG-gated): config dumps or URIs at DEBUG when `LOG_LEVEL` is one env var away. LOW: upstream error bodies, PII in logs, access-log query strings with short-lived tokens, missing `.dockerignore`.

## Gotchas

- `rag_audit.py`-style extractors must skip `.venv`, `node_modules`, `tests`; the runner also skips `vendor`, `.next`, `dist`, `build`.
- Line numbers shift between commits; key overrides by `file:line` of the audited commit and re-map by source text when re-auditing a moved master.
- Go extractor runs via `go run -C <skill>/scripts/goaudit . <root> <out.json>` (Go 1.20+).
- Markdown tables: escape `|` in snippets (the generators do); `<placeholder>` inside reportlab `XPreformatted` must be HTML-escaped.
- Reading a PDF report back page by page is the only reliable layout check for generated PDFs.
