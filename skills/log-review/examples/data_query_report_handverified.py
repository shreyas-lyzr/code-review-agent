"""Render data-query-print-audit.md from dq_audit.json + dq_subsets.json.
Verdicts: LEAK / LEAK-IF / DISCLOSURE / SAFE / CLI (see rag report for definitions)."""
import json, os, re, collections

S = os.environ["S"]; OUT = os.environ["OUT"]
d = json.load(open(f"{S}/dq_audit.json"))
def key(r): return f'{r["file"]}:{r["line"]}'
def src(r, n=160): return " ".join(r["src"].split()).replace("|", "\\|")[:n]
def cell(s): return s.replace("|", "\\|")

TRACE = ("DISCLOSURE", "DEBUG only. Full traceback of the failed request: service file paths plus the exception chain (cloudrift/driver text, the failing SQL). No credential in that chain (see section 3).")
ERRTXT = ("DISCLOSURE", "ERROR. str(e) of the failure: cloudrift SQLConnectionError text (server host + driver message), pydantic location/reason (inputs hidden), or lyzr-agent's error body. No credential on any verified driver path; see F2 for the one make_url edge.")
LOG_VERDICTS = {
    "api/endpoints.py:88": ("DISCLOSURE", "ERROR. he.detail: either the connector's error text or lyzr-agent's full error body (utils.py:72-75)."),
    "api/endpoints.py:89": TRACE, "api/endpoints.py:92": ERRTXT, "api/endpoints.py:93": TRACE,
    "api/endpoints.py:110": ("SAFE", "Static."), "api/endpoints.py:113": ("SAFE", "Static."), "api/endpoints.py:117": ("SAFE", "Static."), "api/endpoints.py:119": ("SAFE", "Static."), "api/endpoints.py:128": ("SAFE", "Static."),
    "api/endpoints.py:131": ("DISCLOSURE", "ERROR. he.detail (see :88)."), "api/endpoints.py:132": TRACE, "api/endpoints.py:135": ERRTXT, "api/endpoints.py:136": TRACE,
    "api/endpoints.py:157": ("DISCLOSURE", "ERROR. he.detail (see :88)."), "api/endpoints.py:158": TRACE, "api/endpoints.py:161": ERRTXT, "api/endpoints.py:162": TRACE,
    "api/endpoints.py:178": ("DISCLOSURE", "ERROR. he.detail (see :88)."), "api/endpoints.py:179": TRACE, "api/endpoints.py:182": ERRTXT, "api/endpoints.py:183": TRACE,
    "api/endpoints.py:194": ("SAFE", "Provider id only."), "api/endpoints.py:195": ("SAFE", "DEBUG. Key NAMES of the credentials dict, never values."),
    "api/endpoints.py:198": ("SAFE", "Class name."), "api/endpoints.py:201": ("SAFE", "Static."), "api/endpoints.py:204": ("SAFE", "Provider id."),
    "api/endpoints.py:207": ("DISCLOSURE", "ERROR. Driver/cloudrift error text for a failed verify: customer DB host and user name (psycopg, pyodbc, oracledb, pymongo texts name the user, never the password)."),
    "api/endpoints.py:208": TRACE,
    "api/logging_config.py:49": ("SAFE", "Level name."),
    "api/settings.py:91": ("SAFE", "Static."),
    "api/settings.py:93": ("DISCLOSURE", "ERROR. cloudrift CacheConnectionError text: Redis host:port and the redis-py error; the password is not echoed."),
    "api/settings.py:114": ("SAFE", "Static."),
    "api/settings.py:117": ("DISCLOSURE", "WARNING. azure-identity error text (credential chain names, no secret)."),
    "api/settings.py:194": ("SAFE", "Database name."), "api/settings.py:196": ("SAFE", "Database name."),
    "api/settings.py:200": ("LEAK-IF", "WARNING. psycopg text for the service's own Postgres (host, user). If DB_PASSWORD contains '@', make_url (:170) mis-parses and the part of the password after the '@' becomes the host name, which libpq then prints in 'could not translate host name' (verified with SQLAlchemy 2.0.38)."),
    "api/utils.py:167": ("SAFE", "Object type + json error."),
    "api/utils.py:172": ("SAFE", "DEBUG. Paths and types of result cells, values deliberately excluded (:63-65)."),
    "api/utils.py:253": ("DISCLOSURE", "WARNING. pandas/TypeError text; can quote a customer result cell value."),
    "api/utils.py:276": ("DISCLOSURE", "DEBUG. Customer column name + pandas error text."),
    "api/utils.py:280": ("DISCLOSURE", "WARNING. Customer column name + error text (may quote a cell value)."),
    "api/utils.py:285": ("DISCLOSURE", "WARNING. Customer column name + error text."),
    "api/utils.py:291": ("DISCLOSURE", "WARNING. pandas error text."),
    "api/utils.py:296": ("DISCLOSURE", "WARNING. Error text."),
    "api/utils.py:307": ("DISCLOSURE", "DEBUG. Column name, dtype, value type, error text."),
    "api/utils.py:317": ("DISCLOSURE", "WARNING. Column name + str() error text (commit 4b4ed0c raised this from debug)."),
    "api/utils.py:323": ("DISCLOSURE", "ERROR. Error text."),
    "app.py:21": ("SAFE", "Static."), "app.py:26": ("SAFE", "Static."),
    "app.py:74": ("SAFE", "ERROR. 422 errors reduced to loc/msg/type by _redact_validation_errors; the offending value (which can be a credential) is dropped."),
    "lyzr_data_query/db_connectors/azuresql.py:86": ("DISCLOSURE", "WARNING. pyodbc error text on a transient failure: server name, user name, SQL Server error code. No password (pyodbc never echoes the DSN)."),
    "lyzr_data_query/db_connectors/azuresql.py:95": ("DISCLOSURE", "ERROR. Same text on the final failure."),
    "lyzr_data_query/db_connectors/mongodb.py:116": ("DISCLOSURE", "DEBUG. Customer collection field names."),
    "lyzr_data_query/db_connectors/postgres.py:94": ("SAFE", "Static."),
    "lyzr_data_query/db_connectors/redshift.py:87": ("SAFE", "Static."), "lyzr_data_query/db_connectors/redshift.py:94": ("SAFE", "Static."),
    "lyzr_data_query/db_connectors/utils.py:132": ("SAFE", "Function name."),
    "lyzr_data_query/db_connectors/utils.py:144": ("DISCLOSURE", "WARNING. Error text of the failed SQL/exec iteration: driver message (can include the SQL statement and quoted data values), or the exec'd code's exception."),
}
def log_verdict(r):
    k = key(r)
    if k in LOG_VERDICTS: return LOG_VERDICTS[k] + ("read",)
    if k.startswith("scripts/"):
        if "exception" in r["src"]: return ("CLI", "Operator migration script; SQLAlchemy error text includes the statement and its parameters (row data), not the URL (URL.create masks the password in repr).", "read")
        return ("CLI", "Operator migration script; database/table names and counts.", "read")
    return ("SAFE", "Static text or ids.", "rule")

DRIVER_TXT = "Wraps the driver/cloudrift error text. Verified texts carry host, port, user and server error codes, never the password (psycopg 3.2/3.3 connection and bad-conninfo errors, oracledb DPY errors, pyodbc, pymongo InvalidURI and server-selection errors)."
SINK_VERDICTS = {
    "api/endpoints.py:94": ("DISCLOSURE", "500 body = str(e): RuntimeError('Failed to create database connector: ...') chain or any other internal error text, to the API caller."),
    "api/endpoints.py:137": ("DISCLOSURE", "500 body = str(e), as :94."),
    "api/endpoints.py:163": ("DISCLOSURE", "500 body = str(e), as :94."),
    "api/endpoints.py:184": ("DISCLOSURE", "500 body = str(e), as :94."),
    "api/endpoints.py:209": ("DISCLOSURE", "400 body with the driver/cloudrift error text (customer DB host/user; no password)."),
    "lyzr_data_query/db_connectors/utils.py:37": ("DISCLOSURE", "Wraps every connector failure (pydantic reason without input, cloudrift text) and reaches the caller through endpoints.py:94/137/163/184."),
    "lyzr_data_query/db_connectors/utils.py:72": ("DISCLOSURE", "Forwards lyzr-agent's error body verbatim to the caller."),
    "lyzr_data_query/db_connectors/file_upload.py:44": ("LEAK-IF", DRIVER_TXT + " Edge: the service's own connection string is parsed with make_url (:51); a DB_PASSWORD containing '@' turns its tail into the host name, which libpq echoes."),
    "lyzr_data_query/db_connectors/file_upload.py:141": ("DISCLOSURE", DRIVER_TXT),
    "lyzr_data_query/db_connectors/file_upload.py:144": ("DISCLOSURE", "Wraps any other run_sql error (pandas, SQL text)."),
    "lyzr_data_query/db_connectors/mongodb.py:54": ("DISCLOSURE", "pymongo error text: hosts, options, auth failure code; the password is not echoed (verified on pymongo 4.8 and 4.18)."),
    "lyzr_data_query/db_connectors/db_models.py:73": ("SAFE", "cryptography's PEM error text; does not echo the certificate."),
    "lyzr_data_query/restricted_exec.py:174": ("SAFE", "SyntaxError text quotes a line of the model-generated code."),
    "api/settings.py:257": ("SAFE", "Names the REDIS_AUTH mode value (a mode name, not a secret)."),
    "api/settings.py:263": ("SAFE", "Provider name."),
    "api/settings.py:90": ("SAFE", "Static."),
}
def sink_verdict(r):
    k = key(r)
    if k in SINK_VERDICTS: return SINK_VERDICTS[k] + ("read",)
    s = r["src"]
    if re.search(r"\{(e|exc|error|retry_error)\}|str\(e\)", s):
        return ("DISCLOSURE", DRIVER_TXT, "rule")
    if "response.text()" in s: return ("DISCLOSURE", "Upstream body forwarded.", "read")
    return ("SAFE", "Static text or ids.", "rule")

def table(rows, fn, extra_label, extra_key):
    out = [f"| # | file:line | {extra_label} | call (truncated) | verdict | note | basis |", "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(sorted(rows, key=lambda r: (r["file"], r["line"])), 1):
        v, note, basis = fn(r)
        out.append(f"| {i} | `{key(r)}` | {r.get(extra_key, '')} | `{src(r)}` | **{v}** | {cell(note)} | {basis} |")
    return "\n".join(out)

logs, sinks = d["logger"], d["sinks"]
lc = collections.Counter(log_verdict(r)[0] for r in logs); sc = collections.Counter(sink_verdict(r)[0] for r in sinks)
lvl = collections.Counter(l["level"] for l in logs); sinkc = collections.Counter(s["call"] for s in sinks)
def fmt(c): return ", ".join(f"{k} {v}" for k, v in sorted(c.items(), key=lambda kv: -kv[1]))

MD = f"""# data-query: print, logging and exception-leak audit

Repository `NeuralgoLyzr/data-query`, branch `master` at `3dc62c4` (2026-09-23, includes PR #115 "logging hygiene"). Scope: every `.py` outside `.venv/` and `tests/` ({d['files']} files, about 5,800 lines, all read). Method and regexes in section 4; every logger call and every raise/response sink is listed with a verdict in the appendices.

This service is the highest-value credential surface in the fleet: every request body carries a live third-party database credential (Postgres/Redshift/MSSQL/Azure SQL/Oracle passwords, Databricks tokens, BigQuery service-account private keys, AWS access keys, Mongo passwords), and `/analysis_response` executes model-generated Python in-process with open handles to that database.

Nothing in this document contains a credential. Probes used fake values only.

## 1. Verdict

| Question | Answer |
|---|---|
| Does any `print` leak a credential? | There are no `print` calls left. PR #115 (`1d3ea07`, 2026-09-23) replaced the last 14 with logger calls. Grep and AST agree: 0 print-family calls (`print`, `pprint`, `sys.stdout.write`, `traceback.print_exc`, ...). |
| Does any logger call leak a credential? | No logger call prints a credential value on a verified path. What the logs do carry: customer DB hosts and user names, customer column/collection names, sometimes a quoted result-cell value, lyzr-agent error bodies, and DEBUG-gated full tracebacks. One conditional edge: the service's own Postgres password fragment if `DB_PASSWORD` contains `@` (F2). |
| Can an exception leak an API key or DB credential to a client? | Not on a verified path, but every endpoint returns raw internal exception text (`detail=str(e)`), so the protection rests entirely on the drivers never echoing passwords (verified for psycopg, oracledb, pyodbc/cloudrift, pymongo, SQLAlchemy `URL.repr`) and on pydantic `hide_input_in_errors` being set on all 11 credential models (verified). The same `@`-in-password edge applies (F2). |
| Does anything else move credentials or data out of the service? | Yes: DB error text and Python tracebacks are appended to the LLM conversation and posted to lyzr-agent, so they reach the LLM provider (F3). The NoSQL system prompt embeds `repr()` of the live Mongo handle, which names the customer's hosts and connection options (password excluded, verified). |
| Can model-generated code steal the credentials it runs with? | Mongo: no. A search over every public attribute reachable from the `db` handle (depth 5, pymongo 4.8 and the motor 3.7 delegate) never reaches the password; the underscore ban in `restricted_exec.py` is what stops it. DynamoDB: partially. Generated code can register a `before-send` hook on the public `dynamodb.meta.client.meta.events` and read the signed request: the access key id and the session token are visible, the secret key is not (verified with boto3). Generated code can also `print`, and there is no stdout guard, so anything it prints lands in the container log (F1). |

## 2. Ranked findings

### F1. MEDIUM: model-generated code runs with live handles, can `print` to the container log, and can read AWS key id + session token

- `lyzr_data_query/service.py:255-264` `exec()`s the model's code with `db` (motor Database) or `dynamodb` (boto3 resource) in scope. `restricted_exec.py` screens the AST (no underscore attributes, no dunder names, import allowlist, no `getattr`/`vars`/`eval`) and allowlists builtins, including `print` (`restricted_exec.py:98`).
- `NoSQL.clean_code` (`service.py:277-281`) drops only lines that *start* with `print(`; `x = 1; print(x)`, a `print` inside a comprehension, or `print` behind a semicolon survive. The service has no stdout guard, so whatever the model (or a prompt-injected user) prints goes to the container log at no log level: query results, customer rows, or anything reachable in scope.
- What is reachable in scope (fake-value probes, `dq_probe_graph.py`, `dq_probe_boto.py`):
  - Mongo: **no** public-attribute path to the password. BFS over 53 reachable nodes at depth 5 on pymongo 4.8.0; motor 3.7.0 exposes `.delegate` (public) but the pymongo `MongoClient` repr and `ClientOptions` exclude username/password; the credential object lives only behind underscore attributes, which the AST screen rejects.
  - DynamoDB: `dynamodb.meta.client.meta.events.register("before-send.dynamodb.*", handler)` is all public names. The handler receives the signed request: `Authorization` contains the **access key id** (`Credential=AKIA.../...`) and `X-Amz-Security-Token` contains the **session token verbatim** (boto3 1.40 probe). The secret key never appears (only its HMAC signature). Alone, key id + session token cannot sign new requests, so this is disclosure of identifiers rather than a usable credential; replaying the captured signed request adds nothing an attacker cannot already do through the analysis code itself.
- Who is the attacker: `/analysis_response` is called by the agent runtime on behalf of whoever chats with the agent, while the credentials belong to the agent builder. A prompt-injected `messages`, `documents` or `examples` entry steers the generated code.

Fix shape: strip `print` from the allowlisted builtins (or bind it to a logger at DEBUG with a size cap); do not expose the raw boto3 resource, expose a thin wrapper over `Table` operations; keep the underscore ban, it is doing real work.

### F2. MEDIUM: every endpoint returns raw internal exception text, and one parse edge can put the service's own DB password fragment into it

- `api/endpoints.py:94, 137, 163, 184` return `detail=str(e)` as a 500; `:209-212` returns the connector error text as a 400. `lyzr_data_query/db_connectors/utils.py:37` wraps every connector failure into `RuntimeError("Failed to create database connector: ...")`, so the driver text always reaches the caller. The same text is logged at ERROR (`endpoints.py:92, 135, 161, 182, 207`) and the full traceback at DEBUG.
- What that text can contain (verified with fake values, `dq_probe_drivers.py`): psycopg connection failure (`connection to server at "host", port N failed: ...`) and bad-conninfo errors, oracledb `DPY-6005`, cloudrift `SQLConnectionError("Failed to connect to MS SQL / Azure SQL at <server>: <pyodbc text>")` (`cloudrift/sql/mssql.py:264-266`), pymongo `InvalidURI`/`ServerSelectionTimeoutError`: hosts, ports, user names, server error codes. **No password in any of them.**
- The edge: `file_upload.py:51` and `settings.py:170` parse the service's own `user:password@host:port/db` string with SQLAlchemy `make_url`. A password containing `@` is split at the first `@`, and the remainder plus `@host` becomes the host name (probe: password `a@bFAKE...` gave `host='bFAKE...@host'`). libpq then reports `could not translate host name "<password tail>@host"`, which lands in the 500 body (`file_upload.py:44` -> `utils.py:37` -> `endpoints.py:94`) and in the ERROR log and the startup WARNING (`settings.py:200`). Only the service's `DB_PASSWORD` is affected (customer Postgres credentials are passed as discrete fields), and only when it contains `@`.
- Pydantic: all 11 credential models set `hide_input_in_errors=True` (`db_models.py:87` and each `model_config`), and the 422 handler in `app.py:56-78` keeps loc/msg/type only. Verified by reading; this is what keeps a malformed request body from echoing the whole credentials dict.

Fix shape: one exception handler that returns a fixed message plus a correlation id and logs the detail server-side; build the service connection from discrete env vars instead of a `user:pass@host` string (the fields already exist: `DB_USERNAME`, `DB_PASSWORD`, `POSTGRES_WRITE_STRING`, `POSTGRES_PORT`, `POSTGRES_DB`).

### F3. MEDIUM: DB error text, tracebacks and the live Mongo handle's repr are sent to the LLM provider

- `lyzr_data_query/db_connectors/utils.py:143-150`: on a failed SQL or exec iteration the message list gets `"Your response resulted in the following error:\\n" + traceback.format_exc()`, and the whole list is posted to lyzr-agent (`utils.py:59-70`) and from there to the model provider. The traceback carries the service's file paths, the failing SQL statement, the driver error (which can quote data values, e.g. `invalid input syntax for type integer: "..."`), and for NoSQL the exec'd code's exception.
- `service.py:169-172` formats `make_locals_dict()` into the NoSQL system prompt; for Mongo that dict contains the live motor Database object, so the prompt carries `AsyncIOMotorDatabase(Database(MongoClient(host=['<customer host>:27017'], ..., <options>)))`. Verified on motor 3.7.0 / pymongo 4.18.0 that the password is not in that repr; the hosts and options are.

Fix shape: send the model a trimmed error (exception type + first line, no traceback) and a string description of the environment instead of `repr(db)`.

### F4. LOW: upstream error bodies and internal text at ERROR

- `utils.py:72-75` raises `HTTPException(detail="Error contacting agent studio: " + response.text())`, forwarding lyzr-agent's body to the caller; `endpoints.py:88/131/157/178` log that body at ERROR.
- `azuresql.py:86, 95` log the pyodbc text (server, user name, SQL Server error code) at WARNING/ERROR.
- `settings.py:93, 117, 200` log Redis / azure-identity / psycopg text for the service's own dependencies (hosts, user names).
- `api/utils.py:253-323` log customer column names and pandas error text (which can quote a result cell) at WARNING/DEBUG; `mongodb.py:116` logs customer field names at DEBUG.

### F5. LOW: build and CI hygiene

- No `.dockerignore`, and `Dockerfile:67` runs `COPY . .`. `.env` is git-ignored, but a developer's local `.env` would be baked into any locally built image.
- `.github/workflows/build-deploy.yml:28` pipes the ACR password into `docker login` (`--password-stdin` pattern, masked by Actions). Standard; listed for completeness.
- cloudrift builds the MSSQL/Azure SQL ODBC string as `PWD=<raw>` without brace quoting (`cloudrift/sql/mssql.py:217`); a password containing `;` is mis-parsed. Not a leak (the error text names only the server), but a correctness edge. cloudrift's `_url.py:23` raises `ValueError(f"Could not parse host from SQL URL: {{url!r}}")` with the full URL, password included; data-query does not call `from_url`, so it is unreachable here.

### Verified safe by design

- `app.py:56-78` 422 redaction; `db_models.py:87` `hide_input_in_errors` on every credential model.
- `endpoints.py:195` logs credential key names only; `api/utils.py:44-67` logs paths/types of result cells, never values.
- `api/logging_config.py:41` sets `uvicorn.access` to WARNING, so no request lines (path + query string) are logged at all.
- `api/auth.py` never logs; the presented key is hashed for the Redis lookup.
- SQLAlchemy `URL` objects mask the password in `repr` (probe), and `scripts/migrate_mysql_to_postgres.py` builds its engines with `URL.create`.

## 3. Log-pipeline facts that decide severity

| Fact | Where | Consequence |
|---|---|---|
| Root logger at `LOG_LEVEL` (default INFO) with a stdout handler; existing handlers removed | `api/logging_config.py:26-37`, called first thing in `app.py:15` | every library INFO line is emitted |
| `uvicorn.access` at WARNING; `azure*` at WARNING | `api/logging_config.py:40-47` | no access-log lines; Azure SDK request logging silenced |
| `LOG_LEVEL` not set in `.env.example`, CI workflows or the Dockerfile | checked | DEBUG-only rows (all 9 tracebacks) are latent until an operator sets it |
| No stdout guard, no `print` in the code base | `app.py`, extractor result | the only stdout writer is model-generated code (F1) |
| HTTP client is aiohttp (lyzr-agent callback); no httpx, no LiteLLM | `utils.py:65` | no INFO-level request-URL logging from an HTTP client |
| Drivers: psycopg 3.2.6, oracledb 2.5.0, pyodbc 5.1.0 via aioodbc, databricks-sql 4.5.0, google-cloud-bigquery 3.30, boto3 1.42, motor 3.7 / pymongo 4.18, all through cloudrift 0.2.9 `from_credentials`/`from_token` | `uv.lock`, connectors | error texts verified or read: none echo a password or token |

## 4. Method and regexes

1. `git clone` + `git checkout master` -> `3dc62c4`; venv built with `uv sync --frozen --python 3.12` for exact-version probes.
2. AST walk (`audit_extract.py`) over every `.py` outside `.venv/` and `tests/`: each `ast.Call` whose callee is in the print family (`print`, `pprint`, `sys.stdout.write`, `sys.stderr.write`, `traceback.print_exc`, `click.echo`, `typer.echo`, `rich.print`, `os.write`), a logger method matching `^(logger|logging|log|self\\.logger|self\\._logger|_logger|LOGGER|_log|LOG|self\\.log)\\.(debug|info|warning|warn|error|exception|critical)$`, or a raise/response sink whose name ends in `Error`, `Exception`, `Failure`, `HTTPException`, `JSONResponse`, `Response`. Recorded with file, line and the exact multi-line source segment.
3. Subsets (`audit_subsets.py`): sensitive-name regex `(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|authorization|bearer|\\bauth\\b|\\buri\\b|\\burl\\b|dsn|connection[_ ]?str|conn_str|mongo|redis|milvus|qdrant|neo4j|arango|zilliz|presign|signature|x-amz|cookie|private_key|client_secret|access_key|refresh_token|config\\b|settings\\b|headers?\\b|payload|body\\b|\\.env\\b|environ|conn\\b|engine|database_url|db_url|host)`; exception-text regex `(\\{{(e|err|exc|ex|error|exception|ex_|e2|inner)(\\b|[\\.\\)\\[:!}}])|str\\((e|err|exc|ex|error|exception)\\)|repr\\((e|err|exc|ex|error)\\)|format_exc\\(\\)|logger\\.exception|exc_info=True|%s|\\{{[a-z_]*err[a-z_]*\\}}|\\{{[a-z_]*detail[a-z_]*\\}}|\\{{[a-z_]*msg[a-z_]*\\}}|\\{{[a-z_]*reason[a-z_]*\\}})`.
4. Every non-test file was read in full (endpoints, utils, settings, auth, service, restricted_exec, connectors, models, logging config, guards), plus the cloudrift SQL backends the connectors delegate to.
5. Probes with fake values in the repo's own venv: (a) BFS over public attributes of the Mongo handle for the password (pymongo 4.8/4.18, motor 3.7); (b) boto3 `before-send` hook header capture; (c) SQLAlchemy `make_url` with `@`, `:`, `/`, `?` in the password; (d) psycopg connect and bad-conninfo error text; (e) oracledb connect error text; (f) `repr` of the prompt's locals dict.
6. Quick re-run for prints: `grep -rnE '(^|[^A-Za-z_.])print\\(' --include='*.py' . | grep -vE '/\\.venv/|/tests/'` -> 0 hits on this commit (the only `print` token left is the string `"print"` in the builtins allowlist and the `print(` prefix check in `clean_code`).

Inventory on `3dc62c4`:

| Set | Count |
|---|---|
| print-family calls | {len(d['print'])} |
| logger calls | {len(logs)} ({fmt(lvl)}) |
| raise/response sinks | {len(sinks)} ({fmt(sinkc)}) |

Verdict totals: logger calls {fmt(lc)}; sinks {fmt(sc)}.

## 5. Appendix A: every logger call ({len(logs)})

{table(logs, log_verdict, "level", "level")}

## 6. Appendix B: every raise/response sink ({len(sinks)})

`HTTPException`/`JSONResponse` rows reach the client directly; other rows reach the client only through `utils.py:37` and the `detail=str(e)` sites in `api/endpoints.py`, or the LLM through `utils.py:148`.

{table(sinks, sink_verdict, "call", "call")}

## 7. Appendix C: non-log sinks

| Sink | Where | Content | Verdict |
|---|---|---|---|
| LLM conversation posted to lyzr-agent | `utils.py:59-70`, appended at `:135-150` | error text + full traceback of failed iterations; NoSQL prompt with `repr(db)` (`service.py:169-172`) | DISCLOSURE (F3) |
| Container stdout from exec'd code | `service.py:263`, builtin `print` allowed at `restricted_exec.py:98` | whatever the model prints | LEAK-IF (F1) |
| Signed AWS request visible to exec'd code | `dynamodb.meta.client.meta.events` (public path) | access key id, session token, signature; not the secret | DISCLOSURE (F1) |
| HTTP 500/400 bodies | `endpoints.py:94,137,163,184,209` | internal exception text | DISCLOSURE (F2) |
| Locally built image | `Dockerfile:67` `COPY . .`, no `.dockerignore` | a developer's `.env` if present | LOW (F5) |

## 8. Recommendations, in order

1. F1: remove `print` from `_SAFE_BUILTIN_NAMES` (or bind it to a capped DEBUG logger); expose DynamoDB through a wrapper that offers `Table` operations only, not the boto3 resource; keep the underscore ban.
2. F2: one exception handler with a fixed message and a correlation id; log detail server-side; build the service Postgres connection from the discrete env vars, never through a `user:pass@host` string, and delete the `make_url` parse in `file_upload.py:51` and `settings.py:170`.
3. F3: feed the model `type(e).__name__` plus the first line of the message, never `traceback.format_exc()`; describe the environment with strings, not `repr(db)`.
4. F4: trim lyzr-agent error bodies to status + first 200 chars before logging or returning; log customer column names at DEBUG only.
5. F5: add a `.dockerignore` with `.env`, `.git`, `tests/`, `.venv/`.
6. Keep the extractor in CI: a `ruff` `T201` rule (no `print`) fails the build if one returns outside `scripts/`.
"""
# ---------------------------------------------------------------------------
# Safety coverage: every number below is computed from the rows in Appendix A/B
# (same verdict functions), not estimated.
# ---------------------------------------------------------------------------
rows = [("logger", r, log_verdict(r)) for r in logs] + [("sink", r, sink_verdict(r)) for r in sinks]
total = len(rows)
leaky = [x for x in rows if x[2][0] in ("LEAK", "LEAK-IF")]
clean = [x for x in rows if x[2][0] in ("SAFE", "CLI")]
disc = [x for x in rows if x[2][0] == "DISCLOSURE"]
disc_gated = [x for x in disc if x[0] == "logger" and x[1]["level"] == "debug"]
disc_live = [x for x in disc if not (x[0] == "logger" and x[1]["level"] == "debug")]
disc_client = [x for x in disc if x[0] == "sink" and x[1]["call"].split(".")[-1] in ("HTTPException", "JSONResponse")]
pct = lambda a, b: f"{(100.0 * a / b):.1f}%" if b else "n/a"
log_clean = sum(1 for x in rows if x[0] == "logger" and x[2][0] in ("SAFE", "CLI"))
sink_clean = sum(1 for x in rows if x[0] == "sink" and x[2][0] in ("SAFE", "CLI"))

CONTROLS = [
    ("No `print` in application code", True, "AST + grep: 0 print-family calls; PR #115 `1d3ea07`"),
    ("`stdout` guard in the server process (blocks prints from exec'd code)", False, "none; `restricted_exec.py:98` allows `print`, `service.py:277-281` strips only leading `print(` lines"),
    ("Request-body validation errors redacted", True, "`app.py:56-78` `_redact_validation_errors`"),
    ("`hide_input_in_errors` on every credential model", True, "`db_models.py:87` + 11 `model_config` assignments"),
    ("Access log disabled (no path/query lines)", True, "`api/logging_config.py:41`"),
    ("Tracebacks gated behind DEBUG; `LOG_LEVEL` defaults INFO", True, "`api/endpoints.py` 9 sites at `logger.debug`; `app.py:15`"),
    ("Central exception handler returning a fixed message", False, "none; `detail=str(e)` at `endpoints.py:94,137,163,184,209`"),
    ("Driver error text sanitized before it reaches a client or log", False, "none; cloudrift text passed through `utils.py:37`"),
    ("Service DB connection built from discrete fields, not a `user:pass@host` string", False, "`settings.py:107-109`, `file_upload.py:51` (`make_url`)"),
    ("Error text sent to the LLM trimmed (no traceback)", False, "`utils.py:148` sends `traceback.format_exc()`"),
    ("Environment description sent to the LLM is a string, not `repr(db)`", False, "`service.py:169-172, 222`"),
    ("Cloud SDK handles wrapped before exposure to exec'd code", False, "`service.py:214, 233` expose the motor Database and the boto3 resource"),
    ("`.dockerignore` excludes `.env`", False, "no `.dockerignore`; `Dockerfile:67` `COPY . .`"),
]
ctrl_present = sum(1 for _, ok, _ in CONTROLS if ok)

MD += f"""
## 9. Safety coverage (grounded)

Every percentage is computed from the {total} inventoried rows in Appendix A ({len(logs)} logger calls) and Appendix B ({len(sinks)} raise/response sinks) using the verdicts printed there, plus the control checklist below. Nothing here is estimated.

| Measure | Value | How it is computed |
|---|---|---|
| Credential-safe rows | **{pct(total - len(leaky), total)}** ({total - len(leaky)}/{total}) | rows whose verdict is not LEAK or LEAK-IF. The {len(leaky)} remaining rows are the `@`-in-`DB_PASSWORD` edge (F2): `api/settings.py:200`, `file_upload.py:44`. |
| Disclosure-free rows (SAFE or CLI) | **{pct(len(clean), total)}** ({len(clean)}/{total}) | logger calls {pct(log_clean, len(logs))} ({log_clean}/{len(logs)}), sinks {pct(sink_clean, len(sinks))} ({sink_clean}/{len(sinks)}) |
| Disclosure rows that are DEBUG-gated | {pct(len(disc_gated), len(disc))} ({len(disc_gated)}/{len(disc)}) | DISCLOSURE logger rows at `logger.debug`; silent while `LOG_LEVEL` stays INFO |
| Disclosure rows live at INFO+ or in HTTP responses | {pct(len(disc_live), len(disc))} ({len(disc_live)}/{len(disc)}) | the rest; {len(disc_client)} of them are `HTTPException`/`JSONResponse` rows that reach the caller directly |
| Print-family calls | 100% clean (0 calls) | AST + grep |
| Safety controls in place | **{pct(ctrl_present, len(CONTROLS))}** ({ctrl_present}/{len(CONTROLS)}) | checklist below, each item tied to a file:line |

Reading the two headline numbers together: {pct(total - len(leaky), total)} of sinks cannot carry a credential on any verified path, but only {pct(len(clean), total)} are free of internal or customer detail, and only {pct(ctrl_present, len(CONTROLS))} of the controls that would make that structural exist. The gap between the first and the other two is exactly the finding list: the service is credential-safe today because the drivers happen not to echo passwords, not because the code strips them.

### How to read each measure

Every measure is a ratio over the same {total} rows: the {len(logs)} logger calls in Appendix A plus the {len(sinks)} places in Appendix B where code raises an error or builds an HTTP response. Each row has exactly one verdict, and each measure counts verdicts.

The verdict vocabulary the measures are built on:

| Verdict | Meaning |
|---|---|
| LEAK | a real secret (password, token, key) reaches the sink on a normal code path |
| LEAK-IF | a secret reaches the sink only under a stated condition, such as a specific character in a password or `LOG_LEVEL=DEBUG` |
| DISCLOSURE | no secret, but internal or customer detail gets out: hostnames, user names, column names, driver error text, upstream error bodies, tracebacks |
| SAFE | static text, ids, counts or key names only; nothing to protect |
| CLI | lives in an operator script under `scripts/` that never runs inside the service |

| Measure | What it means | How to act on it |
|---|---|---|
| Credential-safe rows ({pct(total - len(leaky), total)}) | The share of rows where no password, token or key can appear on any path that was verified. A row fails only with a LEAK or LEAK-IF verdict. The {len(leaky)} failing rows here are one edge case seen at two sites: if the service's own `DB_PASSWORD` contains `@`, the URL parser splits it and the tail lands in an error message. | This is the headline safety number. Anything below 100% is a concrete fix; a conditional (LEAK-IF) row still counts as failing because the condition is outside the code's control. |
| Disclosure-free rows ({pct(len(clean), total)}) | A stricter bar: the row prints nothing internal at all (SAFE) or is a CLI script (CLI). The other {len(disc)} rows print something a customer or an attacker should not see even though it is not a secret. The split shows where the noise is: logger calls {pct(log_clean, len(logs))}, error/response sinks {pct(sink_clean, len(sinks))}. | Measures information hygiene, not secret exposure. It rises when error text is replaced by fixed messages and correlation ids. |
| Disclosure rows that are DEBUG-gated ({pct(len(disc_gated), len(disc))}) | Of the {len(disc)} DISCLOSURE rows, {len(disc_gated)} are `logger.debug` calls. They emit nothing while `LOG_LEVEL` is INFO (the default, not overridden anywhere in the repo or CI), so they are dormant today. | Dormant is not fixed: one environment change switches them all on. Treat as latent. |
| Disclosure rows live at INFO+ or in HTTP responses ({pct(len(disc_live), len(disc))}) | The remaining {len(disc_live)} DISCLOSURE rows fire at the default log level or go into a response body. {len(disc_client)} of them are `HTTPException`/`JSONResponse` rows, which go straight back to the API caller rather than to the log. | These are the rows an outsider can see today. The response rows are the priority because the reader is external. |
| Print-family calls (100% clean) | The count of `print`, `pprint`, `sys.stdout.write`, `traceback.print_exc` and similar calls. Zero on this commit, so there is nothing to grade. Note that this counts application code only; model-generated code executed by `service.py:263` can still call `print` (F1). | Keep at zero with a lint rule (`ruff` `T201`). |
| Safety controls in place ({pct(ctrl_present, len(CONTROLS))}) | Not a row count. A checklist of {len(CONTROLS)} design measures that would make the safety structural rather than incidental, each marked present or absent with the file and line that proves it. {ctrl_present} exist, {len(CONTROLS) - ctrl_present} do not. | This is the durability number. A high credential-safe share with a low controls share means the code relies on library behaviour; if a driver changed its error text, the first number would fall and nothing in the code would catch it. |

The denominators: a percentage over {total} is "of all inventoried sinks"; a percentage over {len(disc)} is "of the DISCLOSURE rows only"; the controls percentage is over the {len(CONTROLS)} checklist items. Re-running `dq_report.py` after a code change recomputes every figure from the same rules, so the numbers can be tracked across commits.

| # | Control | Present | Evidence |
|---|---|---|---|
""" + "\n".join(f"| {i} | {cell(name)} | {'yes' if ok else 'no'} | {cell(ev)} |" for i, (name, ok, ev) in enumerate(CONTROLS, 1)) + f"""

## 10. Summary

Scope: `NeuralgoLyzr/data-query` master `3dc62c4` (2026-09-23), every non-test file read in full, {total} logger and raise/response rows classified, fake-value probes run in the repo's venv.

- **Prints: none left.** PR #115 replaced the last 14 with logger calls; AST and grep both find zero print-family calls.
- **Logger calls leak no credential on any verified path.** They carry customer DB hosts and user names, column and collection names, occasionally a quoted result cell, and lyzr-agent error bodies. Nine full tracebacks are DEBUG-gated.
- **Exceptions leak no key or password to clients on a verified path**, but every route returns raw `str(e)`, so the protection rests on the drivers never echoing passwords (probed for psycopg, oracledb, pymongo; read for pyodbc/cloudrift) and on pydantic `hide_input_in_errors`, which is set on all 11 credential models.
- **F1 (MEDIUM):** model-generated code runs with live handles, keeps builtin `print` with no stdout guard, and on DynamoDB can read the access key id and session token through a public event-hook path; the secret key and the Mongo password are not reachable (verified).
- **F2 (MEDIUM):** `detail=str(e)` on all five routes plus ERROR logging of the same text; one edge where a `DB_PASSWORD` containing `@` puts its tail into the host name that libpq echoes.
- **F3 (MEDIUM):** tracebacks with the failing SQL and driver text, and `repr()` of the live Mongo handle, are sent to the LLM provider.
- **F4/F5 (LOW):** upstream error bodies forwarded to callers and logged at ERROR; column names and pandas error text at WARNING; no `.dockerignore` under a `COPY . .` Dockerfile.
- **Coverage:** {pct(total - len(leaky), total)} credential-safe, {pct(len(clean), total)} disclosure-free, {pct(ctrl_present, len(CONTROLS))} of controls in place.
- **Action:** no PR opened. The ordered fix list in section 8 closes F1-F5 with six changes, the first three of which (drop `print` from the exec builtins, one central exception handler, trimmed error text to the LLM) remove every MEDIUM finding.
"""

open(OUT, "w").write(MD)
print("wrote", OUT, len(MD), "chars"); print("logger verdicts", dict(lc)); print("sink verdicts", dict(sc))
