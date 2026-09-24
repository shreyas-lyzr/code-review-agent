"""Render rag-print-audit.md from rag_audit.json + rag_subsets.json.

Every row gets a verdict. Rows that were read in context get an explicit entry in
OVERRIDES; the rest get a rule-based verdict (marked "rule" in the table).
Verdict vocabulary:
  LEAK        a credential or bearer value reaches the sink on this code path
  LEAK-IF     reaches the sink only under a stated condition (DEBUG, a URI with userinfo, ...)
  DISCLOSURE  internal hosts / URLs / error bodies / PII reach the sink; no credential
  SAFE        ids, names, counts, key names, static text, redacted values
  CLI         operator script under scripts/; never runs in the API or the worker
  DEAD        only under `if __name__ == "__main__":` or a demo() helper
"""
import json, os, re, collections

S = os.environ["S"]
OUT = os.environ["OUT"]
d = json.load(open(f"{S}/rag_audit.json"))
sub = json.load(open(f"{S}/rag_subsets.json"))

def key(r): return f'{r["file"]}:{r["line"]}'
def src(r, n=150): return " ".join(r["src"].split()).replace("|", "\\|")[:n]
def cell(s): return s.replace("|", "\\|")

# ---------------------------------------------------------------------------
# Explicit verdicts (read in context). file:line -> (verdict, note)
# ---------------------------------------------------------------------------
OVERRIDES = {
    # --- finding 1: owner API key in connector config ---
    "kb_sync/tasks/docfetching.py:195": ("LEAK-IF", "DEBUG only. Dumps the whole connector_specific_config; for website sources it holds crawler_api_key = the KB owner's Lyzr API key (set at api/v3/live_sources/endpoints.py:199-204)."),
    # --- finding 2: presigned URLs ---
    "api/v3/extract/endpoints.py:329": ("LEAK", "WARNING. Raw file_url (presigned, signature in the query) although _log_safe_source exists 20 lines above; exc_info=True adds the traceback."),
    "api/v3/extract/endpoints.py:343": ("LEAK", "ERROR + traceback. Raw file_url (presigned)."),
    "api/v3/extract/endpoints.py:408": ("LEAK", "WARNING. Raw file_url (presigned)."),
    "api/v3/extract/endpoints.py:427": ("LEAK", "WARNING. Raw file_url (presigned)."),
    "api/v3/extract/endpoints.py:601": ("LEAK", "WARNING. Raw file_url (presigned)."),
    "api/v3/extract/endpoints.py:610": ("LEAK", "WARNING. Raw file_url (presigned)."),
    "api/v3/extract/endpoints.py:388": ("LEAK", "The message is redacted with _log_safe_source, but logger.exception prints the traceback, and r.raise_for_status() at :373 raises aiohttp.ClientResponseError whose text carries url='...?X-Amz-Signature=...' (verified, aiohttp 3.14.3)."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/parse_upload_staging.py:313": ("LEAK", "exc_info=True. The stream uses httpx with response.raise_for_status() at :258; httpx.HTTPStatusError text carries the full presigned URL (verified with the installed httpx)."),
    "api/v3/extract/endpoints.py:353": ("SAFE", "Redacted with _log_safe_source."),
    "api/v3/extract/endpoints.py:348": ("SAFE", "Redacted with _log_safe_source."),
    "api/v3/extract/endpoints.py:357": ("SAFE", "Redacted with _log_safe_source; `e` is the local blocked-fetch reason."),
    "api/v3/extract/endpoints.py:334": ("SAFE", "Redacted with _log_safe_source."),
    "api/v3/extract/endpoints.py:371": ("SAFE", "Redacted with _log_safe_source."),
    "api/v3/extract/endpoints.py:376": ("SAFE", "Redacted with _log_safe_source."),
    "api/v3/extract/endpoints.py:384": ("SAFE", "Redacted with _log_safe_source."),
    "api/v3/extract/endpoints.py:417": ("SAFE", "Redacted with _log_safe_source."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/parse_upload_staging.py:303": ("SAFE", "Bucket, key and local path; the presigned URL itself is not logged here."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/cloudrift_utils.py:285": ("SAFE", "Key, expiry and bucket; the URL is not logged."),
    # --- finding 4: vector-store / graph URIs ---
    "lyzr_rag_sdk/core/vector_store/milvus.py:65": ("LEAK-IF", "DEBUG. Per-KB Milvus URI. pymilvus accepts https://user:password@host URIs, so a customer URI written that way is logged with its password. The Zilliz token is passed separately and is not logged."),
    "lyzr_rag_sdk/core/vector_store/qdrant.py:67": ("DISCLOSURE", "DEBUG. Per-KB Qdrant URL (host). The api key is a separate field and is not logged."),
    "lyzr_rag_sdk/core/vector_store/qdrant.py:86": ("DISCLOSURE", "DEBUG. Per-KB Qdrant URL (host)."),
    "lyzr_rag_sdk/core/vector_store/qdrant.py:94": ("DISCLOSURE", "DEBUG. Per-KB Qdrant URL (host)."),
    "lyzr_rag_sdk/core/vector_store/qdrant.py:125": ("DISCLOSURE", "ERROR. Per-KB Qdrant URL (host) on every connect failure."),
    "lyzr_rag_sdk/core/vector_store/qdrant.py:124": ("DISCLOSURE", "ERROR. qdrant-client error text; carries the URL host, never the api key."),
    "lyzr_rag_sdk/core/vector_store/graphrag/neo4j_db.py:48": ("DISCLOSURE", "INFO. NEO4J URI from settings (host). The driver takes auth separately; a URI with embedded userinfo would be logged as-is."),
    "lyzr_rag_sdk/core/vector_store/graphrag/arangodb_db.py:185": ("DISCLOSURE", "INFO. Arango host URL; python-arango takes username/password separately."),
    "scripts/migrate_arango_shared_to_perkb.py:371": ("CLI", "Operator script; prints the Arango host from its own --uri argument."),
    "lyzr_rag_sdk/core/vector_store/pg_vector.py:288": ("DISCLOSURE", "DEBUG. host/port/dbname/user/auth_mode/ssl_mode; the password is deliberately left out."),
    "lyzr_rag_sdk/core/vector_store/pg_vector.py:343": ("DISCLOSURE", "ERROR. host:port/dbname plus the psycopg/vecs error; psycopg error text names the user, never the password."),
    # --- finding 5: bodies / dumps / PII ---
    "shared/aci/client.py:110": ("DISCLOSURE", "ERROR. First 500 chars of the ACI error body. ACI authenticates by header; its error bodies do not echo the key, but the body is untrusted upstream text."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/lyzr_parse_reader.py:312": ("DISCLOSURE", "ERROR. First 300 chars of the VLM error response. LiteLLM masks `key=` in Gemini URLs (verified on 1.91.5)."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/lyzr_parse_reader.py:319": ("DISCLOSURE", "INFO. Same 300-char VLM error excerpt."),
    "api/v3/live_sources/source_auth.py:228": ("DISCLOSURE", "ERROR. Logs the Graph /me body: display name, mail, ids (PII), no token."),
    "api/v3/live_sources/queue_backend.py:113": ("DISCLOSURE", "ERROR. First 500 chars of the dead-letter record (error text + start of the traceback)."),
    "api/v3/live_sources/queue_backend.py:299": ("DISCLOSURE", "ERROR. Same for Service Bus."),
    "kb_sync/connectors/google_utils/google_utils.py:131": ("SAFE", "WARNING. Drive page token: an opaque pagination cursor, not a credential. Noise."),
    "kb_sync/connectors/google_drive/file_retrieval.py:321": ("SAFE", "INFO. Drive page token (cursor). Noise."),
    "kb_sync/connectors/google_drive/file_retrieval.py:383": ("SAFE", "INFO. Drive page token (cursor). Noise."),
    "kb_sync/connectors/google_drive/file_retrieval.py:438": ("SAFE", "INFO. Drive page token (cursor). Noise."),
    "kb_sync/connectors/google_drive/connector.py:833": ("SAFE", "INFO. User email (PII) and a page token (cursor)."),
    "kb_sync/connectors/google_drive/connector.py:813": ("DISCLOSURE", "WARNING. User email (PII) plus google-auth RefreshError text ('invalid_grant: ...'); the refresh token is not part of that text."),
    "kb_sync/connectors/google_utils/resources.py:72": ("SAFE", "RefreshError text; no token."),
    "api/v3/live_sources/permissions.py:217": ("DISCLOSURE", "WARNING. Email (PII)."),
    "api/v3/live_sources/permissions.py:219": ("DISCLOSURE", "ERROR. Email (PII) + Graph error text."),
    "api/v3/live_sources/permissions.py:222": ("DISCLOSURE", "ERROR. Email (PII) + Graph error text."),
    "api/v3/live_sources/permissions.py:291": ("DISCLOSURE", "WARNING. Email (PII), site id, error text."),
    "api/v3/live_sources/permissions.py:343": ("DISCLOSURE", "DEBUG. Email (PII), site URL, error text."),
    "api/v3/live_sources/permissions.py:353": ("DISCLOSURE", "DEBUG. Email (PII), site URL, error text."),
    "api/v3/live_sources/source_auth.py:250": ("DISCLOSURE", "INFO. user id and verified email (PII)."),
    "api/v3/live_sources/source_auth.py:204": ("DISCLOSURE", "ERROR. user id + ACI error text (internal ACI URL possible via httpx error)."),
    # --- verified safe-by-design ---
    "app.py:89": ("SAFE", "describe_credentials() prints 'key set' / 'no key', never the value."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/cloudrift_utils.py:71": ("SAFE", "Set/unset flags for env vars, library versions."),
    "lyzr_rag_sdk/lyzr_parse/source_utils/cloudrift_utils.py:99": ("SAFE", "botocore credential-provider names."),
    "api/utils/settings.py:539": ("SAFE", "access_key_id passes through _redact_access_key; the secret key is never logged."),
    "shared/cache.py:105": ("SAFE", "Env var name and the secret's byte length only."),
    "shared/cache.py:127": ("SAFE", "Env var name, the JSON key names and a byte length."),
    "shared/cache.py:195": ("SAFE", "Key names of the Secrets Manager bundle."),
    "kb_sync/connectors/factory.py:43": ("SAFE", "Config key names only."),
    "kb_sync/connectors/factory.py:44": ("SAFE", "Credential key names only."),
    "api/v3/rag/service.py:606": ("SAFE", "Key names only."),
    "lyzr_rag_sdk/core/vector_store/singlestore.py:41": ("SAFE", "Key names only."),
    "shared/vaulted_secrets.py:289": ("SAFE", "credential id only."),
    "api/v3/rag/endpoints.py:452": ("SAFE", "Fingerprint of the value, not the value."),
    "api/v3/live_sources/permission_gate.py:99": ("SAFE", "User id passes through _redact_user_id."),
    "api/v3/live_sources/source_auth_liveness.py:126": ("SAFE", "User id redacted; tenant ids are not secrets."),
    "api/v3/live_sources/source_auth_liveness.py:116": ("SAFE", "User id redacted; ACI error text."),
    "scripts/vault_legacy_credentials.py:68": ("CLI", "Field names only."),
    "kb_sync/connectors/sharepoint/inheritance_scan.py:67": ("SAFE", "MSAL error_description; never the secret."),
    "api/v3/live_sources/permissions.py:175": ("SAFE", "MSAL error code."),
    "api/v3/live_sources/endpoints.py:663": ("SAFE", "credential ids."),
    "api/utils/platform_llm.py:99": ("DISCLOSURE", "WARNING. `detail` field of the platform LLM error body."),
    "kb_sync/connectors/website/connector.py:286": ("SAFE", "Public crawl URL, crawler error text and status; the crawler key is sent in a header and not echoed."),
    "kb_sync/connectors/sharepoint/connector.py:2680": ("SAFE", "`exc` cannot be a requests error: _download_driveitem_bytes catches requests.RequestException itself (:593) and logs name + status (:604-607), so the pre-authenticated downloadUrl never reaches this line."),
    "kb_sync/connectors/sharepoint/connector.py:1413": ("DISCLOSURE", "Customer SharePoint site URL + Graph error text (bearer auth; URL has no secret)."),
    "kb_sync/connectors/sharepoint/connector.py:1562": ("DISCLOSURE", "Graph error text."),
    "shared/oauth/sharepoint.py:97": ("DISCLOSURE", "Azure AD error_description returned to the client (AADSTS text, trace id); never the client secret."),
    "api/v3/rag/endpoints.py:927": ("DISCLOSURE", "When str(e) is empty the FULL traceback.format_exc() is returned in the 500 body (:924-926): file paths, hosts, upstream error text."),
    "api/v3/classify/endpoints.py:83": ("DISCLOSURE", "Upstream LLM error text to the client. LiteLLM 1.91.5 masks `key=` (probe: auth error, unknown model, timeout); OpenAI/Azure/Anthropic bodies do not echo keys; gateway hostnames may appear."),
    "api/v3/extract/endpoints.py:523": ("DISCLOSURE", "Same as classify:83."),
    "api/v3/rag/service.py:274": ("DISCLOSURE", "SecretResolutionError text: lyzr-agent HTTP status + first 200 chars of its body, or the httpx error with the internal AGENT_SERVICE_URL."),
    "api/utils/vlm_credentials.py:179": ("DISCLOSURE", "Same SecretResolutionError text."),
    "api/v3/credentials/endpoints.py:54": ("DISCLOSURE", "detail=str(e) of SecretResolutionError (internal URL / lyzr-agent body excerpt) as a 502."),
    "api/v3/credentials/endpoints.py:157": ("DISCLOSURE", "Same as :54."),
    "api/v3/live_sources/endpoints.py:297": ("DISCLOSURE", "ValueError text from connector_service, including :120 'Credential ... not found in ACI: {exc}' which can carry the internal ACI base URL from an httpx error."),
    "api/v3/live_sources/endpoints.py:644": ("DISCLOSURE", "ACI error text (internal ACI URL possible)."),
    "api/utils/credits.py:124": ("DISCLOSURE", "pymongo error text: host:port list on ServerSelectionTimeoutError; never the password."),
    "shared/vaulted_secrets.py:207": ("DISCLOSURE", "Raised with lyzr-agent's status and 200 chars of its body; reaches clients via credentials/endpoints.py:54,157, rag/service.py:274, vlm_credentials.py:179."),
    "shared/vaulted_secrets.py:218": ("DISCLOSURE", "httpx error text: internal AGENT_SERVICE_URL host (token is a header)."),
    "shared/vaulted_secrets.py:227": ("DISCLOSURE", "Same as :218."),
    "shared/aci/client.py:392": ("DISCLOSURE", "Raised with the full ACI JSON body. Caller source_auth.py:171 has no detail=str(e); FastAPI returns a generic 500, so this is log-only."),
    "shared/cache.py:161": ("DISCLOSURE", "Secrets Manager ARN + botocore error text (no secret value)."),
    "shared/cache.py:114": ("SAFE", "ARN, env name and JSON key names."),
    "lyzr_rag_sdk/core/vector_store/qdrant.py:126": ("DISCLOSURE", "Wraps the qdrant-client error (URL host); surfaces to clients through the train/rag detail=str(e) sites."),
    "lyzr_rag_sdk/core/vector_store/pg_conn.py:131": ("SAFE", "int() ValueError names only the bad port text."),
    "lyzr_rag_sdk/core/vector_store/pg_conn.py:117": ("SAFE", "Scheme only."),
    "kb_sync/services/connector_service.py:120": ("DISCLOSURE", "ACI error text (internal ACI URL possible); reaches clients via live_sources/endpoints.py:297."),
    "kb_sync/services/connector_service.py:131": ("SAFE", "Site access errors (site URLs)."),
    "kb_sync/connectors/sharepoint/connector.py:1740": ("SAFE", "Host only."),
    "lyzr_rag_sdk/core/vector_store/vertex_ai_rag.py:313": ("DISCLOSURE", "Vertex error body field."),
    "api/utils/settings.py:176": ("SAFE", "Names the env var, not its value."),
    "api/utils/settings.py:224": ("SAFE", "Names the env vars, not their values."),
}

# prints: per-file rules
PRINT_RULES = [
    (re.compile(r"^scripts/seed_.*json\.dumps\(PROVIDER_DOC"), ("CLI", "Static provider form schema (no secrets).")),
    (re.compile(r"^scripts/seed_azure_ai_search_credential\.py:92$"), ("CLI", "Credential doc with credentials.api_key replaced by '***' (:86).")),
    (re.compile(r"^scripts/seed_.*host=\{safe_url\}"), ("CLI", "Mongo host with the password replaced by '***' (safe_url, :83-86 / :115-117).")),
    (re.compile(r"^scripts/reset_webhook_subscriptions\.py:75$"), ("CLI", "WEBHOOK_CALLBACK_URL: a public callback URL; Graph webhooks are verified by clientState, which is not in the URL.")),
    (re.compile(r"^scripts/"), ("CLI", "Static text, counts or ids.")),
    (re.compile(r"^kb_sync/connectors/sharepoint/inheritance_scan\.py:130$"), ("DEAD", "print('ok') inside demo().")),
    (re.compile(r"^kb_sync/connectors/(sharepoint|google_drive)/connector\.py"), ("DEAD", "Under `if __name__ == \"__main__\":`; doc identifiers, counts, timings. Never runs in the worker, and builtins.print is a no-op there anyway.")),
]

def print_verdict(r):
    k = key(r); s = src(r, 400)
    for rx, v in PRINT_RULES:
        if rx.search(k) or rx.search(f"{k} {s}") or rx.search(s):
            return v
    return ("CLI", "Static text.")

SENS_URL = re.compile(r"(?i)(url|uri|host)")
EXC_IN = re.compile(r"(\{(e|err|exc|ex|error|exception)(\b|[\.\)\[:!}])|str\((e|err|exc|ex)\)|%s.*\b(e|exc|err|error)\b|exc_info=True|logger\.exception)")
SP_URL = re.compile(r"(site_descriptor\.url|sd\.url|web_url|site_url|checkpoint\.current_site_descriptor\.url|self\.root_url|drive_id)")

def sens_verdict(r):
    k = key(r)
    if k in OVERRIDES: return OVERRIDES[k] + ("read",)
    s = r["src"]
    if not re.search(r"\{[^}]+\}|%[sdrf]|exc_info=True|logger\.exception", s):
        return ("SAFE", "Static message; names a sensitive word but interpolates nothing.", "rule")
    if SP_URL.search(s): return ("SAFE", "Customer SharePoint/site resource URL; Graph uses bearer headers, the URL carries no secret.", "rule")
    if re.search(r"credential_id|cc_pair|rag_id|provider_id|linked_account|collection_name|tenant_id|key_var|env_name|\bkey=%s|key=\{key\}", s) and not EXC_IN.search(s):
        return ("SAFE", "Ids, names or key names only.", "rule")
    if EXC_IN.search(s): return ("DISCLOSURE", "Embeds exception text; see the class verdict in Appendix B.", "rule")
    if SENS_URL.search(s): return ("DISCLOSURE", "Logs a URL/host; no query secret on this path.", "rule")
    return ("SAFE", "Message mentions a sensitive word but prints no value.", "rule")

# Exception-text classes by source of `e`
EXC_CLASSES = [
    ("A", re.compile(r"^lyzr_rag_sdk/core/vector_store/|^lyzr_rag_sdk/core/consumer\.py|^api/utils/credits\.py|^api/utils/llm_pricing\.py|^shared/db/|^api/v3/sharing/|^lyzr_rag_sdk/lyzr_parse/source_utils/parse_cache\.py|^api/v3/rag/(document_registry|pending_uploads|upload_attribution)\.py"),
     "Datastore client errors (pymongo, psycopg/vecs, qdrant-client, pymilvus, weaviate, neo4j, python-arango, redis). Text carries host:port and user names, never the password or token. Edge: SQLAlchemy ArgumentError on an unparsable Postgres/SingleStore URL echoes that URL with its password (customer-supplied malformed URL only)."),
    ("B", re.compile(r"^shared/aci/|^shared/vaulted_secrets\.py|^api/utils/(platform_llm|vlm_credentials|gateway_credentials)\.py|^api/v3/live_sources/(source_auth|source_auth_liveness|permission_context|permissions|endpoints|browse)\.py|^kb_sync/tasks/(sync_permissions|reconcile_permissions|webhook_subscriptions)\.py|^kb_sync/services/|^api/v3/kb_sync/"),
     "httpx/requests errors against internal services (lyzr-agent, ACI) or Microsoft Graph. Auth travels in headers; the text can carry the internal base URL and upstream error bodies. No credential."),
    ("C", re.compile(r"^api/v3/(classify|extract)/endpoints\.py:(82|522)$|^lyzr_rag_sdk/core/reranker\.py|^lyzr_rag_sdk/core/vector_store/base\.py|^lyzr_rag_sdk/core/vector_store/graphrag/(extraction|embedding)\.py|^lyzr_rag_sdk/lyzr_parse/source_utils/lyzr_parse_reader\.py:(312|319|1024)$"),
     "LLM/embedding errors via LiteLLM 1.91.5. Verified with a fake Gemini key: the key never appears in str(e), repr(e), the cause chain or DEBUG logs (masked `key=`). Upstream error bodies and gateway hostnames can appear."),
    ("D", re.compile(r"^api/v3/extract/endpoints\.py|^lyzr_rag_sdk/lyzr_parse/source_utils/parse_upload_staging\.py"),
     "Fetches of presigned object URLs. aiohttp.ClientResponseError, httpx.HTTPStatusError and requests errors all carry the full URL including the signature; see Finding 2 for the affected lines."),
    ("E", re.compile(r"^kb_sync/connectors/(google_|sharepoint)|^kb_sync/connectors/website/|^kb_sync/tasks/docfetching\.py|^kb_sync/connectors/connector_runner\.py"),
     "Connector errors: Google API HttpError (URL without secrets), Graph/MSAL text, crawler text. The SharePoint pre-authenticated downloadUrl is caught inside the download helper and logged as name + status only. Customer resource URLs and user emails (PII) appear."),
    ("F", re.compile(r"^lyzr_rag_sdk/lyzr_parse/|^kb_sync/file_processing/|^kb_sync/file_store/|^kb_sync/utils/|^lyzr_rag_sdk/core/embedding\.py|^kb_sync/connectors/google_drive/doc_conversion\.py"),
     "Parsing / file errors: file names, paths, sizes, parser stderr. No credential."),
    ("G", re.compile(r"^api/utils/(credit_consumption|event_producer|audit|settings)\.py|^celery_app/|^api/v3/live_sources/(queue_backend|consumer)|^lyzr_rag_sdk/trace_provider\.py|^kb_sync/tasks/(monitoring|publish_to_rag)\.py"),
     "Infra errors (botocore/SQS, Service Bus, Redis, Celery): error codes and queue names. No credential."),
]
def exc_class(r):
    k = key(r)
    for c, rx, _ in EXC_CLASSES:
        if rx.search(k): return c
    return "H"
EXC_H = "Other application errors (ids, names, generic text)."

def exc_verdict(r):
    k = key(r)
    if k in OVERRIDES: return OVERRIDES[k] + ("read",)
    c = exc_class(r)
    default = {"A": "DISCLOSURE", "B": "DISCLOSURE", "C": "DISCLOSURE", "D": "DISCLOSURE", "E": "DISCLOSURE", "F": "SAFE", "G": "SAFE", "H": "SAFE"}[c]
    if not EXC_IN.search(r["src"]) and not re.search(r"\b(error|err|exc|reason|detail|msg|stderr)\b", r["src"]):
        default = "SAFE"
    return (default, f"class {c}", "rule")

def http_verdict(r):
    k = key(r)
    if k in OVERRIDES: return OVERRIDES[k] + ("read",)
    s = r["src"]
    if "Database error" in s: return ("DISCLOSURE", "pymongo error text (hosts, no password).", "rule")
    if "SharePoint API error" in s or "browse.py" in k: return ("DISCLOSURE", "Graph error text to the client; no secret.", "rule")
    if re.search(r"kb_sync/endpoints\.py|lyzrparse/endpoints\.py:(265|312|492|523|560)|train/endpoints\.py:(260|304|471|516|567)|live_sources/endpoints\.py:(508|542|578)", k):
        return ("DISCLOSURE", "ValueError text from the service layer (validation messages, ids); low value.", "rule")
    return ("DISCLOSURE", "Generic passthrough of internal exception text (datastore hosts, vector-store URLs, upstream LLM text, file paths) in a 500 body.", "rule")

def raised_verdict(r):
    k = key(r)
    if k in OVERRIDES: return OVERRIDES[k] + ("read",)
    s = r["src"]
    if EXC_IN.search(s): return ("DISCLOSURE", "Wraps another exception's text.", "rule")
    return ("SAFE", "Static text or ids; names a credential without printing it.", "rule")

# ---------------------------------------------------------------------------
def table(rows, verdict_fn, extra_label, extra_key, with_class=None):
    out = [f"| # | file:line | {extra_label} | call (truncated) | verdict | note | basis |", "|---|---|---|---|---|---|---|"]
    rows = sorted(rows, key=lambda r: (r["file"], r["line"]))
    for i, r in enumerate(rows, 1):
        v, note, basis = verdict_fn(r)
        ex = r.get(extra_key, "")
        if with_class: ex = f"{ex} / {with_class(r)}"
        out.append(f"| {i} | `{key(r)}` | {ex} | `{src(r)}` | **{v}** | {cell(note)} | {basis} |")
    return "\n".join(out)

def counts(rows, fn):
    return collections.Counter(fn(r)[0] for r in rows)

prints = d["print"]; logs = d["logger"]; sinks = d["sinks"]
sens_log, exc_log, http_pass, raised_sens, http_sens = sub["sens_log"], sub["exc_log"], sub["http_pass"], sub["raised_sens"], sub["http_sens"]
lvl = collections.Counter(l["level"] for l in logs)
sinkc = collections.Counter(s["call"] for s in sinks)
pc = counts(prints, lambda r: print_verdict(r))
sc = counts(sens_log, sens_verdict); ec = counts(exc_log, exc_verdict); hc = counts(http_pass, http_verdict); rc = counts(raised_sens, raised_verdict)
def fmt(c): return ", ".join(f"{k} {v}" for k, v in sorted(c.items(), key=lambda kv: -kv[1]))

exc_by_class = collections.Counter(exc_class(r) for r in exc_log)

MD = f"""# rag: print, logging and exception-leak audit

Repository `NeuralgoLyzr/rag`, branch `master` at `2f8f64a` (2026-09-23, includes PRs #402, #403, #405, #406). Scope: every `.py` outside `.venv/` and `tests/`. Method and regexes are in section 4; every row in the appendices carries a verdict.

Nothing in this document contains a credential. Snippets are source code; probes used fake values only.

## 1. Verdict

| Question | Answer |
|---|---|
| Does any `print` leak a credential? | No. All 46 prints are operator CLIs, `__main__` blocks or a demo helper, and `print` is a no-op in the API and the worker (`api/utils/stdout_guard.py`, installed at `app.py:16-18` and `celery_app/__init__.py:41,124`; bypass `ALLOW_PRINT=1`, not set in `.env`, CI or the Dockerfiles). No other stdout/stderr sinks exist (0 hits for `traceback.print_exc`, `sys.stdout.write`, `pprint`, `click.echo` …). |
| Does any logger call leak a credential at the default level (INFO)? | Yes, one class: presigned object URLs (temporary bearer credentials to S3/Blob objects) are logged at WARNING/ERROR in `api/v3/extract/endpoints.py` (6 raw sites + 1 through a traceback) and in `parse_upload_staging.py:313` through a traceback. |
| Does any logger call leak a credential at DEBUG? | Yes. `kb_sync/tasks/docfetching.py:195` dumps the connector config, which for website sources holds the KB owner's Lyzr API key. `milvus.py:65` logs the per-KB Milvus URI, which may embed a password. |
| Can an exception leak an API key to a client? | Not on any verified path. 80 endpoints pass exception text through (`detail=str(e)`), and `api/v3/rag/endpoints.py:927` returns a full traceback, but the text carries hosts, internal URLs, file paths and upstream error bodies, not keys: LiteLLM 1.91.5 masks Gemini `key=` URLs (probed), datastore drivers never print passwords, upstream providers do not echo keys. One theoretical edge: SQLAlchemy's `ArgumentError` on a malformed customer Postgres/SingleStore URL echoes that URL with its password. |
| Is a credential exposed through a non-log sink? | Yes, and this is the worst finding. The KB owner's Lyzr API key is stored in plaintext in two Mongo documents and returned in `LiveSourceResponse.connector_specific_config` to anyone who can list the KB's live sources, which includes policy-shared users and sharing-group members. |

## 2. Ranked findings

### F1. HIGH: the KB owner's Lyzr API key is stored in plaintext and returned to shared readers

- `api/v3/live_sources/endpoints.py:199-204` copies `auth_user.api_key` into `connector_specific_config["crawler_api_key"]` when a website live source is created.
- Stored verbatim in the `live_sources` document (`api/v3/live_sources/service.py:20-28`, model `LiveSourceInDB.connector_specific_config` at `models.py:70`) and in the kb_sync connector document (`kb_sync/services/connector_service.py:36-42`).
- Returned in `LiveSourceResponse.connector_specific_config` (`models.py:95`) on create (`endpoints.py:343-350`) and on list (`endpoints.py:380-392`). The list route is gated by `KNOWLEDGE_BASE_READ` plus `verify_rag_ownership`, which admits the owner, any policy-shared user and any sharing-group member with read access (`api/utils/authorization.py:35-75`). A read-only collaborator therefore receives the owner's full API key.
- Logged at DEBUG by `kb_sync/tasks/docfetching.py:195` on every sync of every website KB. `LOG_LEVEL` defaults to INFO and is not overridden in the repo, so this is latent, but both `app.py:8-11` and `kb_sync/utils/logger.py:13-30` honour a single env change.
- Consumed only by `kb_sync/connectors/website/connector.py:372-373`, which sends it as `x-api-key` to the crawler.

Fix shape: keep the key out of `connector_specific_config`; store a reference (credential id or a vaulted secret via `shared/vaulted_secrets.py`) and resolve it in the worker; strip `crawler_api_key` from `LiveSourceResponse`; delete the DEBUG dump or log `sorted(config.keys())` like `kb_sync/connectors/factory.py:43`.

### F2. MEDIUM: presigned object URLs are written to the logs

Presigned URLs are bearer credentials for one object until they expire. `api/v3/extract/endpoints.py` defines `_log_safe_source` (`:288-310`), which strips the query string, but:

| Site | Level | How the URL gets out |
|---|---|---|
| `api/v3/extract/endpoints.py:329` | WARNING | raw `file_url` in the message, plus `exc_info=True` |
| `api/v3/extract/endpoints.py:343` | ERROR | raw `file_url` in the message, plus traceback |
| `api/v3/extract/endpoints.py:408` | WARNING | raw `file_url` |
| `api/v3/extract/endpoints.py:427` | WARNING | raw `file_url` |
| `api/v3/extract/endpoints.py:601` | WARNING | raw `file_url` |
| `api/v3/extract/endpoints.py:610` | WARNING | raw `file_url` |
| `api/v3/extract/endpoints.py:388` | ERROR | message is redacted, but `logger.exception` prints the traceback and `r.raise_for_status()` (`:373`) raises `aiohttp.ClientResponseError`, whose text carries `url='…?X-Amz-Signature=…'` (verified, aiohttp 3.14.3) |
| `lyzr_rag_sdk/lyzr_parse/source_utils/parse_upload_staging.py:313` | WARNING | `exc_info=True`; the stream uses httpx with `raise_for_status()` (`:258`) and `httpx.HTTPStatusError` text carries the full URL (verified with the installed httpx) |

Probe results for the three HTTP clients in use: `httpx.HTTPStatusError` includes the query string; `requests.HTTPError` and `requests.ConnectionError` include it; `aiohttp.ClientResponseError` includes it; connect-level errors in httpx and aiohttp do not.

Fix shape: pass every URL through `_log_safe_source` (move it to a shared module), and on the two traceback sites log `type(e).__name__` and the status instead of `exc_info=True`, or wrap the fetch so the status error is re-raised without the URL.

### F3. MEDIUM: internal exception text and full tracebacks reach API clients

- `api/v3/rag/endpoints.py:924-927`: when `str(e)` is empty the response body is `Training Error: <type>: <traceback.format_exc()>`.
- 80 sites pass exception text into `HTTPException.detail` (Appendix C). What that text can contain, by source: Mongo host:port lists (`ServerSelectionTimeoutError`), per-KB vector-store URLs (`qdrant.py:126` wraps the client error), internal service URLs (`AGENT_SERVICE_URL` via `shared/vaulted_secrets.py:218,227`; the ACI base URL via `kb_sync/services/connector_service.py:120`), the first 200 characters of lyzr-agent error bodies (`shared/vaulted_secrets.py:207`, surfaced by `api/v3/credentials/endpoints.py:54,157`, `api/v3/rag/service.py:274`, `api/utils/vlm_credentials.py:179`), upstream LLM error bodies (`LLM call failed: {{e}}` at `api/v3/classify/endpoints.py:83` and `api/v3/extract/endpoints.py:523`), Azure AD `error_description` (`shared/oauth/sharepoint.py:97`).
- No API key on any of these paths: LiteLLM 1.91.5 was probed with a fake Gemini key on the auth-error, unknown-model and timeout paths and the key never appeared in `str(e)`, `repr(e)`, the cause chain or 98 lines of DEBUG output; pymongo, psycopg, qdrant-client, pymilvus, weaviate, neo4j and python-arango error text names hosts and users but not passwords; OpenAI, Azure and Anthropic error bodies do not echo keys.
- Edge: SQLAlchemy raises `ArgumentError("Could not parse SQLAlchemy URL from string '<url>'")` with the full URL, password included, when a customer supplies a malformed Postgres or SingleStore URL; that text would travel through the same `detail=str(e)` sites.

Fix shape: one exception handler that logs the exception server-side with a correlation id and returns a fixed message; drop the `traceback.format_exc()` branch.

### F4. MEDIUM (DEBUG or config dependent): datastore URIs in logs

| Site | Level | What |
|---|---|---|
| `lyzr_rag_sdk/core/vector_store/milvus.py:65` | DEBUG | per-KB Milvus URI; pymilvus accepts `https://user:password@host`, so such a URI is logged with its password. The Zilliz token is a separate field and is not logged (PR #402 removed the config dump). |
| `lyzr_rag_sdk/core/vector_store/qdrant.py:67,86,94` | DEBUG | per-KB Qdrant URL (host; api key separate) |
| `lyzr_rag_sdk/core/vector_store/qdrant.py:125` | ERROR | per-KB Qdrant URL on every connect failure |
| `lyzr_rag_sdk/core/vector_store/graphrag/neo4j_db.py:48` | INFO | `NEO4J` URI from settings; the driver takes auth separately, but a URI written with userinfo would be logged as-is |
| `lyzr_rag_sdk/core/vector_store/graphrag/arangodb_db.py:185` | INFO | Arango host URL (auth separate) |
| `lyzr_rag_sdk/core/vector_store/pg_vector.py:288` / `:343` | DEBUG / ERROR | host, port, db, user, auth mode; password deliberately omitted |

### F5. LOW: response bodies, dumps and PII in logs and stores

- `shared/aci/client.py:110` (ERROR): 500 characters of the ACI error body. `shared/aci/client.py:392` raises with the full ACI JSON body (log-only: the caller has no `detail=str(e)`).
- `lyzr_rag_sdk/lyzr_parse/source_utils/lyzr_parse_reader.py:312,319`: 300 characters of the VLM error response (LiteLLM-masked).
- `api/v3/live_sources/source_auth.py:228` (ERROR): the Graph `/me` body (display name, mail, ids).
- `api/v3/live_sources/consumer/__init__.py:88-98`: the dead-letter record stores `traceback.format_exc()` and 10 KB of the raw message in Redis/SQS/Service Bus; `api/v3/live_sources/queue_backend.py:113,299` log its first 500 characters. The payload is ids and batch numbers (`kb_sync/tasks/publish_to_rag.py:85-89`); the traceback can carry the host disclosures from F3/F4.
- Emails (PII) at INFO/WARNING/ERROR: `api/v3/live_sources/permissions.py:217,219,222,291,343,353`, `api/v3/live_sources/source_auth.py:250`, `kb_sync/connectors/google_drive/connector.py:813,833`.
- Google Drive page tokens at INFO (`kb_sync/connectors/google_drive/file_retrieval.py:321,383,438`, `google_utils.py:131`): opaque cursors, not credentials; noise.

### F6. LOW: uvicorn access log records query strings

`entrypoint.sh:12` runs uvicorn with the default access log, which records the path and query string of every request. Query parameters in use: `redirect_url` (`api/v3/live_sources/source_auth.py:144`), `state` (a 10-minute HS256 JWT, `source_auth.py:70-80`), Graph `validationToken` (`api/v3/live_sources/webhook.py:43`), `source` (`api/v3/rag/endpoints.py:1111`). None is a long-lived credential; `x-api-key` travels in a header and is not logged.

### F7. INFO: the print inventory is clean (details in section 5)

39 of 46 prints are in `scripts/` and print static text, counts, ids, the static provider schema, a Mongo host with the password replaced by `***` (`scripts/seed_*.py`), or a credential document with `api_key: "***"` (`scripts/seed_azure_ai_search_credential.py:86-92`). 6 sit under `if __name__ == "__main__":` in the SharePoint and Google Drive connectors, 1 is `print("ok")` in a demo helper.

## 3. Log-pipeline facts that decide severity

| Fact | Where | Consequence |
|---|---|---|
| Root logger at `LOG_LEVEL` (default INFO) with a stream handler in the API | `app.py:8-11` (`logging.basicConfig`) | every library INFO line is emitted |
| Root logger at `LOG_LEVEL` with a stdout handler in the worker | `kb_sync/utils/logger.py:13-30`; `celery_worker.Dockerfile:87` runs `--loglevel=info` | same in the worker |
| `LOG_LEVEL`, `ALLOW_PRINT`, `LITELLM_LOG` | not set in `.env`, `.github/workflows`, either Dockerfile | DEBUG-only findings are latent until an operator flips one env var |
| `builtins.print` replaced by a no-op before any app import | `api/utils/stdout_guard.py`; `app.py:16-18`; `celery_app/__init__.py:41,124` | prints cannot reach container logs in the API or worker |
| httpx logs `HTTP Request: <method> <full url>` at INFO | silenced only because `litellm/_logging.py:266-267` sets the `httpx` logger to WARNING at import; rag never sets it itself | fragile: if litellm changes or is imported late, every presigned URL and internal URL is logged at INFO. Pin `logging.getLogger("httpx").setLevel(logging.WARNING)` in `app.py` and `kb_sync/utils/logger.py` |
| requests/urllib3, botocore, aiohttp, pymongo request logging | DEBUG only; pymongo redacts auth commands | no INFO exposure |
| LiteLLM | `LiteLLM` logger INFO lines name model and provider; DEBUG curl dumps mask headers and `key=`; rag sets only `drop_params` (`llm.py:95`, `embedding.py:228`) and a usage-only success callback (`embedding.py:72` -> `ops.py:72-116`) | no key in LiteLLM output (probed) |
| Celery | banner and `as_uri()` mask the broker password (verified during the agent-simulation-engine PR #95) | broker URL safe |

## 4. Method and regexes

1. Checkout: `git -C rag fetch origin && git -C rag checkout master && git -C rag pull` -> `2f8f64a`.
2. AST walk (`rag_audit.py`) over every `.py` outside `.venv/` and `tests/`: each `ast.Call` whose callee is `print`, a logger method matching `^(logger|logging|log|self\\.logger|self\\._logger|_logger|LOGGER)\\.(debug|info|warning|warn|error|exception|critical)$`, or a raise/response sink (`HTTPException`, `JSONResponse`, `ValueError`, `RuntimeError`, custom `*Error`), recorded with file, line and the exact source segment (multi-line calls included, which a line regex misses).
3. Subsets (`rag_subsets.py`) over those calls:
   - sensitive-name regex: `(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|authorization|bearer|\\bauth\\b|\\buri\\b|\\burl\\b|dsn|connection[_ ]?str|conn_str|mongo|redis|milvus|qdrant|neo4j|arango|zilliz|presign|signature|x-amz|cookie|private_key|client_secret|access_key|refresh_token|config\\b|settings\\b|headers?\\b|payload|body\\b|\\.env\\b|environ)`
   - exception-text regex: `(\\{{(e|err|exc|ex|error|exception|ex_|e2|inner)(\\b|[\\.\\)\\[:!}}])|str\\((e|err|exc|ex|error|exception)\\)|repr\\((e|err|exc|ex|error)\\)|format_exc\\(\\)|logger\\.exception|exc_info=True|%s|\\{{[a-z_]*err[a-z_]*\\}}|\\{{[a-z_]*detail[a-z_]*\\}}|\\{{[a-z_]*msg[a-z_]*\\}}|\\{{[a-z_]*reason[a-z_]*\\}})`
   - HTTP passthrough = response sink whose source matches the exception-text regex; raised-sensitive = raise sink whose source matches the sensitive-name regex.
4. Sinks the AST pass cannot see: `grep -rnE 'traceback\\.print_exc|print_exception|sys\\.(stderr|stdout)\\.write|click\\.echo|typer\\.echo|rich\\.print|pprint\\(|os\\.write\\('` -> 0 hits.
5. Context reads for every flagged site (the notes in the appendices marked `read`), and the callers of each raised error to see whether it reaches an HTTP `detail`.
6. Empirical probes with fake values only, run with the repo's `.venv`: LiteLLM Gemini auth-error / unknown-model / timeout paths (fake key never in `str(e)`, `repr(e)`, cause chain or DEBUG logs); URL-in-exception-text for httpx, requests and aiohttp (see F2).

Quick re-run for prints: `grep -rnE '(^|[^A-Za-z_.])print\\(' --include='*.py' . | grep -vE '/\\.venv/|/tests/'` (46 hits on this commit; it cannot see aliased or `builtins.print` calls, the AST pass can).

Inventory counts on `2f8f64a`:

| Set | Count |
|---|---|
| `print(` calls | {len(prints)} |
| logger calls | {len(logs)} ({fmt(lvl)}) |
| raise/response sinks | {len(sinks)} (top: {", ".join(f"{k} {v}" for k, v in sinkc.most_common(6))}) |
| logger calls naming a sensitive thing (Appendix A) | {len(sens_log)} |
| logger calls embedding exception text (Appendix B) | {len(exc_log)} |
| HTTP responses passing exception text (Appendix C) | {len(http_pass)} |
| raised errors naming a credential/URL/config (Appendix D) | {len(raised_sens)} |

Verdict totals: prints {fmt(pc)}; Appendix A {fmt(sc)}; Appendix B {fmt(ec)}; Appendix C {fmt(hc)}; Appendix D {fmt(rc)}.

## 5. Print inventory ({len(prints)})

`print` is a no-op in the API and the worker (section 3), so every row below only runs when an operator invokes the script or module directly.

{table(prints, lambda r: print_verdict(r) + ("read",), "file group", "file")}

## 6. Appendix A: logger calls that name a sensitive thing ({len(sens_log)})

Matched by the sensitive-name regex. `basis` = `read` when the site was read in context, `rule` when the verdict comes from the rules in `rag_report.py`.

{table(sens_log, sens_verdict, "level", "level")}

## 7. Appendix B: logger calls that embed exception text ({len(exc_log)})

Class = the source of `e` on that code path (by module), which decides what the text can contain:

| Class | Rows | What the exception text can carry |
|---|---|---|
""" + "\n".join(f"| {c} | {exc_by_class.get(c,0)} | {cell(desc)} |" for c, _, desc in EXC_CLASSES) + f"""
| H | {exc_by_class.get('H',0)} | {EXC_H} |

{table(exc_log, exc_verdict, "level / class", "level", with_class=exc_class)}

## 8. Appendix C: HTTP responses that pass exception text to the client ({len(http_pass)})

{table(http_pass, http_verdict, "call", "call")}

Responses that mention a credential but embed no exception text ({len(http_sens)}) were reviewed and carry only fixed messages, ids and one `sign_in_url`; they are not listed.

## 9. Appendix D: raised errors that name a credential, URL or config ({len(raised_sens)})

Raised errors reach the client only through the sites in Appendix C or a `detail=str(e)` in their caller; otherwise FastAPI answers `Internal Server Error` and the text is log-only.

{table(raised_sens, raised_verdict, "call", "call")}

## 10. Appendix E: non-log sinks

| Sink | Where | Content | Verdict |
|---|---|---|---|
| `live_sources` Mongo document | `api/v3/live_sources/service.py:20-28` | `connector_specific_config` incl. `crawler_api_key` (owner's API key) for website sources | **LEAK** (F1) |
| kb_sync `connectors` Mongo document | `kb_sync/services/connector_service.py:36-42` | same config | **LEAK** (F1) |
| `LiveSourceResponse` (create + list) | `api/v3/live_sources/endpoints.py:343-350, 380-392` | same config, returned to owner, policy-shared users, sharing-group readers | **LEAK** (F1) |
| Dead-letter record | `api/v3/live_sources/consumer/__init__.py:88-98` -> Redis/SQS/Service Bus | error text, full traceback, 10 KB raw message | DISCLOSURE (F5) |
| 500 body with traceback | `api/v3/rag/endpoints.py:924-927` | `traceback.format_exc()` | DISCLOSURE (F3) |
| LiteLLM success callback | `lyzr_rag_sdk/core/embedding.py:72` -> `ops.py:72-116` | usage metadata (ids, tokens, cost); the append is commented out | SAFE |
| uvicorn access log | `entrypoint.sh:12` | path + query string (`redirect_url`, `state` JWT, `validationToken`) | LOW (F6) |
| Seed script stdout | `scripts/seed_*.py` | Mongo host with `***` password, provider schema, credential doc with `***` key | CLI, SAFE |

## 11. Recommendations, in order

1. F1: stop storing the owner's API key in `connector_specific_config`; reference a credential id or a vaulted secret and resolve it in the worker. Strip `crawler_api_key` from `LiveSourceResponse` and from existing documents (migration). Delete the DEBUG dump at `kb_sync/tasks/docfetching.py:195` or log key names. Rotate the keys of every user who has created a website live source, since they sit in Mongo today.
2. F2: route every `file_url` log through `_log_safe_source`; replace `exc_info=True` / `logger.exception` on the two fetch paths with the status code and exception type. Add a logging `Filter` on the root logger that masks `X-Amz-Signature=`, `sig=`, `key=` and `tempauth=` query values as a backstop.
3. Pin `logging.getLogger("httpx").setLevel(logging.WARNING)` in `app.py` and `kb_sync/utils/logger.py` so the INFO request lines do not depend on litellm's import-time side effect.
4. F3: a single exception handler that returns a fixed message plus a correlation id and logs the detail server-side; remove the `traceback.format_exc()` branch at `api/v3/rag/endpoints.py:924-927`.
5. F4: log vector-store hosts through a helper that strips userinfo (`urlsplit(...).hostname`), and never at ERROR on connect failures.
6. F5: trim the ACI/VLM/Graph body excerpts to a status code and error code; redact emails with `_redact_user_id`-style hashing where they are not needed.
7. Keep `stdout_guard` and the `print` ban in CI (a `ruff` `T201` rule would make the 46 rows fail lint outside `scripts/`).
"""

open(OUT, "w").write(MD)
print("wrote", OUT, len(MD), "chars")
print("verdict totals:", "prints", dict(pc), "A", dict(sc), "B", dict(ec), "C", dict(hc), "D", dict(rc))
