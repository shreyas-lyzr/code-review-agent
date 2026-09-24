"""IN=<inventory json> PFX=<output prefix> python audit_subsets.py"""
import json, re, os, collections
IN = os.environ["IN"]; PFX = os.environ["PFX"]
d = json.load(open(IN))
SENS = re.compile(r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|authorization|bearer|\bauth\b|\buri\b|\burl\b|dsn|connection[_ ]?str|conn_str|mongo|redis|milvus|qdrant|neo4j|arango|zilliz|presign|signature|x-amz|cookie|private_key|client_secret|access_key|refresh_token|config\b|settings\b|headers?\b|payload|body\b|\.env\b|environ|conn\b|engine|database_url|db_url|host)")
EXC = re.compile(r"(\{(e|err|exc|ex|error|exception|ex_|e2|inner)(\b|[\.\)\[:!}])|str\((e|err|exc|ex|error|exception)\)|repr\((e|err|exc|ex|error)\)|format_exc\(\)|logger\.exception|exc_info=True|%s|\{[a-z_]*err[a-z_]*\}|\{[a-z_]*detail[a-z_]*\}|\{[a-z_]*msg[a-z_]*\}|\{[a-z_]*reason[a-z_]*\})")
HTTP = {"HTTPException", "JSONResponse", "Response", "PlainTextResponse", "StreamingResponse"}
def is_http(c): return c.split(".")[-1] in HTTP
prints, logs, sinks = d["print"], d["logger"], d["sinks"]
sens_log = [l for l in logs if SENS.search(l["src"])]
exc_log = [l for l in logs if EXC.search(l["src"])]
http_pass = [s for s in sinks if is_http(s["call"]) and EXC.search(s["src"])]
http_sens = [s for s in sinks if is_http(s["call"]) and SENS.search(s["src"]) and s not in http_pass]
raised_sens = [s for s in sinks if not is_http(s["call"]) and SENS.search(s["src"])]
raised_exc = [s for s in sinks if not is_http(s["call"]) and EXC.search(s["src"]) and s not in raised_sens]
print("sink calls:", collections.Counter(s["call"] for s in sinks).most_common(20))
print("levels:", collections.Counter(l["level"] for l in logs))
print("prints", len(prints), "logger", len(logs), "sinks", len(sinks), "| sens_log", len(sens_log), "exc_log", len(exc_log), "http_pass", len(http_pass), "http_sens", len(http_sens), "raised_sens", len(raised_sens), "raised_exc", len(raised_exc))
def dump(name, rows, extra):
    with open(f"{PFX}_{name}.txt", "w") as f:
        for r in sorted(rows, key=lambda r: (r["file"], r["line"])):
            f.write(f'{r["file"]}:{r["line"]} [{r.get(extra, "")}] {" ".join(r["src"].split())[:200]}\n')
for name, rows, extra in [("prints", prints, "call"), ("sens_log", sens_log, "level"), ("exc_log", exc_log, "level"), ("http_pass", http_pass, "call"), ("http_sens", http_sens, "call"), ("raised_sens", raised_sens, "call"), ("raised_exc", raised_exc, "call"), ("all_log", logs, "level")]:
    dump(name, rows, extra)
json.dump({"sens_log": sens_log, "exc_log": exc_log, "http_pass": http_pass, "http_sens": http_sens, "raised_sens": raised_sens, "raised_exc": raised_exc}, open(f"{PFX}_subsets.json", "w"), indent=1)
print("prints by file:", collections.Counter(p["file"] for p in prints).most_common())
