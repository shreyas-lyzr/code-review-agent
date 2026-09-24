import json, re, os, collections
S = os.environ["S"]
d = json.load(open(f"{S}/rag_audit.json"))
SENS = re.compile(r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|authorization|bearer|\bauth\b|\buri\b|\burl\b|dsn|connection[_ ]?str|conn_str|mongo|redis|milvus|qdrant|neo4j|arango|zilliz|presign|signature|x-amz|cookie|private_key|client_secret|access_key|refresh_token|config\b|settings\b|headers?\b|payload|body\b|\.env\b|environ)")
EXC = re.compile(r"(\{(e|err|exc|ex|error|exception|ex_|e2|inner)(\b|[\.\)\[:!}])|str\((e|err|exc|ex|error|exception)\)|repr\((e|err|exc|ex|error)\)|format_exc\(\)|logger\.exception|exc_info=True|%s|\{[a-z_]*err[a-z_]*\}|\{[a-z_]*detail[a-z_]*\}|\{[a-z_]*msg[a-z_]*\}|\{[a-z_]*reason[a-z_]*\})")
def is_http(c): return c in {"HTTPException","JSONResponse","Response","PlainTextResponse","HTTPError","StreamingResponse"}
def is_raise(c): return not is_http(c)
prints = d["print"]; logs = d["logger"]; sinks = d["sinks"]
print("sink call distribution:", collections.Counter(s["call"] for s in sinks).most_common(25))
sens_log = [l for l in logs if SENS.search(l["src"])]
exc_log = [l for l in logs if EXC.search(l["src"])]
http_pass = [s for s in sinks if is_http(s["call"]) and EXC.search(s["src"])]
raised_sens = [s for s in sinks if is_raise(s["call"]) and SENS.search(s["src"])]
http_sens = [s for s in sinks if is_http(s["call"]) and SENS.search(s["src"]) and s not in http_pass]
print("prints", len(prints), "logger", len(logs), "sinks", len(sinks))
print("sens_log", len(sens_log), "exc_log", len(exc_log), "http_pass", len(http_pass), "raised_sens", len(raised_sens), "http_sens_nonexc", len(http_sens))
print("levels among exc_log:", collections.Counter(l["level"] for l in exc_log))
print("levels among sens_log:", collections.Counter(l["level"] for l in sens_log))
def dump(name, rows, extra):
    with open(f"{S}/{name}.txt","w") as f:
        for r in rows:
            src = " ".join(r["src"].split())
            f.write(f'{r["file"]}:{r["line"]} [{r.get(extra,"")}] {src[:170]}\n')
dump("sens_log", sens_log, "level"); dump("exc_log", exc_log, "level"); dump("http_pass", http_pass, "call"); dump("raised_sens", raised_sens, "call"); dump("http_sens", http_sens, "call"); dump("prints", prints, "line")
json.dump({"sens_log":sens_log,"exc_log":exc_log,"http_pass":http_pass,"raised_sens":raised_sens,"http_sens":http_sens}, open(f"{S}/rag_subsets.json","w"), indent=1)
print("files by print count:", collections.Counter(p["file"] for p in prints).most_common())
