# Probe 2: unknown model (NOT_FOUND path) and a near-zero timeout, fake key only. Booleans only.
import litellm, logging, io
FAKE = "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"
litellm.suppress_debug_info = True
buf = io.StringIO(); h = logging.StreamHandler(buf); h.setLevel(logging.DEBUG)
root = logging.getLogger(); root.setLevel(logging.DEBUG); root.addHandler(h)
for label, kw in [("not_found_model", dict(model="gemini/gemini-does-not-exist-9", timeout=20)), ("timeout", dict(model="gemini/gemini-2.0-flash", timeout=0.0005))]:
    try:
        litellm.completion(messages=[{"role": "user", "content": "hi"}], api_key=FAKE, num_retries=0, **kw)
        print(label, "-> no exception")
    except Exception as e:
        s = str(e); print(label, "->", type(e).__name__, "| fake key in str(e):", FAKE in s, "| 'key=' in str(e):", "key=" in s, "| key in repr:", FAKE in repr(e), "| key in __cause__/__context__:", any(FAKE in str(x) for x in (e.__cause__, e.__context__) if x))
logs = buf.getvalue()
print("DEBUG-level root log: fake key present:", FAKE in logs, "| 'key=' present:", "key=" in logs, "| lines:", logs.count("\n"))
import re; print("masked forms seen:", sorted(set(re.findall(r'key=\*+[A-Za-z0-9]{0,4}', logs)))[:3])
print("httpx logger level after litellm import:", logging.getLogger("httpx").level, "httpcore:", logging.getLogger("httpcore").level)
