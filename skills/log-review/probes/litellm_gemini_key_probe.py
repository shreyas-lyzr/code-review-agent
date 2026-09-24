# Probe: does a failed Gemini call through the installed LiteLLM put the api key
# (here a FAKE, non-working value) into the exception text? Prints booleans only.
import litellm, logging, io
FAKE = "AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"
litellm.suppress_debug_info = True
buf = io.StringIO()
h = logging.StreamHandler(buf); h.setLevel(logging.DEBUG)
root = logging.getLogger(); root.setLevel(logging.INFO); root.addHandler(h)
try:
    litellm.completion(model="gemini/gemini-2.0-flash", messages=[{"role": "user", "content": "hi"}], api_key=FAKE, timeout=20, num_retries=0)
    print("no exception raised")
except Exception as e:
    s = str(e)
    print("litellm version:", litellm.__version__ if hasattr(litellm, "__version__") else "?")
    print("exception type:", type(e).__name__)
    print("fake key in str(e):", FAKE in s)
    print("'key=' substring in str(e):", "key=" in s)
    print("len(str(e)):", len(s))
    print("fake key in repr(e):", FAKE in repr(e))
logs = buf.getvalue()
print("root-INFO log lines captured:", logs.count("\n"))
print("fake key in root INFO/DEBUG logs:", FAKE in logs)
print("httpx 'HTTP Request' line present:", "HTTP Request:" in logs)
import re
print("logged URLs (query masked):", sorted(set(re.sub(r'key=[^ "&]+', 'key=<masked>', m) for m in re.findall(r'https://generativelanguage[^ "\n]*', logs)))[:3])
