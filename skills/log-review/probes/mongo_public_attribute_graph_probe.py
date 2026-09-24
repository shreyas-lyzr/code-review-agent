# Fake values only. BFS over PUBLIC (underscore-free) attributes, the only ones the AST screen lets analysis code touch.
# Question: can generated code reach the customer's Mongo password from the `db` handle, or AWS secrets from `dynamodb`?
import pymongo, collections, inspect
PW = "FAKEPW_9f8e7d"
client = pymongo.MongoClient(host="localhost", port=27017, username="fakeuser", password=PW, connect=False, serverSelectionTimeoutMS=10)
db = client["db"]
def bfs(root, needle, max_depth=5, max_nodes=4000):
    seen = set(); q = collections.deque([(root, "db", 0)]); hits = []; n = 0
    while q and n < max_nodes:
        obj, path, d = q.popleft(); n += 1
        try:
            r = repr(obj)
        except Exception:
            r = ""
        if needle in r: hits.append(path)
        if d >= max_depth or isinstance(obj, (str, bytes, int, float, bool, type(None))): continue
        if isinstance(obj, dict):
            for k, v in list(obj.items())[:50]:
                if id(v) not in seen: seen.add(id(v)); q.append((v, f"{path}[{k!r}]", d + 1))
            continue
        if isinstance(obj, (list, tuple, set, frozenset)):
            for i, v in enumerate(list(obj)[:50]):
                if id(v) not in seen: seen.add(id(v)); q.append((v, f"{path}[{i}]", d + 1))
            continue
        cls = type(obj)
        for name in dir(cls):
            if name.startswith("_"): continue
            try:
                attr = inspect.getattr_static(cls, name)
            except Exception:
                continue
            if inspect.isfunction(attr) or inspect.ismethoddescriptor(attr) or inspect.isbuiltin(attr): continue  # methods need args; properties/data only
            try:
                v = getattr(obj, name)
            except Exception:
                continue
            if callable(v) and not isinstance(v, type): continue
            if id(v) not in seen: seen.add(id(v)); q.append((v, f"{path}.{name}", d + 1))
    return hits, n
hits, n = bfs(db, PW)
print("pymongo", pymongo.__version__, "| nodes visited:", n, "| public attribute paths whose repr contains the password:", hits[:10] or "NONE")
# Common direct guesses
for expr in ["client.options", "db.client", "getattr(client.options, 'credentials', None)"]:
    try:
        val = eval(expr); print(expr, "-> repr has pw:", PW in repr(val))
    except Exception as e:
        print(expr, "->", type(e).__name__)
