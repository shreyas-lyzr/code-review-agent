# Do the HTTP clients used by rag put the full URL (query string included) into exception text?
# Uses a local dummy URL with a fake signature; nothing is sent to a real host.
import httpx, requests, asyncio
U = "https://127.0.0.1:9/bucket/key.pdf?X-Amz-Signature=FAKESIG123&X-Amz-Credential=FAKECRED"
req = httpx.Request("GET", U); resp = httpx.Response(403, request=req)
try:
    resp.raise_for_status()
except httpx.HTTPStatusError as e:
    print("httpx.HTTPStatusError str contains query:", "FAKESIG123" in str(e))
try:
    httpx.get(U, timeout=0.5)
except Exception as e:
    print("httpx connect error type:", type(e).__name__, "| contains query:", "FAKESIG123" in str(e))
r = requests.Response(); r.status_code = 403; r.url = U; r.reason = "Forbidden"
try:
    r.raise_for_status()
except requests.HTTPError as e:
    print("requests.HTTPError str contains query:", "FAKESIG123" in str(e))
try:
    requests.get(U, timeout=0.5)
except Exception as e:
    print("requests connect error type:", type(e).__name__, "| contains query:", "FAKESIG123" in str(e))
try:
    import aiohttp
    async def go():
        async with aiohttp.ClientSession() as s:
            async with s.get(U, timeout=aiohttp.ClientTimeout(total=0.5)) as resp:
                resp.raise_for_status()
    try:
        asyncio.run(go())
    except Exception as e:
        print("aiohttp error type:", type(e).__name__, "| contains query:", "FAKESIG123" in str(e))
except ImportError:
    print("aiohttp not installed")
