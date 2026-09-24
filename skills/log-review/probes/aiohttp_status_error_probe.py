import aiohttp, yarl
U = "https://127.0.0.1:9/bucket/key.pdf?X-Amz-Signature=FAKESIG123"
ri = aiohttp.RequestInfo(url=yarl.URL(U), method="GET", headers={}, real_url=yarl.URL(U))
e = aiohttp.ClientResponseError(ri, (), status=403, message="Forbidden")
print("aiohttp.ClientResponseError str contains query:", "FAKESIG123" in str(e), "| aiohttp", aiohttp.__version__)
