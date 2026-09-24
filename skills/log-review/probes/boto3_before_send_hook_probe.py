import boto3
from botocore.awsrequest import AWSResponse
AK, SK, ST = "AKIAFAKEFAKEFAKEFAKE", "FAKESECRET_1234567890abcdef", "FAKESESSIONTOKEN_xyz"
res = boto3.resource("dynamodb", region_name="us-east-1", aws_access_key_id=AK, aws_secret_access_key=SK, aws_session_token=ST)
seen = {}
class Raw:
    def __init__(self, b): self.b = b
    def stream(self, **kw): yield self.b
def hook(request, **kw):
    seen.update(dict(request.headers.items()))
    return AWSResponse(request.url, 200, {"content-type": "application/x-amz-json-1.0"}, Raw(b'{"TableNames":[]}'))
res.meta.client.meta.events.register("before-send.dynamodb.*", hook)   # dynamodb.meta.client.meta.events.register: no underscore segment
res.meta.client.list_tables(Limit=1)
auth = seen.get("Authorization", b""); auth = auth.decode() if isinstance(auth, bytes) else auth; tok = seen.get("X-Amz-Security-Token", b""); tok = tok.decode() if isinstance(tok, bytes) else tok
print("boto3", boto3.__version__, "| hook saw Authorization:", bool(auth), "| access key id in it:", AK in auth, "| secret key in it:", SK in auth, "| X-Amz-Security-Token equals session token:", tok == ST)
