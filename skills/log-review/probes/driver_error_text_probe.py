# Fake values only. Do driver/URL errors echo a password?
PW = "FAKEPW_9f8e7d"
from sqlalchemy.engine import make_url
for pw in [PW, "a@b" + PW, "a:b" + PW, "a/b" + PW, "a?b" + PW]:
    try:
        u = make_url("postgresql://user:" + pw + "@host:5432/db")
        print("make_url pw=%-16r -> host=%r port=%r db=%r password_ok=%s repr_has_pw=%s" % (pw[:12], u.host, u.port, u.database, u.password == pw, PW in repr(u)))
    except Exception as e:
        print("make_url pw=%-16r -> %s: pw in text=%s" % (pw[:12], type(e).__name__, PW in str(e)))
import psycopg
from psycopg.conninfo import make_conninfo
try:
    ci = make_conninfo(host="127.0.0.1", port=9, user="u", password=PW, dbname="db")
    print("make_conninfo ok; contains raw pw (expected, it is the DSN):", PW in ci)
    psycopg.connect(ci, connect_timeout=2)
except Exception as e:
    print("psycopg connect error:", type(e).__name__, "| pw in text:", PW in str(e), "| text:", str(e)[:90].replace(PW, "<pw>"))
try:
    psycopg.connect("host=127.0.0.1 port=9 user=u password=" + PW + " dbname=db extra=bad", connect_timeout=2)
except Exception as e:
    print("psycopg bad-conninfo error:", type(e).__name__, "| pw in text:", PW in str(e), "| text:", str(e)[:100].replace(PW, "<pw>"))
import oracledb
try:
    oracledb.connect(user="u", password=PW, dsn="127.0.0.1:9/svc", tcp_connect_timeout=2)
except Exception as e:
    print("oracledb connect error:", type(e).__name__, "| pw in text:", PW in str(e), "| text:", str(e)[:90].replace(PW, "<pw>"))
