from pathlib import Path
import base64, datetime, json, re, socket, urllib.parse, urllib.request, ssl

ROOT = Path(__file__).resolve().parents[1]
CFG = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML unavailable")

UA = "Crove-Free-Nodes/1.2"
SOURCE_TIMEOUT = 20
SOCKET_TIMEOUT = 4
MAX_NODES = 300
MAX_SOURCE_BYTES = 8 * 1024 * 1024
SCHEMES = ("ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "socks5://", "http://")

def fetch(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/plain,text/yaml,application/yaml,application/json,*/*",
        "Cache-Control": "no-cache",
    })
    context = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=SOURCE_TIMEOUT, context=context) as r:
        data = r.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("source too large")
        return data.decode("utf-8", "replace").strip()

def b64decode_text(s):
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 8 or len(compact) % 4 == 1:
        return ""
    for decoder in (
        lambda x: base64.b64decode(x + "=" * (-len(x) % 4), validate=False),
        lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)),
    ):
        try:
            out = decoder(compact).decode("utf-8", "ignore")
            if any(s in out.lower() for s in SCHEMES):
                return out
        except Exception:
            pass
    return ""

def yaml_proxies(raw):
    try:
        obj = yaml.safe_load(raw)
    except Exception:
        return []
    if not isinstance(obj, dict):
        return []
    found = []
    # Normal Clash config
    if isinstance(obj.get("proxies"), list):
        found.extend(p for p in obj["proxies"] if isinstance(p, dict))
    # Provider/config nesting seen in some public feeds
    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "proxies" and isinstance(x, list):
                    for p in x:
                        if isinstance(p, dict) and p not in found:
                            found.append(p)
                else:
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(obj)
    return found

def uri_lines(raw):
    texts = [raw]
    dec = b64decode_text(raw)
    if dec:
        texts.append(dec)
    out = []
    # Handles URI feeds embedded in markdown/HTML-ish text.
    pattern = re.compile(r"(?:https?://|)(?:" + "|".join(re.escape(s) for s in SCHEMES) + r")[^\s<>'\"`]+")
    for text in texts:
        for m in pattern.findall(text):
            u = m.rstrip("),]}，。；;")
            if u.lower().startswith(SCHEMES):
                out.append(u)
    return list(dict.fromkeys(out))

def safe_int(v, default=0):
    try:
        return int(str(v).strip())
    except Exception:
        return default

def parse_uri(u):
    try:
        scheme = u.split(":", 1)[0].lower()
        if scheme == "vmess":
            payload = u[8:]
            raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", "ignore")
            o = json.loads(raw)
            p = {
                "name": o.get("ps") or "VMess",
                "type": "vmess", "server": o.get("add"), "port": safe_int(o.get("port")),
                "uuid": o.get("id"), "alterId": safe_int(o.get("aid"), 0),
                "cipher": o.get("scy") or "auto",
            }
            net = o.get("net") or "tcp"
            if net: p["network"] = net
            if o.get("tls"): p["tls"] = True
            if o.get("host"): p["ws-opts"] = {"headers": {"Host": o["host"]}}
            if o.get("path"): p.setdefault("ws-opts", {})["path"] = o["path"]
            if o.get("sni"): p["servername"] = o["sni"]
            return p

        p = urllib.parse.urlsplit(u)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        name = urllib.parse.unquote(p.fragment) or p.hostname or scheme
        if scheme == "trojan":
            return {"name": name, "type":"trojan", "server":p.hostname, "port":p.port or 443,
                    "password":urllib.parse.unquote(p.username or ""), "sni":(q.get("sni") or [p.hostname])[0],
                    **({"skip-cert-verify": True} if (q.get("allowInsecure") or [""])[0].lower()=="true" else {})}
        if scheme == "vless":
            net=(q.get("type") or ["tcp"])[0]
            out={"name":name,"type":"vless","server":p.hostname,"port":p.port or 443,
                 "uuid":urllib.parse.unquote(p.username or ""),"network":net}
            sec=(q.get("security") or [""])[0]
            if sec=="tls": out["tls"]=True
            if q.get("sni"): out["servername"]=q["sni"][0]
            if q.get("flow"): out["flow"]=q["flow"][0]
            if net=="ws":
                out["ws-opts"]={"path":(q.get("path") or ["/"])[0]}
                if q.get("host"): out["ws-opts"]["headers"]={"Host":q["host"][0]}
            return out
        if scheme == "ss":
            payload = p.netloc
            if "@" not in payload:
                payload = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8","ignore")
            userinfo, hostpart = payload.rsplit("@",1)
            method,password=userinfo.split(":",1)
            host,port=hostpart.rsplit(":",1)
            return {"name":name,"type":"ss","server":host.strip("[]"),"port":int(port),"cipher":method,"password":password}
        if scheme in ("socks5","http"):
            return {"name":name,"type":scheme,"server":p.hostname,"port":p.port or (1080 if scheme=="socks5" else 80),
                    **({"username":urllib.parse.unquote(p.username)} if p.username else {}),
                    **({"password":urllib.parse.unquote(p.password)} if p.password else {})}
        if scheme in ("hysteria2","hy2"):
            return {"name":name,"type":"hysteria2","server":p.hostname,"port":p.port or 443,
                    "password":urllib.parse.unquote(p.username or ""),
                    **({"sni":q["sni"][0]} if q.get("sni") else {})}
        if scheme == "hysteria":
            return {"name":name,"type":"hysteria","server":p.hostname,"port":p.port or 443,
                    "password":urllib.parse.unquote(p.username or "")}
        if scheme == "tuic":
            return {"name":name,"type":"tuic","server":p.hostname,"port":p.port or 443,
                    "uuid":urllib.parse.unquote(p.username or ""), "password":urllib.parse.unquote(p.password or "")}
    except Exception:
        return None
    return None

def valid_proxy(p):
    if not isinstance(p, dict): return False
    typ=str(p.get("type","")).lower()
    if not p.get("server") or typ not in {"ss","vmess","vless","trojan","hysteria","hysteria2","tuic","socks5","http"}:
        return False
    port=safe_int(p.get("port"))
    return 1 <= port <= 65535

def tcp_ok(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=SOCKET_TIMEOUT):
            return True
    except Exception:
        return False

def node_key(p):
    ident=p.get("uuid") or p.get("password") or p.get("username") or ""
    return (str(p.get("type","")).lower(), str(p.get("server","")).lower(), safe_int(p.get("port")), str(ident))

candidates=[]
stats=[]
for item in CFG.get("sources",[]):
    url=item if isinstance(item,str) else item.get("url")
    name=item if isinstance(item,str) else item.get("name",url)
    if not url: continue
    try:
        raw=fetch(url)
        parsed=yaml_proxies(raw)
        uri_count=0
        if not parsed:
            for u in uri_lines(raw):
                p=parse_uri(u)
                if p:
                    parsed.append(p)
                    uri_count += 1
        valid=[p for p in parsed if valid_proxy(p)]
        candidates.extend(valid)
        stats.append({"name":name,"url":url,"fetched":True,"bytes":len(raw.encode()),"parsed":len(parsed),"valid":len(valid),"uri_parsed":uri_count})
    except Exception as e:
        stats.append({"name":name,"url":url,"fetched":False,"parsed":0,"valid":0,"error":f"{type(e).__name__}: {str(e)[:120]}"})

unique=[]
seen=set()
tested=0
alive=0
for p in candidates:
    k=node_key(p)
    if k in seen: continue
    seen.add(k)
    tested += 1
    p["port"]=safe_int(p["port"])
    if tcp_ok(p["server"],p["port"]):
        alive += 1
        unique.append(p)
        if len(unique)>=MAX_NODES: break

# Never replace a previously working feed with an empty one.
# This makes temporary source/network failures non-destructive.
if not unique:
    debug = {
        "version": "1.2",
        "nodes": 0,
        "candidates": len(candidates),
        "unique_candidates": len(seen),
        "candidates_tested": tested,
        "nodes_alive": 0,
        "sources": stats,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "test": "TCP connect only; no proxy application traffic was sent",
        "error": "No candidate passed TCP connectivity. Existing feed files were preserved."
    }
    (ROOT/"status.json").write_text(json.dumps(debug, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT/"debug.json").write_text(json.dumps(debug, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(debug, ensure_ascii=False, indent=2))
    raise SystemExit(2)

# Avoid invalid YAML structures from odd source fields.
for i,p in enumerate(unique,1):
    p["name"]=(str(p.get("name") or f"node-{i}"))[:80]

out={"mixed-port":7890,"allow-lan":False,"mode":"rule","proxies":unique}
if unique:
    out["proxy-groups"]=[{"name":"Auto","type":"url-test","proxies":[p["name"] for p in unique],
                          "url":"https://www.gstatic.com/generate_204","interval":300}]
    out["rules"]=["MATCH,Auto"]
else:
    out["rules"]=["MATCH,DIRECT"]
(ROOT/"clash.yaml").write_text(yaml.safe_dump(out,allow_unicode=True,sort_keys=False),encoding="utf-8")

def to_uri(p):
    typ=str(p.get("type","")).lower()
    name=urllib.parse.quote(str(p.get("name","node")))
    if typ=="ss" and p.get("cipher") and p.get("password"):
        payload=f'{p["cipher"]}:{p["password"]}@{p["server"]}:{p["port"]}'
        enc=base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        return "ss://"+enc+"#"+name
    if typ=="trojan" and p.get("password"):
        q={"sni":p.get("sni") or p["server"]}
        if p.get("skip-cert-verify"): q["allowInsecure"]="true"
        return f'trojan://{urllib.parse.quote(str(p["password"]))}@{p["server"]}:{p["port"]}?{urllib.parse.urlencode(q)}#{name}'
    if typ=="vless" and p.get("uuid"):
        q={"type":p.get("network","tcp")}
        if p.get("tls"): q["security"]="tls"
        if p.get("servername"): q["sni"]=p["servername"]
        if p.get("flow"): q["flow"]=p["flow"]
        wo=p.get("ws-opts") or {}
        if q["type"]=="ws":
            q["path"]=wo.get("path","/")
            h=(wo.get("headers") or {}).get("Host")
            if h: q["host"]=h
        return f'vless://{urllib.parse.quote(str(p["uuid"]))}@{p["server"]}:{p["port"]}?{urllib.parse.urlencode(q)}#{name}'
    if typ=="vmess" and p.get("uuid"):
        o={"v":"2","ps":p.get("name","VMess"),"add":p["server"],"port":str(p["port"]),
           "id":p["uuid"],"aid":str(p.get("alterId",0)),"scy":p.get("cipher","auto"),
           "net":p.get("network","tcp"),"type":"none","host":"","path":""}
        if p.get("tls"): o["tls"]="tls"
        wo=p.get("ws-opts") or {}
        o["path"]=wo.get("path","")
        o["host"]=(wo.get("headers") or {}).get("Host","")
        if p.get("servername"): o["sni"]=p["servername"]
        enc=base64.urlsafe_b64encode(json.dumps(o,separators=(",",":")).encode()).decode().rstrip("=")
        return "vmess://"+enc
    return None

uris=[u for p in unique if (u:=to_uri(p))]
(ROOT/"shadowrocket.txt").write_text("\n".join(uris)+"\n" if uris else "",encoding="utf-8")
(ROOT/"base64.txt").write_text(base64.b64encode("\n".join(uris).encode()).decode(),encoding="utf-8")

status={
    "version":"1.2","nodes":len(unique),"candidates":len(candidates),
    "unique_candidates":len(seen),"candidates_tested":tested,"nodes_alive":alive,
    "sources":stats,"updated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "test":"TCP connect only; no proxy application traffic was sent"
}
(ROOT/"status.json").write_text(json.dumps(status,ensure_ascii=False,indent=2),encoding="utf-8")
(ROOT/"debug.json").write_text(json.dumps(status,ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps(status,ensure_ascii=False,indent=2))
