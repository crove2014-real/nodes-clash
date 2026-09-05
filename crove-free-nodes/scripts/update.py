from pathlib import Path
import base64, datetime, json, re, socket, urllib.parse, urllib.request

ROOT = Path(__file__).resolve().parents[1]
CFG = json.loads((ROOT / 'sources.json').read_text(encoding='utf-8'))

try:
    import yaml
except ImportError:
    raise SystemExit('PyYAML unavailable')

UA = 'Crove-Free-Nodes/1.1'
TIMEOUT = 5
MAX_NODES = 300


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode('utf-8', 'ignore').strip()


def decode_b64(s):
    s = re.sub(r'\s+', '', s)
    try:
        return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'ignore')
    except Exception:
        return ''


def clash_nodes(raw):
    try:
        obj = yaml.safe_load(raw)
        if isinstance(obj, dict) and isinstance(obj.get('proxies'), list):
            return [p for p in obj['proxies'] if isinstance(p, dict)]
    except Exception:
        pass
    return []


def uri_nodes(raw):
    lines = raw.splitlines()
    decoded = decode_b64(raw)
    if decoded and any(x in decoded for x in ('ss://', 'vmess://', 'vless://', 'trojan://')):
        lines += decoded.splitlines()
    return [x.strip() for x in lines if x.strip().lower().startswith(('ss://','vmess://','vless://','trojan://'))]


def parse_uri(u):
    try:
        if u.startswith('vmess://'):
            obj = json.loads(base64.urlsafe_b64decode(u[8:] + '=' * (-len(u[8:]) % 4)).decode())
            return {'name': obj.get('ps') or 'VMess', 'type': 'vmess', 'server': obj['add'], 'port': int(obj['port']),
                    'uuid': obj['id'], 'alterId': int(obj.get('aid', 0)), 'cipher': 'auto',
                    **({'tls': True} if obj.get('tls') else {}),
                    **({'network': obj.get('net')} if obj.get('net') else {})}
        p = urllib.parse.urlsplit(u)
        q = urllib.parse.parse_qs(p.query)
        name = urllib.parse.unquote(p.fragment) or p.hostname or p.scheme
        if p.scheme == 'trojan':
            return {'name': name, 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443,
                    'password': urllib.parse.unquote(p.username or ''), 'sni': (q.get('sni') or [p.hostname])[0]}
        if p.scheme == 'vless':
            out = {'name': name, 'type': 'vless', 'server': p.hostname, 'port': p.port or 443,
                   'uuid': urllib.parse.unquote(p.username or ''), 'network': (q.get('type') or ['tcp'])[0]}
            if (q.get('security') or [''])[0] == 'tls': out['tls'] = True
            if q.get('sni'): out['servername'] = q['sni'][0]
            if q.get('flow'): out['flow'] = q['flow'][0]
            return out
        if p.scheme == 'ss':
            payload = p.netloc
            if '@' not in payload:
                payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)).decode('utf-8', 'ignore')
            userinfo, hostpart = payload.rsplit('@', 1)
            method, password = userinfo.split(':', 1)
            host, port = hostpart.rsplit(':', 1)
            return {'name': name, 'type': 'ss', 'server': host.strip('[]'), 'port': int(port), 'cipher': method, 'password': password}
    except Exception:
        return None
    return None


def valid_shape(p):
    try:
        return bool(p.get('name') and p.get('type') and p.get('server') and int(p.get('port')) > 0)
    except Exception:
        return False


def tcp_ok(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            return True
    except Exception:
        return False

nodes = []
source_stats = []
for src in CFG.get('sources', []):
    url = src if isinstance(src, str) else src.get('url')
    if not url: continue
    try:
        raw = fetch(url)
        parsed = clash_nodes(raw)
        if not parsed:
            for u in uri_nodes(raw):
                p = parse_uri(u)
                if p: parsed.append(p)
        nodes.extend(parsed)
        source_stats.append({'url': url, 'fetched': True, 'candidates': len(parsed)})
    except Exception as e:
        source_stats.append({'url': url, 'fetched': False, 'candidates': 0, 'error': type(e).__name__})

unique=[]; seen=set(); tested=0
for p in nodes:
    if not valid_shape(p): continue
    p['port'] = int(p['port'])
    key=(str(p['type']).lower(), str(p['server']).lower(), p['port'], p.get('uuid') or p.get('password') or '')
    if key in seen: continue
    seen.add(key)
    tested += 1
    # Conservative test: TCP reachability only; never sends application data through the proxy.
    if tcp_ok(p['server'], p['port']):
        unique.append(p)
    if len(unique) >= MAX_NODES: break

# Stable names and output
for i,p in enumerate(unique,1):
    p['name'] = str(p['name'])[:80] or f'node-{i}'

out={'mixed-port':7890,'allow-lan':False,'mode':'rule','proxies':unique}
if unique:
    out['proxy-groups']=[{'name':'Auto','type':'url-test','proxies':[p['name'] for p in unique],
                          'url':'https://www.gstatic.com/generate_204','interval':300}]
    out['rules']=['MATCH,Auto']
else:
    out['rules']=['MATCH,DIRECT']
(ROOT/'clash.yaml').write_text(yaml.safe_dump(out, allow_unicode=True, sort_keys=False), encoding='utf-8')

# Preserve original share URIs when sources are URI feeds; conversion is deliberately only emitted for parsed types we can serialize safely.
uris=[]
for p in unique:
    typ=p['type']
    if typ == 'ss' and p.get('cipher') and p.get('password'):
        payload=f"{p['cipher']}:{p['password']}@{p['server']}:{p['port']}"
        enc=base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        uris.append('ss://' + enc + '#' + urllib.parse.quote(p['name']))
    elif typ == 'trojan' and p.get('password'):
        uris.append('trojan://' + urllib.parse.quote(p['password']) + '@' + p['server'] + ':' + str(p['port']) + '?sni=' + urllib.parse.quote(p.get('sni',p['server'])) + '#' + urllib.parse.quote(p['name']))
    elif typ == 'vless' and p.get('uuid'):
        q={'type':p.get('network','tcp')}
        if p.get('tls'): q['security']='tls'
        if p.get('servername'): q['sni']=p['servername']
        if p.get('flow'): q['flow']=p['flow']
        uris.append('vless://' + urllib.parse.quote(p['uuid']) + '@' + p['server'] + ':' + str(p['port']) + '?' + urllib.parse.urlencode(q) + '#' + urllib.parse.quote(p['name']))
(ROOT/'shadowrocket.txt').write_text('\n'.join(uris)+'\n' if uris else '', encoding='utf-8')
(ROOT/'base64.txt').write_text(base64.b64encode('\n'.join(uris).encode()).decode(), encoding='utf-8')

status={'nodes':len(unique),'candidates_tested':tested,'sources':source_stats,
        'updated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'test':'TCP connect only'}
(ROOT/'status.json').write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(status, ensure_ascii=False, indent=2))
