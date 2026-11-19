"""VeriClaim - blockchain insurance claims prototype (educational simulation)."""
import os, json, time, hmac, hashlib, random, socket, sqlite3, secrets, threading, shutil, glob
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

B = os.path.dirname(os.path.abspath(__file__)); UP = B + '/uploads'; os.makedirs(UP, exist_ok=True)
DIFF = 3; HK = b'consortium-shared-hmac-key'   # PoW difficulty / shared HMAC key (demo only)
PINS = {'customer': '1111', 'surveyor': '2222', 'insurer': '3333', 'insurerB': '4444'}; ANY = tuple(PINS)
app = Flask(__name__, static_folder=B + '/static'); LK = threading.RLock(); TOK = {}; CH = []

# ---------- crypto helpers ----------
H = lambda s: hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()
cj = lambda o: json.dumps(o, sort_keys=True, separators=(',', ':'))
def _keys():
    f = B + '/keys.json'
    if os.path.exists(f): d = json.load(open(f))
    else: d = {r: secrets.token_hex(32) for r in PINS}; json.dump(d, open(f, 'w'))
    return {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v)) for r, v in d.items()}
K = _keys(); pub = lambda r: K[r].public_key().public_bytes_raw().hex()

def merkle(hs):
    l = list(hs)
    if not l: return H('')
    while len(l) > 1:
        if len(l) % 2: l.append(l[-1])
        l = [H(l[i] + l[i + 1]) for i in range(0, len(l), 2)]
    return l[0]
def mproof(hs, i):
    l = list(hs); p = []
    while len(l) > 1:
        if len(l) % 2: l.append(l[-1])
        p.append([l[i ^ 1], i % 2]); l = [H(l[j] + l[j + 1]) for j in range(0, len(l), 2)]; i //= 2
    return p
def mverify(h, p, root):
    for s, right in p: h = H(s + h) if right else H(h + s)
    return h == root

def mktx(t, cid, actor, data):
    b = {'t': t, 'cid': cid, 'actor': actor, 'data': data, 'ts': time.time()}
    return {**b, 'sig': K[actor].sign(cj(b).encode()).hex(), 'pub': pub(actor)}
txbody = lambda x: {k: x[k] for k in ('t', 'cid', 'actor', 'data', 'ts')}
txh = lambda x: H(cj(x))
def sigok(x):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(x['pub'])).verify(bytes.fromhex(x['sig']), cj(txbody(x)).encode())
        return x['pub'] == pub(x['actor'])
    except Exception: return False

# ---------- storage ----------
C = sqlite3.connect(B + '/claimchain.db', check_same_thread=False)
C.executescript('CREATE TABLE IF NOT EXISTS claims(id TEXT PRIMARY KEY,j TEXT);CREATE TABLE IF NOT EXISTS blocks(i INTEGER PRIMARY KEY,j TEXT);CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts REAL,kind TEXT,msg TEXT);')
def getc(i): r = C.execute('SELECT j FROM claims WHERE id=?', (i,)).fetchone(); return json.loads(r[0]) if r else None
def putc(c): C.execute('REPLACE INTO claims VALUES(?,?)', (c['id'], json.dumps(c))); C.commit()
def allc(): return [json.loads(r[0]) for r in C.execute('SELECT j FROM claims')]
def ev(kind, msg): C.execute('INSERT INTO events(ts,kind,msg) VALUES(?,?,?)', (time.time(), kind, msg)); C.commit()
def step(c, st, by, note='', ts=None): c['status'] = st; c['hist'].append({'s': st, 'ts': ts or time.time(), 'by': by, 'n': note})

# ---------- blockchain ----------
bhash = lambda b: H(cj({k: b[k] for k in ('i', 'ts', 'prev', 'root', 'nonce')}))
def mine(txs):
    b = {'i': len(CH), 'ts': time.time(), 'prev': CH[-1]['hash'] if CH else '0' * 64, 'txs': txs, 'root': merkle([txh(x) for x in txs]), 'nonce': 0}
    while not bhash(b).startswith('0' * DIFF): b['nonce'] += 1
    b['hash'] = bhash(b); CH.append(b); C.execute('INSERT INTO blocks VALUES(?,?)', (b['i'], json.dumps(b))); C.commit(); return b
def verify():
    for i, b in enumerate(CH):
        if bhash(b) != b['hash'] or not b['hash'].startswith('0' * DIFF): return {'valid': False, 'block': i, 'why': 'Block hash or Proof-of-Work invalid'}
        if merkle([txh(x) for x in b['txs']]) != b['root']: return {'valid': False, 'block': i, 'why': 'Merkle root mismatch: a transaction was changed'}
        if i and b['prev'] != CH[i - 1]['hash']: return {'valid': False, 'block': i, 'why': 'Link to previous block is broken'}
        if not all(sigok(x) for x in b['txs']): return {'valid': False, 'block': i, 'why': 'Invalid digital signature'}
    return {'valid': True}
def load(): CH[:] = [json.loads(r[0]) for r in C.execute('SELECT j FROM blocks ORDER BY i')]
def genesis(): mine([mktx('GENESIS', '-', 'insurer', {'note': 'VeriClaim genesis block'})])
load()
if not CH: genesis()

# ---------- auth ----------
def need(*roles):
    def d(f):
        @wraps(f)
        def w(*a, **k):
            r = TOK.get(request.headers.get('X-Token'))
            if r not in roles:
                ev('blocked', 'BLOCKED: %s attempted %s (requires %s)' % (r or 'anonymous', request.path, '/'.join(roles)))
                return jsonify(error='Permission denied for role: %s' % (r or 'not logged in')), 403
            g.role = r; return f(*a, **k)
        return w
    return d
@app.before_request
def _lk(): LK.acquire()
@app.teardown_request
def _ul(e): LK.release()
@app.post('/api/login')
def login():
    d = request.json or {}
    if PINS.get(d.get('role')) != d.get('pin'): return jsonify(error='Wrong PIN'), 401
    t = secrets.token_hex(8); TOK[t] = d['role']; return jsonify(token=t, role=d['role'])

# ---------- duplicate fingerprint (HMAC, NOT zero-knowledge) ----------
def fp(date, typ, asset):
    s = '|'.join(x.strip().lower().replace(' ', '') for x in (date, typ, asset)); return hmac.new(HK, s.encode(), hashlib.sha256).hexdigest()
def fpmatches(f, insurer):
    return [{'insurer': x['data']['insurer'], 'block': b['i']} for b in CH for x in b['txs'] if x['t'] in ('CLAIM_SUBMITTED', 'FP_REGISTER') and x['data'].get('fp') == f and x['data'].get('insurer') != insurer]
@app.post('/api/dup/check')
@need('insurerB', 'insurer')
def dupcheck():
    d = request.json; f = fp(d['date'], d['type'], d['asset']); ins = 'InsurerB' if g.role == 'insurerB' else 'InsurerA'
    m = fpmatches(f, ins); mine([mktx('FP_REGISTER', '-', g.role, {'fp': f, 'insurer': ins})])
    if m: ev('dup', 'DUPLICATE ALERT: a claim from %s matches a fingerprint already filed at %s (block #%d). No customer data was shared.' % (ins, m[0]['insurer'], m[0]['block']))
    return jsonify(fp=f, match=bool(m), matches=m)

# ---------- claims ----------
def evidence(c):
    if not c['photo']: return {'match': None}
    p = UP + '/' + c['photo']; return {'match': os.path.exists(p) and H(open(p, 'rb').read()) == c['hash']}
@app.get('/api/claims')
@need(*ANY)
def lst(): return jsonify(sorted(allc(), key=lambda c: -c['hist'][0]['ts']))
@app.get('/api/claims/<cid>/evidence')
@need(*ANY)
def evid(cid): return jsonify(evidence(getc(cid)))
@app.get('/uploads/<n>')
def up(n): return send_from_directory(UP, n)
@app.post('/api/claims')
@need('customer')
def newclaim():
    f = request.form; ph = request.files.get('photo'); cid = 'CLM-' + secrets.token_hex(2).upper(); name = h = ''
    if ph and ph.filename:
        name = cid + '.jpg'; ph.save(UP + '/' + name); h = H(open(UP + '/' + name, 'rb').read())
    f_ = fp(f['date'], f['type'], f['asset']); par = f['type'].startswith('Flight')
    c = {'id': cid, 'type': f['type'], 'mode': 'parametric' if par else 'conventional', 'policy': f['policy'], 'date': f['date'], 'asset': f['asset'],
         'amount': float(f.get('amount') or 0), 'desc': f.get('desc', ''), 'photo': name, 'hash': h, 'fp': f_, 'status': '', 'pay': 'Not paid', 'hist': [], 'flag': False, 'oracle': None}
    step(c, 'Event Reported' if par else 'Submitted', 'customer')
    dup = fpmatches(f_, 'InsurerA')
    if dup: c['flag'] = True; ev('dup', 'Potential duplicate for %s: fingerprint already seen at %s' % (cid, dup[0]['insurer']))
    mine([mktx('CLAIM_SUBMITTED', cid, 'customer', {'fp': f_, 'insurer': 'InsurerA', 'evidence_hash': h, 'mode': c['mode'], 'amount': c['amount']})])
    putc(c); ev('claim', 'New claim %s submitted from customer device' % cid); return jsonify(c)
@app.post('/api/claims/<cid>/verify')
@need('surveyor')
def verify_c(cid):
    c = getc(cid); d = request.json; ok = d.get('ok', True)
    if not c or c['mode'] != 'conventional' or c['status'] != 'Submitted': return jsonify(error='Claim is not awaiting surveyor review'), 400
    em = evidence(c)['match']; step(c, 'Verified' if ok else 'Rejected', 'surveyor', d.get('remarks', '')); c['remarks'] = d.get('remarks', '')
    mine([mktx('SURVEY_ASSESSMENT', cid, 'surveyor', {'ok': ok, 'evidence_match': em, 'remarks_hash': H(d.get('remarks', ''))})])
    putc(c); ev('claim', '%s %s by surveyor' % (cid, c['status'])); return jsonify(c)
@app.post('/api/claims/<cid>/decide')
@need('insurer')
def decide(cid):
    c = getc(cid); ap = bool(request.json.get('approve'))
    if not c or c['status'] not in ('Verified', 'Trigger Confirmed', 'Manual Review'): return jsonify(error='Claim is not ready for a decision'), 400
    step(c, 'Approved' if ap else 'Rejected', 'insurer', 'Human decision')
    mine([mktx('DECISION', cid, 'insurer', {'approved': ap})]); putc(c); ev('claim', '%s %s by insurer' % (cid, c['status'])); return jsonify(c)
@app.post('/api/claims/<cid>/settle')
@need('insurer')
def settle(cid):
    c = getc(cid)
    if not c or c['status'] != 'Approved': return jsonify(error='Only approved claims can be settled'), 400
    ref = 'SIM-' + secrets.token_hex(3).upper(); step(c, 'Settled', 'insurer', 'Simulated payout ' + ref); c['pay'] = 'Simulated payout ' + ref
    mine([mktx('SETTLEMENT', cid, 'insurer', {'ref': ref, 'amount': c['amount'], 'simulated': True})]); putc(c)
    ev('claim', '%s settled (SIMULATED payout, no real money)' % cid); return jsonify(c)

# ---------- multi-oracle consensus ----------
ORC = [('Airline API', 'airline'), ('Airport Authority', 'airport'), ('Flight Tracker', 'tracker')]; REL = {o[0]: 100 for o in ORC}
@app.post('/api/claims/<cid>/oracle')
@need('insurer')
def oracle(cid):
    c = getc(cid); d = request.json; k = int(d.get('k', 2)); sc = d.get('scenario', 'agree'); TH = 120
    if not c or c['mode'] != 'parametric' or c['status'] != 'Event Reported': return jsonify(error='Not a pending parametric claim'), 400
    base = random.randint(150, 200); rd = [{'oracle': n, 'source': s, 'val': base + random.randint(-4, 4), 'ok': True} for n, s in ORC]
    if sc == 'conflict': rd[0]['val'] = base - 130; rd[2]['val'] = base + 90
    if sc == 'offline': rd[1]['ok'] = rd[2]['ok'] = False
    if sc == 'shared': rd[1]['source'] = rd[0]['source']          # two oracles reading the same upstream source
    on = [r for r in rd if r['ok']]; best = []
    for r in on:
        cl = [x for x in on if abs(x['val'] - r['val']) <= 10]
        if len({x['source'] for x in cl}) > len({x['source'] for x in best}): best = cl
    ind = len({x['source'] for x in best})
    for r in rd:
        r['outlier'] = r['ok'] and r not in best
        if r['outlier']: REL[r['oracle']] = max(0, REL[r['oracle']] - 15)
        r['rel'] = REL[r['oracle']]
    if ind >= k:
        med = sorted(x['val'] for x in best)[len(best) // 2]; trig = med >= TH
        res = {'status': 'consensus', 'value': med, 'trigger': trig}; st = 'Trigger Confirmed' if trig else 'Rejected'; note = '%d-of-3 consensus' % k
    else: res = {'status': 'no-consensus'}; st = 'Manual Review'; note = 'No %d-of-3 independent agreement' % k
    res.update(readings=rd, k=k, independent=ind, threshold=TH, scenario=sc); c['oracle'] = res; step(c, st, 'oracle', note)
    mine([mktx('ORACLE_RESULT', cid, 'insurer', {'k': k, 'independent': ind, 'result': st, 'values': [r['val'] if r['ok'] else None for r in rd]})])
    putc(c); ev('oracle', '%s oracle round (%d-of-3): %s' % (cid, k, st)); return jsonify(c)

# ---------- explorer, proofs, tamper demo ----------
@app.get('/api/chain')
@need(*ANY)
def chain():
    bl = [{**{k: v for k, v in b.items() if k != 'txs'}, 'txs': [{'t': x['t'], 'cid': x['cid'], 'actor': x['actor']} for x in b['txs']]} for b in CH]
    return jsonify(blocks=bl, verify=verify())
@app.get('/api/proof/<cid>')
@need(*ANY)
def prf(cid):
    for b in CH:
        hs = [txh(x) for x in b['txs']]
        for i, x in enumerate(b['txs']):
            if x['cid'] == cid and x['t'] == 'CLAIM_SUBMITTED':
                p = mproof(hs, i); return jsonify(block=b['i'], root=b['root'], leaf=hs[i], proof=p, leaves=len(hs), valid=mverify(hs[i], p, b['root']))
    return jsonify(error='Claim transaction not found'), 404
@app.post('/api/tamper')
@need('insurer')
def tamper():
    if request.json.get('mode') == 'block':
        b = next((b for b in CH if b['i'] > 0 and b['txs']), None)
        if not b: return jsonify(error='No block to tamper yet'), 400
        b['txs'][0]['data']['tampered'] = True; ev('tamper', 'DEMO: a transaction in block #%d was altered in memory' % b['i'])
    else:
        cs = [c for c in allc() if c['photo'] and os.path.exists(UP + '/' + c['photo'])]
        if not cs: return jsonify(error='No uploaded photo yet'), 400
        p = UP + '/' + cs[-1]['photo']; shutil.copy(p, p + '.bak'); open(p, 'ab').write(b'tampered'); ev('tamper', 'DEMO: evidence file of %s was modified' % cs[-1]['id'])
    return jsonify(ok=1)
@app.post('/api/restore')
@need('insurer')
def restore():
    load()
    for b in glob.glob(UP + '/*.bak'): shutil.move(b, b[:-4])
    ev('tamper', 'DEMO: original data restored'); return jsonify(ok=1)

# ---------- dashboard ----------
@app.get('/api/dashboard')
@need(*ANY)
def dash():
    cs = allc(); mins = lambda l: round(sum(l) / len(l) / 60, 1) if l else 0
    pend = {s: sum(c['status'] == s for c in cs) for s in ['Submitted', 'Event Reported', 'Verified', 'Trigger Confirmed', 'Manual Review', 'Approved']}
    gaps = {}
    for c in cs:
        for a, b in zip(c['hist'], c['hist'][1:]): gaps.setdefault('%s → %s' % (a['s'], b['s']), []).append(b['ts'] - a['ts'])
    stg = {k: mins(v) for k, v in gaps.items()}; dec = [c for c in cs if c['status'] in ('Approved', 'Settled', 'Rejected')]
    auto = sum(1 for c in cs if c['oracle'] and c['oracle']['status'] == 'consensus')
    return jsonify(total=len(cs), avg_min=mins([c['hist'][-1]['ts'] - c['hist'][0]['ts'] for c in cs if c['status'] == 'Settled']), pending=pend, auto=auto, manual=len(cs) - auto,
        flagged=sum(c['flag'] for c in cs), dups=C.execute("SELECT COUNT(*) FROM events WHERE kind='dup'").fetchone()[0],
        approval=round(100 * sum(c['status'] in ('Approved', 'Settled') for c in dec) / len(dec)) if dec else 0,
        payout=sum(c['amount'] for c in cs if c['status'] == 'Settled'), stages=stg, bottleneck=max(stg, key=stg.get) if stg else None)
@app.post('/api/seed')
@need('insurer')
def seed():
    now = time.time(); txs = []; types = ['Vehicle Accident', 'Property Damage', 'Flight Delay (parametric)']
    for i in range(10):
        t = random.choice(types); par = t.startswith('Flight'); cid = 'CLM-S%02d' % i; t0 = now - random.randint(86400, 5 * 86400)
        c = {'id': cid, 'type': t, 'mode': 'parametric' if par else 'conventional', 'policy': 'POL-%d' % (1000 + i), 'date': '2026-10-%02d' % (i + 1), 'asset': 'ASSET-%d' % i,
             'amount': random.choice([8000, 15000, 32000, 54000]), 'desc': 'Synthetic demo claim', 'photo': '', 'hash': '', 'status': '', 'pay': 'Not paid', 'hist': [], 'flag': i == 3, 'oracle': None}
        c['fp'] = fp(c['date'], t, c['asset'])
        path = ['Event Reported', 'Trigger Confirmed', 'Approved', 'Settled'] if par else ['Submitted', 'Verified', 'Approved', 'Settled']
        gaps = [random.randint(300, 1200), random.randint(600, 2400), random.randint(300, 900)] if par else [random.randint(14400, 40000), random.randint(3600, 10000), random.randint(900, 3000)]
        ts = t0
        for j, s in enumerate(path[:random.randint(2, 4)]):
            step(c, s, 'seed', ts=ts); ts += gaps[min(j, 2)]
        if par: c['oracle'] = {'status': 'consensus', 'value': 170, 'trigger': True, 'readings': [], 'k': 2, 'independent': 3, 'threshold': 120}
        if c['status'] == 'Settled': c['pay'] = 'Simulated payout SIM-SEED'
        txs.append(mktx('CLAIM_SUBMITTED', cid, 'customer', {'fp': c['fp'], 'insurer': 'InsurerC', 'evidence_hash': '', 'mode': c['mode'], 'amount': c['amount']})); putc(c)
    mine(txs); ev('claim', 'Seeded 10 synthetic claims in one block (multi-leaf Merkle tree)'); return jsonify(ok=1)
@app.post('/api/reset')
@need('insurer')
def reset():
    for t in ('claims', 'blocks', 'events'): C.execute('DELETE FROM ' + t)
    C.commit()
    for f in glob.glob(UP + '/*'): os.remove(f)
    CH.clear(); genesis(); REL.update({o[0]: 100 for o in ORC}); return jsonify(ok=1)

# ---------- Consensus Lab (educational simulations) ----------
@app.get('/api/lab/pow')
def lab_pow():
    d = min(int(request.args.get('d', 3)), 5); data = 'lab-block-' + secrets.token_hex(4); n = 0; t = time.time(); first = []
    while True:
        h = H(data + str(n))
        if n < 6: first.append({'n': n, 'h': h})
        if h.startswith('0' * d) or n > 3000000: break
        n += 1
    return jsonify(data=data, d=d, nonce=n, hash=h, attempts=n + 1, ms=round((time.time() - t) * 1000), first=first)
@app.get('/api/lab/pos')
def lab_pos():
    V = [('Node A', 50), ('Node B', 30), ('Node C', 15), ('Node D', 5)]
    return jsonify(validators=[{'n': a, 'stake': b} for a, b in V], rounds=[random.choices(V, weights=[v[1] for v in V])[0][0] for _ in range(10)])
@app.get('/api/lab/pbft')
def lab_pbft():
    n = int(request.args.get('n', 4)); f = int(request.args.get('faulty', 0)); tol = (n - 1) // 3; q = 2 * tol + 1
    return jsonify(n=n, faulty=f, tolerates=tol, quorum=q, agree=n - f, success=n - f >= q, msgs={'pre-prepare': n - 1, 'prepare': (n - 1) ** 2, 'commit': n * (n - 1)})

@app.get('/api/events')
def events():
    r = C.execute('SELECT id,kind,msg,ts FROM events WHERE id>? ORDER BY id', (int(request.args.get('since', 0)),)).fetchall()
    return jsonify([dict(zip(('id', 'kind', 'msg', 'ts'), x)) for x in r])
@app.get('/')
def index(): return send_from_directory(app.static_folder, 'index.html')

def lan():
    if os.environ.get('CLAIMCHAIN_IP'): return os.environ['CLAIMCHAIN_IP']
    for t in ('10.255.255.255', '8.8.8.8'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect((t, 1)); return s.getsockname()[0]
        except Exception: pass
        finally: s.close()
    return '127.0.0.1'
if __name__ == '__main__':
    print('\n  VeriClaim is running (simulation only)\n  Laptop : http://localhost:5000\n  Phone  : http://%s:5000   (same hotspot, type http:// explicitly)\n' % lan())
    app.run('0.0.0.0', 5000, threaded=True)
