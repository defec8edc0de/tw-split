"""Engine-level tests (no wiki password needed): plugin/src/engine.js + github.js against tests/mock_github.py with a synthetic random DEK.
Run: .venv/bin/python tests/engine_test.py"""
import functools, http.server, os, shutil, subprocess, sys, tempfile, threading
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..')
sys.path.insert(0, HERE); import mock_github
TOKEN = 'test-token-ENGINE-xyz'
tmp = tempfile.mkdtemp(prefix='tweng-'); pages = os.path.join(tmp, 'pages'); os.makedirs(pages)
class Q(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def end_headers(self): self.send_header('Cache-Control', 'no-cache'); super().end_headers()
static = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=pages)); threading.Thread(target=static.serve_forever, daemon=True).start()
st = mock_github.State(pages, TOKEN); api = mock_github.serve(st, 0)
zipdir = os.path.join(tmp, 'zips'); os.makedirs(zipdir)
env = dict(os.environ, SP=str(static.server_address[1]), AP=str(api.server_address[1]), TOKEN=TOKEN, PAGES=pages, ZIPDIR=zipdir)
env.pop('TW_PASSWORD', None)
rc = subprocess.call([os.path.join(ROOT, '.venv', 'bin', 'node'), os.path.join(HERE, 'node', 'engine.test.js')], env=env, cwd=os.path.join(HERE, 'node'))
rc3 = subprocess.call([os.path.join(ROOT, '.venv', 'bin', 'node'), os.path.join(HERE, 'node', 'adaptor.test.js')], env=env, cwd=os.path.join(HERE, 'node'))   # adaptor / saver / buttons wiring on a fake $tw
rc2 = subprocess.call([os.path.join(ROOT, '.venv', 'bin', 'node'), os.path.join(HERE, 'node', 'net.test.js')], env=env, cwd=os.path.join(HERE, 'node'))   # hostile-network tests (own servers)

# zips written by the node tests (JS zip builder) must be valid for an independent implementation: Python's zipfile
import hashlib, json, zipfile
nz = 0; zbad = 0
for fn in sorted(os.listdir(zipdir)):
    if not fn.endswith('.zip'): continue
    nz += 1; expect = json.load(open(os.path.join(zipdir, fn + '.expect.json')))
    with zipfile.ZipFile(os.path.join(zipdir, fn)) as z:
        infos = z.infolist(); names = [i.filename for i in infos]
        checks = {'testzip (CRC of every member)': z.testzip() is None,
                  'every member STORED': all(i.compress_type == zipfile.ZIP_STORED for i in infos),
                  'UTF-8 flag on every member': all(i.flag_bits & 0x800 for i in infos),
                  'member order as built': names == expect['order'],
                  'no duplicate names': len(set(names)) == len(names),
                  'sha256 of every member': all(hashlib.sha256(z.read(n)).hexdigest() == h for n, h in expect['files'].items()) and sorted(expect['files']) == sorted(names),
                  'no unsafe names': all(not n.startswith('/') and '..' not in n.split('/') and '\\' not in n for n in names)}
        if 'remove' in expect: checks['_remove.txt content'] = z.read('_remove.txt').decode() == expect['remove']
    for k, v in checks.items():
        print(('PASS' if v else 'FAIL'), 'python zipfile', fn, k); zbad += not v
if nz < 2: print('FAIL expected zips from the node tests, found', nz); zbad += 1

# tools/twlib.py parsing of an untrusted HTML file: no super-linear behaviour, no silent truncation
import time; sys.path.insert(0, os.path.join(ROOT, 'tools')); import twlib
def timed(s):
    t = time.time()
    try: twlib.find_store(s)
    except ValueError: pass
    return time.time() - t
bad = 0
for name, doc in {'10MB of near-miss openers': ('<pre id="encryptedStoreArea" type="text/plain" ' * 250000),
                  '10MB of </pre> decoys, no store': '</pre>' * 1700000,
                  'store without terminator': twlib.PRE_OPEN + 'A' * 10_000_000,
                  '10MB entity soup': twlib.PRE_OPEN + '&amp;' * 2_000_000 + '</pre>'}.items():
    dt = timed(doc); ok = dt < 2.0; bad += not ok; print(('PASS' if ok else 'FAIL'), 'twlib.find_store', name, '%.2fs' % dt)
try: twlib.find_store(twlib.PRE_OPEN + 'x'); print('FAIL unterminated store accepted'); bad += 1
except ValueError: print('PASS twlib rejects unterminated store')
import html as _h
t = time.time(); _h.unescape('&amp;' * 2_000_000 + '&#' * 2_000_000); dt = time.time() - t; print(('PASS' if dt < 3 else 'FAIL'), 'html.unescape on 10MB hostile entities %.2fs' % dt); bad += dt >= 3
# hostile SJCL parameters are bounded before any KDF work
for blob in [dict(mode='ccm', cipher='aes', adata='', salt='AA==', iv='AAAAAAAAAAAAAAAAAAAAAA==', ct='A' * 40, iter=10**12, ks=128, ts=64),
             dict(mode='ccm', cipher='aes', adata='', salt='AA==', iv='AAAAAAAAAAAAAAAAAAAAAA==', ct='A' * 40, iter=1000, ks=512, ts=64),
             dict(mode='gcm', cipher='aes', adata='', salt='AA==', iv='AAAAAAAAAAAAAAAAAAAAAA==', ct='A' * 40, iter=1000, ks=128, ts=64)]:
    try: twlib.sjcl_decrypt(blob, 'pw'); print('FAIL hostile SJCL params accepted'); bad += 1
    except (ValueError, KeyError): print('PASS hostile SJCL params rejected')
shutil.rmtree(tmp, ignore_errors=True); sys.exit(rc or rc2 or rc3 or (1 if bad or zbad else 0))
