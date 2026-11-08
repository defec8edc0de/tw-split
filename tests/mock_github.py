"""Tiny in-memory GitHub Git-Data-API mock backed by a directory (which is also what the static server serves => emulates Pages)."""
import base64, hashlib, json, os, re, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class State:
    def __init__(self, root, token, repo='o/r', branch='master'):
        self.root, self.token, self.repo, self.branch = root, token, repo, branch
        self.lock = threading.Lock()
        self.blobs = {}; self.trees = {}; self.commits = {}
        self.head = self._snapshot_commit(None)
        self.commit_log = []; self.requests = []; self.tree_reqs = []; self.fail_next_ref = 0
        self.history = [self.head]   # every head the branch has had (for rollback tests)
        self.rl = None               # (skip, retry_after): after `skip` more blob POSTs answer 429 + Retry-After until /__ratelimit/off
        self.inject = None           # (code, method, needle): answer that status for every authenticated request whose path contains needle (/__inject)
        self.defer = False           # True: commits are NOT published to the static dir until /__deploy (stale Pages / CDN skew)
    def publish(self, sha):
        """Write the commit's tree into the static dir (= "Pages deploy")."""
        new = self.trees[self.commits[sha]['tree']]
        for path, data in new.items():
            fp = os.path.join(self.root, path); os.makedirs(os.path.dirname(fp), exist_ok=True)
            if not os.path.exists(fp) or open(fp, 'rb').read() != data: open(fp, 'wb').write(data)
        for path in list(self._files()):
            if path not in new: os.remove(os.path.join(self.root, path))
    def _files(self):
        out = {}
        for d, _, fs in os.walk(self.root):
            for f in fs:
                p = os.path.relpath(os.path.join(d, f), self.root)
                if p != 'tw.html': out[p] = open(os.path.join(d, f), 'rb').read()
        return out
    def _sha(self, b): return hashlib.sha1(b).hexdigest()
    def _snapshot_commit(self, parent):
        files = self._files(); tsha = self._sha(json.dumps(sorted(files)).encode() + os.urandom(4))
        self.trees[tsha] = files
        c = self._sha(tsha.encode() + (parent or '').encode() + os.urandom(4)); self.commits[c] = {'tree': tsha, 'parent': parent}
        return c

def make_handler(st):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _cors(self):
            self.send_header('Access-Control-Allow-Origin', '*'); self.send_header('Access-Control-Allow-Headers', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS')
        def _send(self, code, obj=None, raw=None, headers=None):
            body = raw if raw is not None else json.dumps(obj).encode()
            self.send_response(code); self._cors()
            for k, v in (headers or {}).items(): self.send_header(k, v)
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_OPTIONS(self): self.send_response(204); self._cors(); self.end_headers()
        def _body(self):
            n = int(self.headers.get('Content-Length') or 0); return json.loads(self.rfile.read(n) or b'null')
        def handle_any(self, method):
            if self.path == '/__state':
                return self._send(200, {'commits': len(st.commit_log), 'auths': sorted({a for _, _, a in st.requests if a}), 'n': len(st.requests), 'files': len(st._files())})
            m0 = re.match(r'/__fail/(\d+)$', self.path)
            if m0: st.fail_next_ref = int(m0.group(1)); return self._send(200, {})
            m0 = re.match(r'/__defer/([01])$', self.path)            # hold back / allow publishing to the static dir
            if m0: st.defer = m0.group(1) == '1'; return self._send(200, {})
            m0 = re.match(r'/__ratelimit/(\d+)/(\d+)$', self.path)
            if m0: st.rl = [int(m0.group(1)), int(m0.group(2))]; return self._send(200, {})
            if self.path == '/__ratelimit/off': st.rl = None; return self._send(200, {})
            if self.path == '/__deploy':                              # publish the current head now
                with st.lock: st.publish(st.head)
                return self._send(200, {})
            if self.path == '/__reseed':                              # adopt the static dir's current content as a fresh root commit
                with st.lock: st.head = st._snapshot_commit(None); st.history = [st.head]; st.commit_log = []
                return self._send(200, {})
            m0 = re.match(r'/__sethead/(\d+)$', self.path)           # force the branch back to an earlier head (malicious repo writer)
            if m0:
                with st.lock:
                    st.head = st.history[int(m0.group(1))]
                    if not st.defer: st.publish(st.head)
                return self._send(200, {'n': len(st.history)})
            if self.path == '/__emptyrepo':                           # the branch now holds an EMPTY tree (fresh repo); the static dir (= the local copy) is untouched
                with st.lock:
                    t = st._sha(b'empty' + os.urandom(4)); st.trees[t] = {}
                    c = st._sha(t.encode() + os.urandom(4)); st.commits[c] = {'tree': t, 'parent': None}
                    st.head = c; st.history = [c]; st.commit_log = []
                return self._send(200, {})
            m0 = re.match(r'/__inject/(\d+)/([A-Z]+)/([\w/.-]+)$', self.path)   # e.g. /__inject/404/GET/git/commits/
            if m0: st.inject = (int(m0.group(1)), m0.group(2), m0.group(3)); return self._send(200, {})
            if self.path == '/__inject/off': st.inject = None; return self._send(200, {})
            if self.path == '/__headfiles':                           # path -> sha256 of every file in the branch head's tree
                with st.lock: return self._send(200, {k: hashlib.sha256(v).hexdigest() for k, v in st.trees[st.commits[st.head]['tree']].items()})
            m0 = re.match(r'/__headfile/([\w/.-]+)$', self.path)
            if m0:
                with st.lock: files = st.trees[st.commits[st.head]['tree']]
                return self._send(200, raw=files[m0.group(1)]) if m0.group(1) in files else self._send(404, {'message': 'no'})
            if self.path == '/__trees': return self._send(200, st.tree_reqs)
            if self.path == '/__history': return self._send(200, {'n': len(st.history)})
            with st.lock:
                st.requests.append((method, self.path, self.headers.get('Authorization')))
                if self.headers.get('Authorization') != 'Bearer ' + st.token: return self._send(401, {'message': 'Bad credentials'})
                base = '/repos/%s' % st.repo; p = self.path.split('?')[0]
                if not p.startswith(base): return self._send(404, {'message': 'no'})
                p = p[len(base):]
                if st.inject and method == st.inject[1] and st.inject[2] in p:
                    return self._send(st.inject[0], {'message': 'Not Found' if st.inject[0] == 404 else 'Resource not accessible by personal access token'})
                if method == 'GET' and p == '/git/ref/heads/' + st.branch: return self._send(200, {'object': {'sha': st.head}})
                m = re.match(r'/git/commits/(\w+)$', p)
                if method == 'GET' and m: return self._send(200, {'tree': {'sha': st.commits[m.group(1)]['tree']}})
                if method == 'GET' and p.startswith('/contents/'):
                    path = p[len('/contents/'):]; ref = re.search(r'ref=(\w+)', self.path).group(1)
                    files = st.trees[st.commits[ref]['tree']]
                    if 'raw' in (self.headers.get('Accept') or ''):
                        return self._send(200, raw=files[path]) if path in files else self._send(404, {'message': 'Not Found'})
                    # JSON metadata like the real API: a file -> {type, path, sha = git blob id}; a folder -> list of its entries
                    if path in files:
                        b = files[path]; return self._send(200, {'type': 'file', 'path': path, 'sha': hashlib.sha1(b'blob %d\0' % len(b) + b).hexdigest()})
                    kids = sorted(k for k in files if k.startswith(path + '/') and '/' not in k[len(path) + 1:])
                    return self._send(200, [{'type': 'file', 'path': k} for k in kids]) if kids else self._send(404, {'message': 'Not Found'})
                if method == 'POST' and p == '/git/blobs':
                    if st.rl is not None:
                        if st.rl[0] <= 0: return self._send(429, {'message': 'You have exceeded a secondary rate limit.'}, headers={'Retry-After': str(st.rl[1])})
                        st.rl[0] -= 1
                    b = base64.b64decode(self._body()['content']); s = st._sha(b); st.blobs[s] = b; return self._send(201, {'sha': s})
                if method == 'POST' and p == '/git/trees':
                    d = self._body(); st.tree_reqs.append(d); files = dict(st.trees[d['base_tree']])
                    for e in d['tree']:
                        if e['sha'] is None:
                            if e['path'] not in files: return self._send(422, {'message': 'tree.sha: path to delete does not exist: ' + e['path']})   # strict, like the real API can be
                            files.pop(e['path'])
                        else: files[e['path']] = st.blobs[e['sha']]
                    ts = st._sha(json.dumps(sorted(files)).encode() + os.urandom(4)); st.trees[ts] = files; return self._send(201, {'sha': ts})
                if method == 'POST' and p == '/git/commits':
                    d = self._body(); c = st._sha(d['tree'].encode() + os.urandom(4)); st.commits[c] = {'tree': d['tree'], 'parent': d['parents'][0], 'message': d['message']}
                    return self._send(201, {'sha': c, 'tree': {'sha': d['tree']}})
                if method == 'PATCH' and p == '/git/refs/heads/' + st.branch:
                    d = self._body()
                    if st.fail_next_ref > 0: st.fail_next_ref -= 1; return self._send(422, {'message': 'Update is not a fast forward'})
                    if st.commits[d['sha']]['parent'] != st.head: return self._send(422, {'message': 'Update is not a fast forward'})
                    st.head = d['sha']; st.commit_log.append(d['sha']); st.history.append(d['sha'])
                    if not st.defer: st.publish(d['sha'])
                    return self._send(200, {'ref': 'ok'})
                return self._send(404, {'message': 'unhandled ' + method + ' ' + p})
        def do_GET(self): self.handle_any('GET')
        def do_POST(self): self.handle_any('POST')
        def do_PATCH(self): self.handle_any('PATCH')
    return H

def serve(st, port=0):
    srv = ThreadingHTTPServer(('127.0.0.1', port), make_handler(st)); threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
