// Hostile-network tests for plugin/src/{github,engine}.js: redirects (token must never leave the API origin), oversized /
// endless / slow streamed bodies, hanging servers. Needs no wiki password and no mock GitHub: own throw-away node servers.
const Module = require('module'), path = require('path'), http = require('http'), crypto = require('crypto');
const SRC = path.join(__dirname, '..', '..', 'plugin', 'src');
const orig = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) { const m = /^\$:\/plugins\/tw-enc-sync\/(.+)$/.exec(req); return orig.call(this, m ? path.join(SRC, m[1]) : req, ...rest); };
const G = require('$:/plugins/tw-enc-sync/github.js'), { Engine } = require('$:/plugins/tw-enc-sync/engine.js');
const fails = []; let current = '';
const ok = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + current + ': ' + n + (!c && x !== undefined ? ' ' + JSON.stringify(x) : '')); if (!c) fails.push(current + ': ' + n); };
const rejects = async p => { try { await p; } catch (e) { return e; } return null; };
const tests = [], test = (n, fn) => tests.push([n, fn]);
const TOKEN = 'ghp_NETTESTTOKEN0123456789';
const servers = [];
function listen(handler) { return new Promise(res => { const s = http.createServer(handler); s.listen(0, '127.0.0.1', () => { servers.push(s); res({ s, port: s.address().port, url: 'http://127.0.0.1:' + s.address().port }); }); }); }
function client(apiBase, o) { return new G.Client(Object.assign({ repo: 'o/r', branch: 'master', apiBase, token: TOKEN }, o)); }

test('redirects: the Authorization header and request bodies never reach another origin', async () => {
  const seen = [];   // everything the "other origin" receives
  const evil = await listen((q, r) => { seen.push({ m: q.method, u: q.url, h: q.headers }); r.writeHead(200, { 'content-type': 'application/json' }); r.end('{"object":{"sha":"' + 'a'.repeat(40) + '"}}'); });
  for (const code of [301, 302, 303, 307, 308]) {
    const api = await listen((q, r) => { q.resume(); r.writeHead(code, { location: evil.url + '/steal' }); r.end(); });
    const c = client(api.url);
    for (const [name, fn] of [['GET', () => c.getHead()], ['POST', () => c.createBlob(new Uint8Array([1, 2, 3]))], ['PATCH', () => c.api('PATCH', '/git/refs/heads/master', { sha: 'a'.repeat(40) })]]) {
      const e = await rejects(fn());
      ok(code + ' ' + name + ' is refused, scrubbed', !!e && e.status === 0 && e.message.indexOf(TOKEN) === -1, e && e.message);
    }
  }
  ok('cross-origin target received 0 requests (no token, no body)', seen.length === 0, seen);
  // same-origin redirect (e.g. renamed repo) is also refused rather than followed: a POST must never silently turn into a GET
  const hits = []; const api = await listen((q, r) => { q.resume(); hits.push(q.method + ' ' + q.url); if (q.url.indexOf('/moved') === -1) { r.writeHead(301, { location: '/moved' }); r.end(); } else { r.writeHead(200); r.end('{}'); } });
  await rejects(client(api.url).createBlob(new Uint8Array(1))); ok('same-origin redirect not followed', hits.length === 1 && !hits.some(h => /moved/.test(h)), hits);
  // init options requested from fetch
  let init; await rejects(client('http://127.0.0.1:1', { fetch: async (u, i) => { init = i; throw new Error('x'); } }).getHead());
  ok('fetch init: redirect=error, credentials=omit, no-referrer, no-store', init.redirect === 'error' && init.credentials === 'omit' && init.referrerPolicy === 'no-referrer' && init.cache === 'no-store', init);
  ok('token only in the Authorization header', Object.keys(init.headers).filter(k => String(init.headers[k]).indexOf(TOKEN) !== -1).join() === 'Authorization');
});

test('requests: token never in URL or body; GETs carry no query token', async () => {
  const reqs = []; const api = await listen((q, r) => { let b = ''; q.on('data', d => b += d); q.on('end', () => { reqs.push({ u: q.url, b, a: q.headers.authorization }); r.writeHead(404); r.end('{"message":"nope ' + TOKEN + '"}'); }); });
  const c = client(api.url);
  const errs = [await rejects(c.getHead()), await rejects(c.getRaw('m/' + 'a'.repeat(32) + '.bin', 'b'.repeat(40))), await rejects(c.createBlob(new Uint8Array(4))), await rejects(c.commit({ commit: 'a'.repeat(40), tree: 'b'.repeat(40) }, [{ path: 'm/' + 'a'.repeat(32) + '.bin', sha: null }], 'Update'))];
  ok('all failed', errs.every(e => e && e.status === 404));
  ok('no URL or body contains the token', reqs.every(r => r.u.indexOf(TOKEN) === -1 && r.b.indexOf(TOKEN) === -1) && reqs.length === 4, reqs);
  ok('every request authenticated by header only', reqs.every(r => r.a === 'Bearer ' + TOKEN));
  ok('an echoed token in GitHub error text is redacted', errs.every(e => e.message.indexOf(TOKEN) === -1 && JSON.stringify(e).indexOf(TOKEN) === -1), errs[0].message);
});

test('streamed bodies: size cap holds without / against Content-Length, aborts the transfer', async () => {
  let sent = 0, closed = false;
  const srv = await listen((q, r) => {   // endless chunked body, no content-length
    r.writeHead(200, { 'content-type': 'application/octet-stream' });
    const chunk = Buffer.alloc(65536, 7);
    (function pump() { if (closed || r.destroyed) return; sent += chunk.length; if (r.write(chunk)) setImmediate(pump); else r.once('drain', pump); })();
    q.socket.on('close', () => { closed = true; });
  });
  const t0 = Date.now();
  const e = await rejects(G.request(fetch, srv.url + '/x', {}, { max: 1048576, timeoutMs: 20000 }));
  ok('endless chunked body rejected', !!e && /too large/.test(e.message), e && e.message);
  await new Promise(r => setTimeout(r, 300));
  ok('server connection torn down, bounded transfer', closed && sent < 64 * 1048576 && Date.now() - t0 < 10000, { sent, closed });
  // large content-length claim
  const big = await listen((q, r) => { r.writeHead(200, { 'content-length': '5000000000' }); r.write('x'); setTimeout(() => r.destroy(), 2000); });
  const e2 = await rejects(G.request(fetch, big.url, {}, { max: 1048576, timeoutMs: 20000 }));
  ok('huge Content-Length rejected up front', !!e2, e2 && e2.message);
  // within the cap
  const small = await listen((q, r) => { r.writeHead(200); r.end(Buffer.alloc(1000, 1)); });
  const ok1 = await G.request(fetch, small.url, {}, { max: 1048576, timeoutMs: 5000 }); ok('small body passes', ok1.bytes.length === 1000);
  // error bodies are truncated, not fatal and not reflected
  const errb = await listen((q, r) => { r.writeHead(500); r.end(Buffer.alloc(5 * 1048576, 65)); });
  const r5 = await G.request(fetch, errb.url, {}, { max: 1048576, timeoutMs: 5000 }); ok('5 MB error body truncated to 64 KiB', r5.res.status === 500 && r5.bytes.length === 65536, r5.bytes.length);
  // through the API client: a 200 JSON body above the API cap
  const api = await listen((q, r) => { q.resume(); r.writeHead(200); const b = Buffer.alloc(65536, 32); let n = 0; (function p() { if (r.destroyed) return; if (n++ > 400) return r.end('{}'); if (r.write(b)) setImmediate(p); else r.once('drain', p); })(); });
  const e3 = await rejects(client(api.url).getHead()); ok('API client refuses > 8 MiB JSON', !!e3 && e3.status === 0, e3 && e3.message);
  // manifest cap through getRaw's explicit max
  const raw = await listen((q, r) => { q.resume(); r.writeHead(200); r.end(Buffer.alloc(300000, 1)); });
  const e4 = await rejects(client(raw.url).getRaw('m/' + 'a'.repeat(32) + '.bin', 'b'.repeat(40), 100000)); ok('getRaw honours max', !!e4);
  const okRaw = await client(raw.url).getRaw('m/' + 'a'.repeat(32) + '.bin', 'b'.repeat(40), 400000); ok('getRaw within max returns bytes', okRaw.byteLength === 300000);
});

test('slow-drip and hanging servers time out', async () => {
  const drip = await listen((q, r) => { r.writeHead(200); const iv = setInterval(() => { if (r.destroyed) clearInterval(iv); else r.write('x'); }, 50); q.socket.on('close', () => clearInterval(iv)); });
  let t0 = Date.now(); let e = await rejects(G.request(fetch, drip.url, {}, { max: 1e9, timeoutMs: 600 }));
  ok('slow body aborted by overall timeout', !!e && /timed out/.test(e.message) && Date.now() - t0 < 3000, e && e.message);
  const hang = await listen(() => {});
  t0 = Date.now(); e = await rejects(client(hang.url, { timeoutMs: 500 }).getHead());
  ok('hanging API server => GitHubError, no hang', !!e && e.status === 0 && Date.now() - t0 < 3000, e && e.message);
  // fetch implementations that ignore AbortSignal are still bounded
  t0 = Date.now(); e = await rejects(client('https://api.github.com', { timeoutMs: 300, fetch: () => new Promise(() => {}) }).getHead());
  ok('signal-ignoring fetch bounded by race', !!e && Date.now() - t0 < 2000);
});

test('engine page fetches: cross-origin redirect never followed, no Authorization to the page origin, limits', async () => {
  const evilSeen = []; const evil = await listen((q, r) => { evilSeen.push(q.headers); r.writeHead(200); r.end(Buffer.alloc(2048, 1)); });
  const pageSeen = [];
  let mode = 'redirect', sent = 0;
  const page = await listen((q, r) => {
    pageSeen.push({ u: q.url, h: q.headers });
    if (mode === 'redirect') { r.writeHead(302, { location: evil.url + q.url }); return r.end(); }
    if (mode === 'endless') { r.writeHead(200); const c = Buffer.alloc(65536); (function p() { if (r.destroyed) return; sent += 65536; if (r.write(c)) setImmediate(p); else r.once('drain', p); })(); return; }
    if (mode === 'status') { r.writeHead(503, { 'content-type': 'text/html' }); return r.end('<script>alert(1)</script>' + TOKEN); }
    r.writeHead(200); r.end(Buffer.alloc(100));
  });
  const mkE = (o) => new Engine(Object.assign({ cfg: { repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', base: 'wk/' }, dek: Uint8Array.from(crypto.randomBytes(32)), fetch: (u, i) => fetch(u, i), baseUrl: page.url + '/dir/index.html', getToken: () => TOKEN, storage: null, isBase64Type: () => false, categoryOrder: () => [], onStatus: () => {}, requestTimeoutMs: 3000 }, o));
  let E = mkE(); let err = await rejects(E.ready); await new Promise(r => setTimeout(r, 200));
  ok('manifest load fails on cross-origin redirect', !!err && E.status.state === 'error', err && err.message);
  ok('cross-origin server got nothing', evilSeen.length === 0, evilSeen.length);
  ok('requests were for base+hex path only, resolved against baseUrl', pageSeen.length >= 1 && pageSeen.every(p => /^\/dir\/wk\/m\/[0-9a-f]{32}\.bin(\?v=\d+)?$/.test(p.u) || /^\/wk\/m\/[0-9a-f]{32}\.bin(\?v=\d+)?$/.test(p.u)), pageSeen.map(p => p.u));
  ok('no Authorization / Cookie / Referer sent to the page origin', pageSeen.every(p => !p.h.authorization && !p.h.cookie && !p.h.referer));
  ok('error text does not reflect the response', err && err.message.indexOf(TOKEN) === -1 && !/script/.test(err.message));
  mode = 'endless'; sent = 0; E = mkE(); err = await rejects(E.fetchBytes('m/' + 'a'.repeat(32) + '.bin', null, 2 * 1048576));
  ok('page file: endless body capped', !!err && /too large/.test(err.message) && sent < 64 * 1048576, { err: err && err.message, sent });
  mode = 'status'; err = await rejects(E.fetchBytes('m/' + 'a'.repeat(32) + '.bin'));
  ok('HTTP error: status only', !!err && err.message === 'HTTP 503 for encrypted file', err && err.message);
  // slow/hanging page
  const hang = await listen(() => {}); const t0 = Date.now(); E = mkE({ baseUrl: hang.url + '/', requestTimeoutMs: 500 });
  err = await rejects(E.fetchBytes('m/' + 'a'.repeat(32) + '.bin')); ok('hanging page file times out', !!err && /timed out/.test(err.message) && Date.now() - t0 < 3000, err && err.message);
});

(async () => {
  for (const [n, fn] of tests) { current = n; try { await fn(); } catch (e) { ok('threw ' + (e && e.stack || e), false); } }
  servers.forEach(s => { s.closeAllConnections && s.closeAllConnections(); s.close(); });
  console.log(fails.length ? 'FAILED (' + fails.length + '):\n  ' + fails.join('\n  ') : 'ALL NET CHECKS PASSED');
  process.exit(fails.length ? 1 : 0);
})();
