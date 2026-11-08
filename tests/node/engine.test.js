// Engine-level tests: plugin/src/{engine,github}.js (real code, injected deps) vs tests/mock_github.py ("GitHub" + "Pages").
// Synthetic random DEK, no wiki password. Launched by tests/engine_test.py (sets SP, AP, TOKEN, PAGES).
const Module = require('module'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const SRC = path.join(__dirname, '..', '..', 'plugin', 'src');
const orig = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) { const m = /^\$:\/plugins\/tw-enc-sync\/(.+)$/.exec(req); return orig.call(this, m ? path.join(SRC, m[1]) : req, ...rest); };
const F = require('$:/plugins/tw-enc-sync/encfmt.js'), G = require('$:/plugins/tw-enc-sync/github.js'), { Engine } = require('$:/plugins/tw-enc-sync/engine.js');
const LS = require('$:/plugins/tw-enc-sync/localsink.js'), TG = require('$:/plugins/tw-enc-sync/targets.js');
const SP = process.env.SP, AP = process.env.AP, TOKEN = process.env.TOKEN, PAGES = process.env.PAGES, ZIPDIR = process.env.ZIPDIR;
const DEK = crypto.randomBytes(32);
const fails = []; let current = '';
const ok = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + current + ': ' + n + (!c && x !== undefined ? ' ' + JSON.stringify(x) : '')); if (!c) fails.push(current + ': ' + n); };
const mock = p => fetch(`http://127.0.0.1:${AP}${p}`).then(r => r.json());
const state = () => mock('/__state');
const bytes = () => Uint8Array.from(DEK);
const storage = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), m }; };
const rejects = async (p) => { try { await p; } catch (e) { return e; } return null; };
let KEYS, MPATH;

function walk(d, out = []) { for (const f of fs.readdirSync(d)) { const p = path.join(d, f); fs.statSync(p).isDirectory() ? walk(p, out) : out.push(path.relative(PAGES, p)); } return out; }
const files = () => walk(PAGES).sort();
async function readManifest() { return F.openManifest(KEYS, new Uint8Array(fs.readFileSync(path.join(PAGES, MPATH)))); }
// raw sealing (same layout as encfmt.sealManifest) so tests can plant structurally invalid but authentic manifests
async function sealRaw(m) {
  const enc = new TextEncoder(), pl = enc.encode(JSON.stringify(m)); let n = 1024; while (n < pl.length) n *= 2;
  const plain = new Uint8Array(n); plain.set(pl); const iv = crypto.randomBytes(12), ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(m.counter));
  const aad = Buffer.concat([Buffer.from('TWM1'), ctr]);
  const ct = Buffer.from(await crypto.webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, KEYS.man, plain));
  return Buffer.concat([aad, iv, ct]);
}
async function writeManifest(m) { const p = path.join(PAGES, MPATH); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, await sealRaw(m)); }
async function reset(counter = 1) {
  for (const f of fs.readdirSync(PAGES)) fs.rmSync(path.join(PAGES, f), { recursive: true, force: true });
  await writeManifest({ v: 1, counter, tiddlers: {} });
  await mock('/__defer/0'); await mock('/__inject/off'); await mock('/__ratelimit/off'); await mock('/__reseed');
}
function mk(o = {}) {
  const e = new Engine({
    cfg: Object.assign({ repo: 'o/r', branch: 'master', apiBase: `http://127.0.0.1:${AP}`, base: '' }, o.cfg), dek: bytes(),
    fetch: o.fetch || ((u, i) => fetch(u, i)), baseUrl: o.baseUrl || `http://127.0.0.1:${SP}/`, getToken: () => ('token' in o ? o.token : TOKEN),
    storage: o.storage === undefined ? storage() : o.storage, isBase64Type: t => /^image\//.test(t || ''), categoryOrder: () => [], onStatus: o.onStatus || (() => {}),
    getTargets: o.targets ? () => o.targets : undefined, autoSave: o.autoSave,
    debounceMs: o.debounceMs || 3600000, maxWaitMs: 3600000, setTimeout: o.setTimeout, clearTimeout: o.setTimeout ? () => {} : undefined, requestTimeoutMs: o.requestTimeoutMs
  });
  if (o.keep !== true) live.push(e);
  return e;
}
const live = [];
const ready = async e => { await e.ready; return e; };
const text = async (e, t) => (await e.load(t)).text;
const T = (title, text, extra) => Object.assign({ title, text }, extra);
const tests = [];
const test = (n, fn) => tests.push([n, fn]);

test('round trip, one commit, second engine sees it, no token leak', async () => {
  await reset(); const A = await ready(mk());
  await A.save('N1', T('N1', 'hello ☃', { tags: 'task' })); await A.save('N2', T('N2', 'two')); await A.flush();
  const s = await state();
  ok('one commit', s.commits === 1, s); ok('only bearer token used', s.auths.length === 1 && s.auths[0] === 'Bearer ' + TOKEN, s.auths);
  const B = await ready(mk());
  ok('B lists both', B.titles().sort().join() === 'N1,N2');
  ok('B loads text', (await text(B, 'N1')) === 'hello ☃' && (await text(B, 'N2')) === 'two');
  ok('files = 2 tiddlers + manifest', files().length === 3, files());
  ok('A counter advanced', A.counter === 2 && (await readManifest()).counter === 2);
});

test('concurrent writers: stale device merges instead of clobbering', async () => {
  await reset(); const A = await ready(mk()), B = await ready(mk());
  await B.save('FromB', T('FromB', 'b')); await B.flush();
  await A.save('FromA', T('FromA', 'a')); await A.flush();
  const m = await readManifest();
  ok('both present', Object.keys(m.tiddlers).sort().join() === 'FromA,FromB', Object.keys(m.tiddlers));
  ok('A adopted B entry', A.titles().sort().join() === 'FromA,FromB' && (await text(A, 'FromB')) === 'b');
  ok('counter 3', m.counter === 3, m.counter);
});

test('lost ref race (another writer commits between our head read and PATCH)', async () => {
  await reset(); const B = await ready(mk());
  let fired = false;
  const A = await ready(mk({ fetch: async (u, i) => { if (!fired && i && i.method === 'PATCH') { fired = true; await B.save('Rival', T('Rival', 'r')); await B.flush(); } return fetch(u, i); } }));
  await A.save('Mine', T('Mine', 'm')); await A.flush();
  const m = await readManifest();
  ok('rival fired', fired); ok('both survive the race', Object.keys(m.tiddlers).sort().join() === 'Mine,Rival', Object.keys(m.tiddlers));
});

test('same title edited on two devices: revision never goes down, file opens with manifest rev', async () => {
  await reset(); const A = await ready(mk()), B = await ready(mk());
  await A.save('T', T('T', 'v1')); await A.flush();
  const B2 = await ready(mk());   // B2 sees T@1; A edits twice, B2 edits once from the stale rev
  await A.save('T', T('T', 'v2')); await A.save('T', T('T', 'v3')); await A.flush();   // rev 3 after both saves? (sealed per save: rev 2 then 3)
  const rA = (await readManifest()).tiddlers.T.r;
  await B2.save('T', T('T', 'from-b2')); await B2.flush();
  const e = (await readManifest()).tiddlers.T;
  ok('rev strictly increased over A\'s', e.r > rA, [rA, e.r]);
  const C = await ready(mk());
  ok('fresh device decrypts file with manifest rev (AAD match)', (await text(C, 'T')) === 'from-b2');
  await A.save('Other', T('Other', 'o')); await A.flush();   // A merges B2's newer T into its view; its cached blob for that path is outdated
  ok('A adopts new entry and loads it (no stale cached blob)', (await text(A, 'T')) === 'from-b2');
  ok('hash in manifest matches the file', (await F.sha256Hex(fs.readFileSync(path.join(PAGES, e.p)))) === e.h);
});

test('delete then re-add before flush does not rewind revision', async () => {
  await reset(); const A = await ready(mk());
  await A.save('T', T('T', 'a')); await A.save('T', T('T', 'b')); await A.save('T', T('T', 'c')); await A.flush();   // rev 3
  await A.remove('T'); await A.save('T', T('T', 'again'));   // local rev restarts at 1
  await A.flush();
  const e = (await readManifest()).tiddlers.T;
  ok('rev > 3', e.r > 3, e.r);
  const B = await ready(mk()); ok('opens', (await text(B, 'T')) === 'again');
});

test('category moves (twice before flush) leave exactly one file, never delete a missing path', async () => {
  await reset(); const A = await ready(mk());
  await A.save('M', T('M', 'x', { tags: 'alpha' })); await A.flush();
  const f1 = files().length;
  await A.save('M', T('M', 'x', { tags: 'beta' })); await A.save('M', T('M', 'x', { tags: 'gamma' })); await A.flush();
  const m = await readManifest();
  ok('single entry in gamma', m.tiddlers.M.c === 'gamma');
  ok('same file count (old removed, intermediate never created)', files().length === f1, [files().length, f1]);
  ok('no failed commit attempts', (await state()).commits === 2);
  await A.save('M', T('M', 'x', { tags: 'beta' })); await A.save('M', T('M', 'x2', { tags: 'gamma' })); await A.flush();   // away and back within one batch
  ok('away-and-back keeps one file', files().length === f1 && (await readManifest()).tiddlers.M.c === 'gamma');
  const B = await ready(mk()); ok('loads', (await text(B, 'M')) === 'x2');
});

test('rename = delete + add in one commit; remote category move vs local edit', async () => {
  await reset(); const A = await ready(mk()), B = await ready(mk());
  await A.save('Old', T('Old', 'o', { tags: 'alpha' })); await A.flush();
  const B2 = await ready(mk());
  await A.remove('Old'); await A.save('New', T('New', 'o', { tags: 'alpha' })); await A.flush();
  const m = await readManifest(); ok('rename', Object.keys(m.tiddlers).join() === 'New'); ok('old file gone', files().length === 2, files());
  // B2 is stale: moves a tiddler that A deleted -> resurrects Old (last writer wins) but must not touch New
  await B2.save('Old', T('Old', 'edited-late', { tags: 'beta' })); await B2.flush();
  const m2 = await readManifest(); ok('both exist, files consistent', Object.keys(m2.tiddlers).sort().join() === 'New,Old' && files().length === 3, files());
  // device with stale view of category moves a title that another device has since moved
  const X = await ready(mk()), Y = await ready(mk());
  await X.save('New', T('New', 'o', { tags: 'gamma' })); await X.flush();
  await Y.save('New', T('New', 'y', { tags: 'delta' })); await Y.flush();
  const m3 = await readManifest(); ok('moved once, old paths removed', m3.tiddlers.New.c === 'delta' && files().length === 3, files());
  const Z = await ready(mk()); ok('Z loads moved', (await text(Z, 'New')) === 'y');
});

test('remote deletion propagates when a stale device commits something else', async () => {
  await reset(); const A = await ready(mk());
  await A.save('Gone', T('Gone', 'g')); await A.save('Stay', T('Stay', 's')); await A.flush();
  const S = await ready(mk()); await A.remove('Gone'); await A.flush();
  await S.save('Other', T('Other', 'o')); await S.flush();
  const m = await readManifest(); ok('Gone stays deleted, others kept', Object.keys(m.tiddlers).sort().join() === 'Other,Stay', Object.keys(m.tiddlers));
  ok('S dropped Gone from memory', S.titles().indexOf('Gone') === -1);
});

test('blob cache never serves a blob that does not match the current manifest entry', async () => {
  await reset(); const A = await ready(mk()), B = await ready(mk());
  await A.save('C', T('C', 'a1')); await A.flush();
  await B.save('C', T('C', 'b1')); await B.flush();   // rewrites same path
  await A.save('D', T('D', 'd')); await A.flush();    // A adopts B's entry for C
  ok('A loads B\'s version', (await text(A, 'C')) === 'b1');
});

test('manifest entries are bound to their title: foreign / hostile paths are rejected', async () => {
  const mkpath = (t, c) => F.filePath(KEYS, t, c);
  const good = async (t, c, over) => Object.assign({ c, p: await mkpath(t, c), r: 1, h: 'a'.repeat(64), s: 1024, f: {} }, over);
  const cases = {
    'path of another title': async () => ({ A: await good('A', 'x', { p: await mkpath('B', 'x') }) }),
    'path of other category': async () => ({ A: await good('A', 'x', { p: await mkpath('A', 'y') }) }),
    'manifest path as entry path': async () => ({ A: await good('A', 'x', { p: MPATH }) }),
    'dot-dot path': async () => ({ A: await good('A', 'x', { p: '../../etc/passwd' }) }),
    'nested prefix path': async () => ({ A: await good('A', 'x', { p: 'zz/' + await mkpath('A', 'x') }) }),
    'bad hash': async () => ({ A: await good('A', 'x', { h: 'zz' }) }),
    'negative rev': async () => ({ A: await good('A', 'x', { r: -1 }) }),
    'fractional rev': async () => ({ A: await good('A', 'x', { r: 1.5 }) }),
    'array as fields': async () => ({ A: await good('A', 'x', { f: [] }) }),
    'null entry': async () => ({ A: null }),
    'tiddlers is array': async () => [],
  };
  for (const [name, mkT] of Object.entries(cases)) {
    await reset(); await writeManifest({ v: 1, counter: 5, tiddlers: await mkT() });
    const e = mk(); const err = await rejects(e.ready);
    ok('rejects ' + name, !!err && e.status.state === 'error', err && err.message);
  }
  await reset(); await writeManifest({ v: 1, counter: 5, tiddlers: { A: await good('A', 'x') } });
  ok('control: valid entry loads', (await ready(mk())).titles().join() === 'A');
});

test('prototype pollution: hostile titles/fields', async () => {
  await reset(); const A = await ready(mk());
  const titles = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'prototype', '__defineGetter__'];
  for (const t of titles) await A.save(t, T(t, 'body-' + t, { tags: '__proto__ constructor', __proto__x: 'y' }));
  await A.save('F', JSON.parse('{"title":"F","text":"f","__proto__":"zzz","constructor":"c","polluted":"yes"}'));
  await A.flush();
  const B = await ready(mk());
  ok('all titles listed', titles.every(t => B.titles().indexOf(t) !== -1), B.titles());
  for (const t of titles) ok('load ' + t, (await text(B, t)) === 'body-' + t);
  ok('entries[__proto__] is own entry, not the prototype', Object.getPrototypeOf(B.entries) === null && Object.prototype.hasOwnProperty.call(B.entries, '__proto__'));
  ok('Object.prototype untouched', Object.keys(Object.prototype).length === 0 && ({}).polluted === undefined && ({}).p === undefined);
  const f = await B.load('F'); ok('field constructor kept, __proto__ field dropped', f.constructor === 'c' && f.polluted === 'yes' && Object.getPrototypeOf(f) === Object.prototype);
  const sk = B.skinny().find(x => x.title === '__proto__'); ok('skinny ok', !!sk && Object.getPrototypeOf(sk) === Object.prototype);
  // an authentic manifest that carries a "__proto__" key straight from JSON.parse
  await reset();
  const p = await F.filePath(KEYS, '__proto__', 'x');
  await writeManifest(JSON.parse('{"v":1,"counter":9,"tiddlers":{"__proto__":{"c":"x","p":"' + p + '","r":1,"h":"' + 'b'.repeat(64) + '","s":1,"f":{"__proto__":"x","a":"b"}}}}'));
  const C = await ready(mk()); ok('manifest __proto__ key adopted as own key only', C.titles().join() === '__proto__' && ({}).c === undefined && C.entries['__proto__'].f.a === 'b');
});

test('Pages skew / tampering: stale manifest with new files, swapped files, truncated files', async () => {
  await reset(); const A = await ready(mk());
  await A.save('P', T('P', 'one')); await A.save('Q', T('Q', 'qq')); await A.flush();
  const m1 = await readManifest(); const mfile = path.join(PAGES, MPATH);
  const oldManifest = fs.readFileSync(mfile), oldP = fs.readFileSync(path.join(PAGES, m1.tiddlers.P.p));
  await A.save('P', T('P', 'two')); await A.flush();
  const m2 = await readManifest();
  // 1. old manifest + new file
  fs.writeFileSync(mfile, oldManifest);
  let B = await ready(mk()); ok('old manifest adopted', B.entries.P.r === m1.tiddlers.P.r);
  let err = await rejects(B.load('P')); ok('old manifest + new file => integrity failure (no data returned)', !!err && /integrity/.test(err.message), err && err.message);
  ok('untouched file still loads', (await text(B, 'Q')) === 'qq');
  // 2. new manifest + old file
  await writeManifest(m2); fs.writeFileSync(path.join(PAGES, m2.tiddlers.P.p), oldP);
  B = await ready(mk()); err = await rejects(B.load('P')); ok('new manifest + old file => integrity failure', !!err && /integrity/.test(err.message));
  // 3. swapped files between titles (hashes in manifest do not match)
  await reset(); const A2 = await ready(mk());
  await A2.save('P', T('P', 'pp')); await A2.save('Q', T('Q', 'qq')); await A2.flush(); const m = await readManifest();
  const fp = path.join(PAGES, m.tiddlers.P.p), fq = path.join(PAGES, m.tiddlers.Q.p), bp = fs.readFileSync(fp);
  fs.writeFileSync(fp, fs.readFileSync(fq)); fs.writeFileSync(fq, bp);
  B = await ready(mk()); ok('swap P<->Q rejected both ways', !!(await rejects(B.load('P'))) && !!(await rejects(B.load('Q'))));
  // 4. even if the manifest were forged to carry the swapped hash (needs the key), the AAD binds title
  const forged = JSON.parse(JSON.stringify(m)); forged.tiddlers.P.h = await F.sha256Hex(fs.readFileSync(fp)); await writeManifest(forged);
  B = await ready(mk()); err = await rejects(B.load('P')); ok('AAD blocks file of another title even with matching hash', !!err && !/integrity/.test(err.message), err && err.message);
  // 5. truncated and garbage files
  fs.writeFileSync(fp, bp.subarray(0, 40)); forged.tiddlers.P.h = await F.sha256Hex(bp.subarray(0, 40)); await writeManifest(forged);
  B = await ready(mk()); ok('truncated file rejected', !!(await rejects(B.load('P'))));
});

test('CDN skew: stale copy on first fetch, cache-busted retry succeeds', async () => {
  await reset(); const A = await ready(mk());
  await A.save('K', T('K', 'v1')); await A.flush(); const m1 = await readManifest(); const old = fs.readFileSync(path.join(PAGES, m1.tiddlers.K.p)), oldM = fs.readFileSync(path.join(PAGES, MPATH));
  await A.save('K', T('K', 'v2')); await A.flush();
  const stale = u => { const x = new URL(u); return x.search === '' ? (x.pathname.endsWith(MPATH) ? oldM : old) : null; };
  const urls = [];
  const st = storage(); st.setItem('tw-enc-sync/counter/' + MPATH, '3');   // this browser has seen the newest manifest
  const B = await ready(mk({ storage: st, fetch: async (u, i) => { urls.push(u); const s = stale(u); return s ? new Response(s) : fetch(u, i); } }));
  ok('manifest: stale copy detected via counter, busted refetch gave the newest', B.counter === 3 && !B.status.warning, [B.counter, B.status.warning]);
  ok('retry used a cache-buster', urls.some(u => /\?v=/.test(u)));
  ok('final entry is newest', B.entries.K.r === 2, B.entries.K.r);
  ok('file loads after busted retry', (await text(B, 'K')) === 'v2');
});

test('anti-rollback counter: per-wiki key, warning on older manifest, refusal to commit on a rolled-back repo', async () => {
  await reset(); const st = storage(); const A = await ready(mk({ storage: st }));
  await A.save('R', T('R', 'r1')); await A.flush(); await A.save('R', T('R', 'r2')); await A.flush();   // counter 3
  const key = [...st.m.keys()]; ok('namespaced key', key.length === 1 && key[0].indexOf(MPATH) !== -1, key);
  ok('seen counter == 3', st.getItem(key[0]) === '3');
  const n = (await mock('/__history')).n; ok('history has 3 heads', n === 3, n);
  await mock('/__sethead/1');   // malicious writer rolls the branch back to counter 2 (Pages rolls back too)
  const B = await ready(mk({ storage: st }));
  ok('load-time warning about older manifest', /backwards/.test(B.status.warning || ''), B.status);
  ok('different wiki (other key) not affected', !/backwards/.test((await ready(mk({ storage: storage() }))).status.warning || ''));
  const before = (await state()).commits;
  await B.save('R2', T('R2', 'x')); const err = await rejects(B.flush());
  ok('commit refused', !!err && err.fatal === true && /rollback/i.test(err.message), err && err.message);
  ok('nothing committed, pending kept, no auto-retry timer', (await state()).commits === before && B.pending.size === 1 && B.timer === null);
  ok('counter in storage not lowered', st.getItem(key[0]) === '3');
  B.acceptRollback(); await B.flush();
  const m = await readManifest(); ok('after explicit accept it commits on top (counter 3)', m.counter === 3 && !!m.tiddlers.R2, m.counter);
  ok('storage reset to accepted state', st.getItem(key[0]) === '3');
});

test('token missing / failed PATCH / partial upload: memory stays consistent and nothing is lost', async () => {
  await reset(); let tok; const A = await ready(mk({ token: undefined, fetch: (u, i) => fetch(u, i) }));
  await A.save('E1', T('E1', 'one'));
  let err = await rejects(A.flush()); ok('token missing => error', !!err && /token/i.test(err.message) && A.status.state === 'error');
  ok('entry + pending retained', A.pending.size === 1 && !!A.entries.E1); ok('retry timer scheduled with back-off', A.timer !== null && A.failures === 1);
  // exhausted ref races
  const B = await ready(mk()); await B.save('E2', T('E2', 'two'));
  await mock('/__fail/5'); err = await rejects(B.flush()); ok('422 x3 => rejected', !!err && err.status === 422);
  ok('state intact after failed PATCH', B.pending.size === 1 && B.entries.E2.r === 1 && B.counter === 1);
  await mock('/__fail/0'); await B.flush(); ok('later flush succeeds with same data', (await readManifest()).tiddlers.E2.r === 1);
  // partial upload: 2nd blob POST fails
  const C = (() => { let n = 0; return mk({ fetch: (u, i) => (i && i.method === 'POST' && /git\/blobs/.test(u) && ++n === 2 ? Promise.resolve(new Response('{"message":"boom"}', { status: 500 })) : fetch(u, i)) }); })();
  await ready(C); await C.save('E3', T('E3', 'three')); await C.save('E4', T('E4', 'four'));
  const before = (await state()).commits; err = await rejects(C.flush());
  ok('partial upload fails the flush, no commit', !!err && (await state()).commits === before && C.pending.size === 2, err && err.message);
  await C.flush(); const m = await readManifest(); ok('retry commits everything', !!m.tiddlers.E3 && !!m.tiddlers.E4 && C.pending.size === 0);
  // lost PATCH response: the commit happened but the client saw a network error
  let drop = true; const D = await ready(mk({ fetch: async (u, i) => { const r = await fetch(u, i); if (drop && i && i.method === 'PATCH') { drop = false; throw new TypeError('network down ' + TOKEN); } return r; } }));
  await D.save('E5', T('E5', 'five')); err = await rejects(D.flush());
  ok('network error does not leak token', !!err && String(err.message).indexOf(TOKEN) === -1 && JSON.stringify(D.status).indexOf(TOKEN) === -1, err && err.message);
  await D.flush(); const e5 = (await readManifest()).tiddlers.E5; ok('replayed commit is idempotent (rev stays 1)', e5.r === 1, e5.r);
  ok('E5 loads', (await text(await ready(mk()), 'E5')) === 'five');
});

test('save/remove are applied in call order even when issued concurrently', async () => {
  await reset(); const A = await ready(mk());
  await Promise.all([A.save('S', T('S', 'a')), A.save('S', T('S', 'b')), A.remove('S'), A.save('S', T('S', 'c')), A.save('Z', T('Z', 'z')), A.remove('Z')]);
  await A.flush(); const m = await readManifest();
  ok('final state: S=c, Z gone', Object.keys(m.tiddlers).join() === 'S' && m.tiddlers.S.r >= 1 && (await text(await ready(mk()), 'S')) === 'c');
});

test('github client: validation, no token echo, no foreign hosts', async () => {
  const base = { repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'ghp_abc', fetch: () => Promise.reject(new Error('x')) };
  const bad = o => { try { new G.Client(Object.assign({}, base, o)); return false; } catch (e) { return String(e.message).indexOf('ghp_abc') === -1 && String(e.message).indexOf('SECRET') === -1; } };
  ok('control ok', !bad({}));
  for (const [n, o] of Object.entries({
    'repo ../..': { repo: '../..' }, 'repo ./x': { repo: './x' }, 'repo with query': { repo: 'o/r?x=1' }, 'branch ..': { branch: 'a/../b' }, 'branch trailing slash': { branch: 'a/' },
    'api userinfo': { apiBase: 'https://api.github.com@evil.com' }, 'api http remote': { apiBase: 'http://evil.com' }, 'api dot seg': { apiBase: 'https://api.github.com/../x' },
    'api query': { apiBase: 'https://api.github.com?x' }, 'api http localhost+path': { apiBase: 'http://localhost:1/x' }, 'api trailing slash': { apiBase: 'https://api.github.com/' }, 'api backslash': { apiBase: 'https://evil.com\\@api.github.com' },
    'token newline': { token: 'SECRET\nX-Evil: 1' }, 'token empty': { token: '  ' }, 'token non-string': { token: 5 }
  })) ok('rejects ' + n, bad(o));
  ok('GHES base accepted', !bad({ apiBase: 'https://ghe.example.com/api/v3' }));
  const c = new G.Client(Object.assign({}, base, { fetch: () => Promise.reject(new TypeError('headers: Bearer ghp_abc')) }));
  const err = await rejects(c.getHead()); ok('transport errors are scrubbed', !!err && err.message.indexOf('ghp_abc') === -1 && err.status === 0, err && err.message);
  const e2 = await rejects(c.getRaw('../etc/passwd', 'a'.repeat(40))); ok('getRaw refuses odd path', !!e2);
  const e3 = await rejects(c.getRaw('m/' + 'a'.repeat(32) + '.bin', 'master?x')); ok('getRaw refuses non-sha ref', !!e3);
  const e4 = await rejects(c.commit({ commit: 'a'.repeat(40), tree: 'b'.repeat(40) }, [{ path: '../x', sha: null }], 'm')); ok('commit refuses odd path', !!e4);
  // token only goes to the configured base
  const seen = []; const c2 = new G.Client(Object.assign({}, base, { apiBase: `http://127.0.0.1:${AP}`, token: TOKEN, fetch: (u, i) => { seen.push([u, i.headers.Authorization]); return fetch(u, i); } }));
  await c2.getHead(); ok('requests stay on apiBase', seen.every(([u]) => u.indexOf(`http://127.0.0.1:${AP}/repos/o/r/`) === 0));
});

test('engine fetches only fixed-shape paths; hostile cfg is rejected', async () => {
  await reset();
  ok('bad base rejected', !!(() => { try { mk({ keep: true }); new Engine({ cfg: { repo: 'o/r', branch: 'master', apiBase: 'x', base: '../' }, dek: bytes() }); } catch (e) { return e; } })());
  const urls = []; const A = await ready(mk({ fetch: (u, i) => { urls.push(u); return fetch(u, i); } }));
  await A.save('x/../../y', T('x/../../y', 'p')); await A.save('a?b#c', T('a?b#c', 'q')); await A.flush();
  const B = await ready(mk({ fetch: (u, i) => { urls.push(u); return fetch(u, i); } }));
  await B.load('x/../../y'); await B.load('a?b#c');
  ok('all page fetches match path shape', urls.filter(u => u.indexOf(`:${SP}/`) !== -1).every(u => new RegExp(`^http://127\\.0\\.0\\.1:${SP}/(?:[0-9a-f]{12}/[0-9a-f]{32}|m/[0-9a-f]{32})\\.bin(\\?v=[0-9a-f]+)?$`).test(u)), urls.filter(u => u.indexOf(':' + SP) !== -1));
});

test('rate limit: 429 + Retry-After is honoured, no hammering, uploaded blobs are not re-sent', async () => {
  await reset(); const waits = [], posts = [];
  const A = await ready(mk({ debounceMs: 1000, setTimeout: (fn, ms) => { waits.push(ms); return 1; }, fetch: (u, i) => { if (i && i.method === 'POST' && /git\/blobs/.test(u)) posts.push(1); return fetch(u, i); } }));
  for (let n = 0; n < 5; n++) await A.save('R' + n, T('R' + n, 'body' + n));
  waits.length = 0;
  await mock('/__ratelimit/3/120');
  const req0 = (await state()).n;
  const err = await rejects(A.flush());
  ok('429 surfaced with status and retry hint', !!err && err.status === 429 && err.retryAfterMs === 120000, err && [err.status, err.retryAfterMs]);
  ok('next attempt scheduled no earlier than Retry-After', waits.length === 1 && waits[0] >= 120000, waits);
  ok('state error but nothing lost', A.status.state === 'error' && A.pending.size === 5);
  ok('single failed attempt did not loop on 429', (await state()).n - req0 < 20, (await state()).n - req0);
  const before = posts.length; await mock('/__ratelimit/off');
  await A.flush();
  ok('second attempt skipped blobs already stored (<= 4 of 6 re-sent)', posts.length - before <= 4, posts.length - before);
  const m = await readManifest(); ok('all 5 committed', Object.keys(m.tiddlers).length === 5 && A.pending.size === 0);
  // header-less secondary rate limit (403 + message) and primary limit via X-RateLimit-Reset
  const mkc = (status, msg, hdr) => new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'tok', fetch: async () => new Response(JSON.stringify({ message: msg }), { status, headers: hdr }) });
  let e = await rejects(mkc(403, 'You have exceeded a secondary rate limit', {}).getHead()); ok('403 secondary limit => >= 60 s', e.status === 403 && e.retryAfterMs === 60000, e.retryAfterMs);
  e = await rejects(mkc(403, 'Resource not accessible', {}).getHead()); ok('plain 403 => no retry hint', !e.retryAfterMs);
  e = await rejects(mkc(403, 'API rate limit exceeded', { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 300) }).getHead()); ok('primary limit uses X-RateLimit-Reset', e.retryAfterMs > 280000 && e.retryAfterMs <= 300000, e.retryAfterMs);
  e = await rejects(mkc(429, 'x', { 'retry-after': new Date(Date.now() + 30000).toUTCString() }).getHead()); ok('Retry-After as HTTP date', e.retryAfterMs > 20000 && e.retryAfterMs <= 31000, e.retryAfterMs);
  e = await rejects(mkc(429, 'x', { 'retry-after': '99999999' }).getHead()); ok('Retry-After clamped to 1 h', e.retryAfterMs === 3600000, e.retryAfterMs);
  e = await rejects(mkc(429, 'x', { 'retry-after': 'garbage' }).getHead()); ok('garbage Retry-After => default 60 s', e.retryAfterMs === 60000, e.retryAfterMs);
  e = await rejects(mkc(500, 'x', {}).getHead()); ok('500 => no retry hint, engine back-off applies', !e.retryAfterMs && e.status === 500);
});

test('GitHub error text is sanitised for the UI and never contains the token', async () => {
  const tok = 'ghp_SECRETSECRET123';
  const c = new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: tok, fetch: async () => new Response(JSON.stringify({ message: '<$button message="x">{{$:/secret}}</$button> [[a|b]] ' + tok + ' \u202E\u0000' + 'A'.repeat(500) }), { status: 422 }) });
  const e = await rejects(c.getHead());
  ok('no markup / wikitext metacharacters', !!e && !/[<>{}\[\]|$]/.test(e.message.replace(/^GitHub API GET 422 \(step: read ref\): /, '')), e && e.message);
  ok('no token, bounded length, ASCII only', e.message.indexOf(tok) === -1 && e.message.length < 260 && /^[\x20-\x7e]*$/.test(e.message), e.message);
});

test('hostile response shapes from the API are rejected, not trusted', async () => {
  const mkc = body => new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'tok', fetch: async () => new Response(body, { status: 200 }) });
  for (const b of ['null', '[]', '{"object":{"sha":"../../x"}}', '{"object":{"sha":"' + 'A'.repeat(40) + '"}}', '{"object":{"sha":5}}', 'not json', '']) {
    ok('getHead rejects ' + b.slice(0, 30), !!(await rejects(mkc(b).getHead())));
  }
  ok('createBlob rejects bad sha', !!(await rejects(mkc('{"sha":"zz"}').createBlob(new Uint8Array(1)))));
  ok('commit rejects tree response without sha', !!(await rejects(mkc('{"tree":{}}').commit({ commit: 'a'.repeat(40), tree: 'b'.repeat(40) }, [], 'm'))));
  const p = JSON.parse('{"object":{"sha":"' + 'a'.repeat(40) + '","__proto__":{"polluted":1}},"__proto__":{"polluted":2}}');
  await rejects(mkc(JSON.stringify(p)).getHead()); ok('no prototype pollution', ({}).polluted === undefined);
});

test('git protocol: only 100644 blobs on hex .bin paths, sibling site files survive, sub-directory base', async () => {
  await reset();
  const w = (rel, data) => { const f = path.join(PAGES, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, data); };
  const site = { 'CNAME': 'example.org\n', 'index.html': '<html>', '.nojekyll': '', 'assets/app.js': 'x', 'wk/index.html': 'w', 'wk/README.md': 'r', ['other/12345678901a/' + 'a'.repeat(32) + '.bin']: 'foreign' };
  for (const [k, v] of Object.entries(site)) w(k, v);
  w('wk/' + MPATH, fs.readFileSync(path.join(PAGES, MPATH))); fs.rmSync(path.join(PAGES, MPATH.split('/')[0]), { recursive: true });
  await mock('/__reseed'); const nTrees0 = (await mock('/__trees')).length;
  const A = await ready(mk({ cfg: { base: 'wk/' } }));
  for (const t of ['a', 'b', 'c', 'd']) await A.save(t, T(t, t + '1', { tags: 'x' }));
  await A.flush();
  await A.save('a', T('a', 'a2', { tags: 'y' })); await A.remove('b'); await A.remove('c'); await A.save('e', T('e', 'e', { type: 'image/png' })); await A.flush();   // category move + deletes + create
  await A.remove('a'); await A.remove('d'); await A.remove('e'); await A.flush();
  for (const [k, v] of Object.entries(site)) ok('site file untouched: ' + k, fs.existsSync(path.join(PAGES, k)) && fs.readFileSync(path.join(PAGES, k), 'utf8') === v);
  ok('everything else is under wk/', files().filter(f => !(f in site)).every(f => /^wk\/(?:m|[0-9a-f]{12})\/[0-9a-f]{32}\.bin$/.test(f)), files());
  ok('manifest at base path, no root-level manifest', fs.existsSync(path.join(PAGES, 'wk', MPATH)) && !fs.existsSync(path.join(PAGES, MPATH)));
  const trees = (await mock('/__trees')).slice(nTrees0); ok('three commits', trees.length === 3, trees.length);
  const re = /^wk\/(?:m|[0-9a-f]{12})\/[0-9a-f]{32}\.bin$/;
  ok('every tree entry: mode 100644, blob, hex .bin path under base, null sha only for deletes', trees.every(t => t.tree.every(e => e.mode === '100644' && e.type === 'blob' && re.test(e.path) && (e.sha === null || /^[0-9a-f]{40}$/.test(e.sha)))));
  ok('deletions never name the manifest', trees.every(t => t.tree.every(e => e.sha !== null || e.path !== 'wk/' + MPATH)));
  const B = await ready(mk({ cfg: { base: 'wk/' } })); ok('second device reads from base', B.titles().length === 0 && B.counter === A.counter);
  // hostile base values never reach a URL
  for (const b of ['../', '/', '//evil/', 'a//', 'a/../', '.hidden/', 'a\\b/', 'a%2e%2e/', 'a b/', 'http://evil/', 'a?b/']) {
    ok('rejects base ' + JSON.stringify(b), !!(() => { try { new Engine({ cfg: { repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', base: b }, dek: bytes(), baseUrl: 'https://x.github.io/' }); } catch (e) { return e; } })());
  }
  ok('non-string base rejected', !!(() => { try { new Engine({ cfg: { repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', base: ['wk/'] }, dek: bytes(), baseUrl: 'https://x.github.io/' }); } catch (e) { return e; } })());
});

test('repoBase: wiki in a sub-folder of the repo (vault/): fetch relative to tw.html, commit under vault/', async () => {
  await reset();
  const w = (rel, data) => { const f = path.join(PAGES, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, data); };
  const site = { 'index.html': '<html>', 'content/blog/x/index.md': '# post', 'vault/tw.html': '<html>stage-1' };
  for (const [k, v] of Object.entries(site)) w(k, v);
  w('vault/' + MPATH, fs.readFileSync(path.join(PAGES, MPATH))); fs.rmSync(path.join(PAGES, MPATH.split('/')[0]), { recursive: true });
  await mock('/__reseed'); const nTrees0 = (await mock('/__trees')).length;
  const page = `http://127.0.0.1:${SP}/vault/tw.html`;
  const A = await ready(mk({ cfg: { repoBase: 'vault/' }, baseUrl: page }));
  for (const t of ['a', 'b']) await A.save(t, T(t, t + '1', { tags: 'x' }));
  await A.flush(); await A.remove('b'); await A.flush();
  for (const [k, v] of Object.entries(site)) ok('repoBase: site file untouched: ' + k, fs.readFileSync(path.join(PAGES, k), 'utf8') === v);
  ok('repoBase: every encrypted file is under vault/', files().filter(f => !(f in site)).every(f => /^vault\/(?:m|[0-9a-f]{12})\/[0-9a-f]{32}\.bin$/.test(f)), files());
  const trees = (await mock('/__trees')).slice(nTrees0);
  ok('repoBase: every tree path starts with vault/', trees.length === 2 && trees.every(t => t.tree.every(e => /^vault\/(?:m|[0-9a-f]{12})\/[0-9a-f]{32}\.bin$/.test(e.path))), trees.map(t => t.tree.map(e => e.path)));
  const B = await ready(mk({ cfg: { repoBase: 'vault/' }, baseUrl: page }));
  ok('repoBase: second device loads from /vault/ relative to tw.html', B.titles().join() === 'a' && (await text(B, 'a')) === 'a1');
  for (const b of ['../', '/', 'a/../', '.hidden/', '..', 'vault', 'a b/', 'http://evil/']) {
    ok('repoBase: rejects ' + JSON.stringify(b), !!(() => { try { new Engine({ cfg: { repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', base: '', repoBase: b }, dek: bytes(), baseUrl: 'https://x.github.io/' }); } catch (e) { return e; } })());
  }
});

test('cfg snapshot, injected <base href> / foreign origin, oversized tiddler', async () => {
  await reset();
  const cfg = { repo: 'o/r', branch: 'master', apiBase: `http://127.0.0.1:${AP}`, base: '' };
  const A = await ready(new Engine({ cfg, dek: bytes(), fetch: (u, i) => fetch(u, i), baseUrl: `http://127.0.0.1:${SP}/`, getToken: () => TOKEN, storage: storage(), isBase64Type: () => false, categoryOrder: () => [], onStatus: () => {}, debounceMs: 3600000 }));
  live.push(A);
  cfg.apiBase = 'https://evil.example'; cfg.repo = 'evil/x'; cfg.base = 'zz/';
  ok('engine keeps a private copy of cfg', A.cfg.apiBase.indexOf('127.0.0.1') !== -1 && A.cfg.repo === 'o/r' && A.base === '');
  await A.save('s', T('s', 's')); await A.flush(); ok('commit still went to the original repo', (await state()).commits === 1);
  const prev = globalThis.location;
  globalThis.location = { origin: `http://127.0.0.1:${SP}` };
  try {
    const mkb = u => () => new Engine({ cfg: { repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', base: '' }, dek: bytes(), baseUrl: u });
    ok('same-origin baseUrl accepted', !(() => { try { mkb(`http://127.0.0.1:${SP}/dir/`)(); } catch (e) { return e; } })());
    for (const u of ['https://evil.example/', `http://127.0.0.1:${SP + 1}/`, 'http://evil.example:' + SP + '/', 'not a url', undefined]) ok('rejects baseUrl ' + u, !!(() => { try { mkb(u)(); } catch (e) { return e; } })());
  } finally { if (prev === undefined) delete globalThis.location; else globalThis.location = prev; }
  const big = await ready(mk()); const e = await rejects(big.save('huge', { title: 'huge', text: 'x'.repeat(128 * 1048576) }));
  ok('tiddler larger than the readable limit is refused at save time', !!e && /too large/.test(e.message) && big.pending.size === 0, e && e.message);
});

/* ======================================================================================================================================
   Local-first workflow: reconcile / seed, local save targets (zip, folder), target selection, diagnostics
   ====================================================================================================================================== */
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const FILE_DIR = 'file:///C:/Users/x/Notes/wiki/', FILE_BASE = FILE_DIR + 'tw.html';
// A page opened from file:// : encrypted files come from the "local folder" (= the static server's dir), the API stays http
const fileFetch = (inner) => async (u, i) => {
  if (String(u).indexOf(FILE_DIR) !== 0) return (inner || fetch)(u, i);
  const r = await fetch('http://127.0.0.1:' + SP + '/' + String(u).slice(FILE_DIR.length), Object.assign({}, i, { mode: undefined }));
  return new Response(await r.arrayBuffer(), { status: r.status });
};
const mkLocal = (o = {}) => mk(Object.assign({}, o, { baseUrl: FILE_BASE, fetch: fileFetch(o.fetch) }));
const headFiles = () => mock('/__headfiles');
const headBytes = async p => new Uint8Array(await (await fetch(`http://127.0.0.1:${AP}/__headfile/${p}`)).arrayBuffer());
const headManifest = async () => F.openManifest(KEYS, await headBytes(MPATH));
const memSink = () => ({ name: 'mem', plans: [], write: async function (plan, o) { this.plans.push({ plan, o }); return {}; } });
const localFile = p => fs.readFileSync(path.join(PAGES, p));
const MSG_TOKEN_FREE = (...xs) => xs.every(x => String(typeof x === 'string' ? x : JSON.stringify(x)).indexOf(TOKEN) === -1);

test('fresh repository (manifest 404), page opened from file://: publish seeds it from the local copy in ONE commit, no rollback refusal', async () => {
  await reset(); const A = await ready(mk());
  await A.save('N1', T('N1', 'hello ☃', { tags: 'task' })); await A.save('N2', T('N2', 'two')); await A.save('Img', T('Img', Buffer.from('not really a png').toString('base64'), { type: 'image/png' }));
  await A.flush();                                  // PAGES (= the user's local folder) now holds manifest counter 2 + 3 files
  await mock('/__defer/1'); await mock('/__emptyrepo');   // the repository has none of it
  const st = storage(), infos = [];
  const L = await ready(mkLocal({ storage: st, onStatus: s => infos.push(s.info) }));
  ok('loaded counter 2 from the local copy, nothing written to the anti-rollback store by a file:// load', L.counter === 2 && st.m.size === 0 && L.floor === 0, [L.counter, [...st.m]]);
  const c0 = (await state()).commits;
  const e0 = await rejects(L.flush());   // nothing pending, not forced: no-op
  ok('plain flush with nothing pending does nothing', !e0 && (await state()).commits === c0);
  await L.flush({ force: true });
  const hf = await headFiles();
  ok('exactly one commit', (await state()).commits === c0 + 1, (await state()).commits - c0);
  ok('repository now holds 3 files + manifest, all identical to the local copy', Object.keys(hf).length === 4 && Object.entries(hf).every(([p, h]) => p === MPATH || h === sha256(localFile(p))), Object.keys(hf));
  const hm = await headManifest();
  ok('manifest counter = max(remote 0, local 2) + 1', hm.counter === 3 && Object.keys(hm.tiddlers).sort().join() === 'Img,N1,N2', hm.counter);
  ok('hint shown while seeding, cleared afterwards', infos.some(x => /repository has no manifest yet: it will be seeded from your local files/.test(x || '')) && L.status.info === null && !L.status.error && !!L.status.lastCommit, infos);
  ok('seen counter written after the successful commit', st.getItem('tw-enc-sync/counter/' + MPATH) === '3' && L.counter === 3 && L.floor === 3);
  const again = await rejects(L.flush({ force: true }));
  ok('repeated publish is a no-op (no commit, no error)', !again && (await state()).commits === c0 + 1, again && again.message);
  const again2 = await rejects(L.flush({ force: true }));
  ok('and again', !again2 && (await state()).commits === c0 + 1);
  ok('token only in Authorization', (await state()).auths.join() === 'Bearer ' + TOKEN);
});

test('http-loaded page whose repository suddenly has no manifest is a rollback (refused); explicit accept re-seeds', async () => {
  await reset(); const st = storage(); const A = await ready(mk({ storage: st }));
  await A.save('N1', T('N1', 'one')); await A.flush();   // seen = 2
  await mock('/__defer/1'); await mock('/__emptyrepo');
  const B = await ready(mk({ storage: st }));            // http: floor 2
  await B.save('X', T('X', 'x'));
  const c0 = (await state()).commits, err = await rejects(B.flush());
  ok('refused as fatal rollback', !!err && err.fatal === true && /deleted or rolled back|rollback/i.test(err.message) && (await state()).commits === c0, err && err.message);
  ok('no retry timer, pending kept', B.timer === null && B.pending.size === 1);
  B.acceptRollback(); await B.flush();
  const hm = await headManifest(); ok('after accept: seeded (N1 fetched from the local copy, X from the queue)', Object.keys(hm.tiddlers).sort().join() === 'N1,X' && (await state()).commits === c0 + 1, Object.keys(hm.tiddlers));
});

test('local ahead of a stale NON-empty remote: hash diff uploads only what differs (bytes fetched from the local copy), deletes what is gone locally', async () => {
  await reset(); const A = await ready(mk());
  for (const t of ['Keep', 'Edit', 'Gone']) await A.save(t, T(t, t + '-1'));
  await A.flush(); const h2 = (await mock('/__history')).n - 1;   // repo head at counter 2
  await A.save('Edit', T('Edit', 'Edit-2')); await A.remove('Gone'); await A.save('New', T('New', 'New-1')); await A.flush();   // PAGES at counter 3
  await mock('/__defer/1'); await mock('/__sethead/' + h2);       // repository rolled back to counter 2, the local copy keeps counter 3
  const posts = []; const L = await ready(mkLocal({ fetch: (u, i) => { if (i && i.method === 'POST' && /git\/blobs/.test(u)) posts.push(1); return fetch(u, i); } }));
  ok('local counter 3, nothing pending', L.counter === 3 && L.pending.size === 0);
  const c0 = (await state()).commits; await L.flush({ force: true });
  const hf = await headFiles(), pf = fs.readdirSync(PAGES).flatMap(d => fs.statSync(path.join(PAGES, d)).isDirectory() ? fs.readdirSync(path.join(PAGES, d)).map(f => d + '/' + f) : []);
  ok('one commit', (await state()).commits === c0 + 1);
  ok('Keep not re-uploaded: only Edit, New, manifest (3 blobs)', posts.length === 3, posts.length);
  const hm = await headManifest(); ok('manifest titles = local titles, counter 4', Object.keys(hm.tiddlers).sort().join() === 'Edit,Keep,New' && hm.counter === 4, [Object.keys(hm.tiddlers), hm.counter]);
  ok('repository files == local files (Gone removed), hashes equal', Object.keys(hf).filter(p => p !== MPATH).sort().join() === pf.filter(p => p !== MPATH).sort().join() && Object.entries(hf).every(([p, h]) => p === MPATH || h === sha256(localFile(p))));
  ok('only paths from the authenticated manifest were deleted', (await mock('/__trees')).slice(-1)[0].tree.filter(e => e.sha === null).length === 1);
});

test('equal counters: overlay merge (never overwrites the other device); stale-remote-ahead merge; local counter bump is not a rollback', async () => {
  await reset(); const stA = storage(); const A = await ready(mk({ storage: stA })), B = await ready(mk());
  await B.save('FromB', T('FromB', 'b')); await B.flush();           // remote counter 2
  await A.save('FromA', T('FromA', 'a'));
  const sink = memSink(); await A.saveLocal(sink);
  ok('local save bumped the counter to 2 (== remote) and did not touch the seen counter', A.counter === 2 && stA.getItem('tw-enc-sync/counter/' + MPATH) === '1' && sink.plans.length === 1);
  await A.flush();
  const m = await readManifest();
  ok('overlay: both tiddlers present, B untouched, counter 3', Object.keys(m.tiddlers).sort().join() === 'FromA,FromB' && m.counter === 3, m);
  ok('A adopted B (no local target configured)', A.titles().sort().join() === 'FromA,FromB' && (await text(A, 'FromB')) === 'b');
  // stale remote ahead: remote at 6, local at 2
  await reset(); const C = await ready(mk()), D = await ready(mk());
  for (let n = 0; n < 4; n++) { await D.save('D' + n, T('D' + n, 'd' + n)); await D.flush(); }   // remote counter 5
  await C.save('C1', T('C1', 'c')); await C.saveLocal(memSink()); await C.flush();
  const m2 = await readManifest(); ok('stale device merged into remote counter 5 -> 6', Object.keys(m2.tiddlers).sort().join() === 'C1,D0,D1,D2,D3' && m2.counter === 6, [Object.keys(m2.tiddlers), m2.counter]);
});

test('local save (counter bump) must not trip the rollback refusal when publishing to an older repository', async () => {
  await reset(); const st = storage(); const A = await ready(mk({ storage: st }));
  await A.save('X', T('X', 'x')); await A.saveLocal(memSink());
  ok('local counter ahead of the remote counter', A.counter === 2 && (await readManifest()).counter === 1);
  const c0 = (await state()).commits, err = await rejects(A.flush());
  ok('published (reconcile), no refusal', !err && (await state()).commits === c0 + 1 && (await readManifest()).counter === 3, err && err.message);
  ok('floor/seen follow the REMOTE only', A.floor === 3 && st.getItem('tw-enc-sync/counter/' + MPATH) === '3');
  // genuine rollback still refused even though the local counter is far ahead
  await A.save('Y', T('Y', 'y')); await A.saveLocal(memSink()); await A.saveLocal(memSink(), { force: true });
  await mock('/__sethead/0');   // repo back to the first state (counter 1 < seen 3)
  const e2 = await rejects(A.flush()); ok('rollback below the observed floor is refused', !!e2 && e2.fatal === true, e2 && e2.message);
});

test('reconcile re-seals entries above the remote revision (pending and non-pending), local copy follows', async () => {
  await reset(); const A = await ready(mk()), B = await ready(mk());   // B stays at counter 1 / base
  await A.save('T', T('T', 'v1')); await A.flush();                    // c2: T r1
  const B2 = await ready(mk());
  await A.save('T', T('T', 'v2')); await A.save('T', T('T', 'v3')); await A.flush();   // c3: T r3
  const L = await ready(mk());                                          // loaded c3
  // pending case: L edits T from r3 -> r4? make a stale device instead
  await mock('/__defer/1');
  const S = await ready(mk());       // same state c3 (T r3), will fall behind
  await B2.save('T', T('T', 'b2-edit'));   // B2 loaded at c2 (T r1) -> pending r2 'b2-edit'
  await B2.saveLocal(memSink()); await B2.save('Z', T('Z', 'z')); await B2.saveLocal(memSink());   // B2.counter = 2 + 2 = 4 > remote 3
  const c0 = (await state()).commits; await B2.flush();
  const hm = await headManifest();
  ok('pending T (r2) re-sealed above remote r3', hm.tiddlers.T.r === 4 && (await state()).commits === c0 + 1, hm.tiddlers.T);
  const f = await F.openTiddler(KEYS, 'T', await headBytes(hm.tiddlers.T.p), 4); ok('and opens with AAD rev 4 -> local content wins', F.utf8decode(f.body) === 'b2-edit');
  ok('local copy follows the re-seal: dirty blob == published blob', sha256(B2.localDirty.get(hm.tiddlers.T.p)) === hm.tiddlers.T.h);
  const sink = memSink(); await B2.saveLocal(sink, { force: true });
  ok('next local save writes the new T file', sink.plans[0].plan.files.some(x => x.path === hm.tiddlers.T.p && sha256(x.bytes) === hm.tiddlers.T.h));
  // non-pending case: local copy (PAGES) holds T r2 'local-edit' at a higher counter; repo holds T r2 'remote-edit' at counter 3
  await reset(); const A1 = await ready(mk()); await A1.save('T', T('T', 'v1')); await A1.flush();           // c2
  const Bx = await ready(mk());                                                                          // at c2
  await A1.save('T', T('T', 'local-edit')); await A1.save('Z', T('Z', 'z')); await A1.flush();           // c3 = PAGES
  await A1.save('Z2', T('Z2', 'z2')); await A1.flush();                                                  // c4 = PAGES (local copy)
  await mock('/__defer/1'); await mock('/__sethead/1');                                                  // repo back to c2
  await Bx.save('T', T('T', 'remote-edit')); await Bx.flush();                                          // repo: c3', T r2 remote-edit
  const Lx = await ready(mkLocal()); ok('local copy counter 4, nothing pending', Lx.counter === 4 && Lx.pending.size === 0 && Lx.entries.T.r === 2);
  await Lx.flush({ force: true });
  const hm2 = await headManifest(); const e = hm2.tiddlers.T;
  ok('non-pending T re-sealed to r3', e.r === 3 && hm2.counter === 5, [e.r, hm2.counter]);
  const f2 = await F.openTiddler(KEYS, 'T', await headBytes(e.p), 3); ok('content = local copy', F.utf8decode(f2.body) === 'local-edit');
  ok('local dirty blob matches', Lx.localDirty.has(e.p) && sha256(Lx.localDirty.get(e.p)) === e.h);
});

test('local-first mode (a local target is configured): other devices\' tiddlers are preserved in the commit but not pulled into the local view', async () => {
  await reset(); const A = await ready(mk({ targets: ['folder'] })), B = await ready(mk());
  await B.save('FromB', T('FromB', 'b')); await B.flush();
  await A.save('FromA', T('FromA', 'a')); await A.flush({ force: true });
  const m = await readManifest();
  ok('remote has both', Object.keys(m.tiddlers).sort().join() === 'FromA,FromB');
  ok('local view unchanged (its files are not in the local folder)', A.titles().join() === 'FromA');
});

test('saveLocal: plan content, manifest counter, failure leaves state intact, success clears, edits are not blocked while a sink waits', async () => {
  await reset(); const A = await ready(mk({ targets: ['folder'] }));
  await A.save('M', T('M', 'x', { tags: 'alpha' })); await A.save('G', T('G', 'g')); await A.save('Keep', T('Keep', 'k'));
  const bad = { write: async () => { throw Object.assign(new Error('disk full ' + TOKEN), { code: 'x' }); } };
  const before = A.localDirty.size, err = await rejects(A.saveLocal(bad));
  ok('failure: state intact, status.error set, counter unchanged', !!err && A.localDirty.size === before && A.counter === 1 && /^Local save failed/.test(A.status.error) && before === 3, A.status.error);
  const s1 = memSink(); const r = await A.saveLocal(s1, { interactive: false });
  const p = s1.plans[0].plan;
  ok('success: counter+1, dirty cleared, error cleared', r.saved && A.counter === 2 && A.localDirty.size === 0 && A.status.error === null && p.counter === 2, [A.counter, A.status.error]);
  ok('plan: 3 files, manifest, interactive flag passed', p.files.length === 3 && p.manifest.path === MPATH && p.removals.length === 0 && s1.plans[0].o.interactive === false);
  const pm = await F.openManifest(KEYS, p.manifest.bytes); ok('manifest sealed from current entries with counter 2', pm.counter === 2 && Object.keys(pm.tiddlers).sort().join() === 'G,Keep,M');
  const s2 = memSink(); const r2 = await A.saveLocal(s2); ok('nothing dirty: skipped, no counter bump', r2.skipped && A.counter === 2 && s2.plans.length === 0);
  const oldPath = A.entries.M.p, gPath = A.entries.G.p;
  await A.save('M', T('M', 'x', { tags: 'beta' })); await A.remove('G');
  const s3 = memSink(); await A.saveLocal(s3); const p3 = s3.plans[0].plan;
  ok('category move + delete => removals (old paths) and only the new file', p3.removals.sort().join() === [oldPath, gPath].sort().join() && p3.files.length === 1 && p3.files[0].path === A.entries.M.p && A.entries.M.p !== oldPath, p3.removals);
  ok('counter 3', p3.counter === 3);
  // away and back within one save: nothing removed
  await A.save('M', T('M', 'x', { tags: 'gamma' })); await A.save('M', T('M', 'x', { tags: 'beta' }));
  const s4 = memSink(); await A.saveLocal(s4); ok('away-and-back: the final path is not deleted', !s4.plans[0].plan.removals.includes(A.entries.M.p));
  // a slow sink does not block the edit pipeline
  let release; const slow = { write: () => new Promise(res => { release = res; }) };
  await A.save('S0', T('S0', 's')); const pr = A.saveLocal(slow); await new Promise(r => setTimeout(r, 30));
  const t0 = Date.now(); await A.save('S1', T('S1', 's1')); ok('save() resolves while a sink waits', Date.now() - t0 < 500);
  release({}); await pr; ok('only the snapshot was cleared, the newer edit stays dirty', A.localDirty.size === 1 && A.localDirty.has(A.entries.S1.p));
  // full rewrite
  const s5 = memSink(); await A.saveLocal(s5, { full: true });
  ok('full: every entry file is in the plan', s5.plans[0].plan.files.length === A.titles().length && s5.plans[0].plan.files.every(f => sha256(f.bytes) === A.entries[A.titles().find(t => A.entries[t].p === f.path)].h), [s5.plans[0].plan.files.length, A.titles().length]);
});

test('saveLocal(full) writes every file, hash-verified against the manifest', async () => {
  await reset(); const A = await ready(mk()); await A.save('P', T('P', 'p')); await A.save('Q', T('Q', 'q')); await A.flush();
  const L = await ready(mkLocal({ targets: ['zip'] })); const s = memSink(); await L.saveLocal(s, { full: true });
  const pl = s.plans[0].plan; ok('both files + manifest', pl.files.length === 2 && pl.files.every(f => sha256(f.bytes) === sha256(localFile(f.path))) && pl.counter === L.counter);
  fs.writeFileSync(path.join(PAGES, L.entries.P.p), Buffer.from('corrupt')); const L2 = await ready(mkLocal({ targets: ['zip'] }));
  const err = await rejects(L2.saveLocal(memSink(), { full: true })); ok('a corrupt local file is refused (integrity)', !!err && /integrity|Local save failed/.test(err.message), err && err.message);
});

// ---------------------------------------------------------------------------------------------------------------------------------
// zip
function unzip(buf) {   // tiny independent reader: EOCD -> central directory -> local headers, verifies CRC32 (zlib's, not ours) and stored method
  buf = Buffer.from(buf); let e = buf.length - 22; while (e >= 0 && buf.readUInt32LE(e) !== 0x06054b50) e--;
  if (e < 0) throw new Error('no EOCD'); const n = buf.readUInt16LE(e + 10), cdSize = buf.readUInt32LE(e + 12), cdOff = buf.readUInt32LE(e + 16);
  if (cdOff + cdSize !== e) throw new Error('central directory does not end at EOCD');
  const out = []; let p = cdOff;
  for (let i = 0; i < n; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad central header');
    const flags = buf.readUInt16LE(p + 8), method = buf.readUInt16LE(p + 10), crc = buf.readUInt32LE(p + 16), csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
    const nl = buf.readUInt16LE(p + 28), xl = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32), lo = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nl).toString('utf8');
    if (buf.readUInt32LE(lo) !== 0x04034b50) throw new Error('bad local header');
    const lnl = buf.readUInt16LE(lo + 26), lxl = buf.readUInt16LE(lo + 28), data = buf.slice(lo + 30 + lnl + lxl, lo + 30 + lnl + lxl + csize);
    if (method !== 0 || csize !== usize || data.length !== usize) throw new Error('not stored');
    if (require('zlib').crc32(data) !== crc) throw new Error('crc mismatch for ' + name);
    if (buf.readUInt32LE(lo + 14) !== crc || buf.slice(lo + 30, lo + 30 + lnl).toString('utf8') !== name) throw new Error('local header differs');
    out.push({ name, data, flags }); p += 46 + nl + xl + cl;
  }
  return out;
}
const zipOf = parts => Buffer.concat(parts.map(x => Buffer.from(x)));
const dumpZip = (name, buf, expect) => { if (!ZIPDIR) return; fs.writeFileSync(path.join(ZIPDIR, name), buf); fs.writeFileSync(path.join(ZIPDIR, name + '.expect.json'), JSON.stringify(expect)); };

test('zip: crc32, store-only layout, UTF-8 names, empty and large entries, limits, name checks', async () => {
  ok('crc32("123456789")', LS.crc32(Buffer.from('123456789')) === 0xCBF43926);
  ok('crc32 matches zlib on random data', LS.crc32(crypto.randomBytes(100000)) !== undefined && (() => { const b = crypto.randomBytes(300001); return LS.crc32(b) === require('zlib').crc32(b); })());
  const big = crypto.randomBytes(3 * 1048576 + 17), files = [{ name: 'ünï/☃ file.txt', bytes: Buffer.from('héllo') }, { name: 'empty', bytes: new Uint8Array(0) }, { name: 'big.bin', bytes: big }, { name: 'a/b/c/d.txt', bytes: Buffer.from('x') }];
  const z = LS.buildZip(files, { now: new Date(2026, 10, 6, 21, 30, 40) }), buf = zipOf(z.parts);
  ok('size accounted', buf.length === z.size);
  const out = unzip(buf);
  ok('names, bytes, UTF-8 flag round trip', out.length === 4 && out.every((o, i) => o.name === files[i].name && Buffer.compare(o.data, Buffer.from(files[i].bytes)) === 0 && (o.flags & 0x800) === 0x800));
  dumpZip('unit.zip', buf, { files: Object.fromEntries(files.map(f => [f.name, sha256(f.bytes)])), order: files.map(f => f.name) });
  for (const bad of ['../x', '/abs', 'a\\b', 'a//b', './x', '', 'a/../b']) ok('rejects name ' + JSON.stringify(bad), !!(() => { try { LS.buildZip([{ name: bad, bytes: new Uint8Array(1) }]); } catch (e) { return e; } })());
  ok('rejects duplicate names', !!(() => { try { LS.buildZip([{ name: 'a', bytes: new Uint8Array(1) }, { name: 'a', bytes: new Uint8Array(1) }]); } catch (e) { return e; } })());
  const huge = (() => { try { LS.buildZip([{ name: 'x', bytes: { length: 1.6 * 1073741824 } }]); } catch (e) { return e; } })();
  ok('fails clearly above 1.5 GiB (before touching data)', !!huge && /too large/.test(huge.message), huge && huge.message);
  const many = (() => { try { LS.buildZip(Array.from({ length: 65536 }, (_, i) => ({ name: 'f' + i, bytes: new Uint8Array(0) }))); } catch (e) { return e; } })();
  ok('fails clearly above 65535 entries (no zip64)', !!many && /too many files/.test(many.message));
});

test('ZipSink + engine: download name, content = changed files + manifest + _remove.txt, only ciphertext', async () => {
  await reset(); const A = await ready(mk({ targets: ['zip'] }));
  await A.save('Secret title', T('Secret title', 'TOP-SECRET-BODY-xyz', { tags: 'task' })); await A.save('Del', T('Del', 'd')); await A.flush({ force: true });
  await A.saveLocal(memSink());                       // baseline
  const delPath = A.entries.Del.p; await A.remove('Del'); await A.save('Second', T('Second', 'TOP-SECRET-BODY-xyz')); await A.save('Secret title', T('Secret title', 'TOP-SECRET-BODY-xyz', { tags: 'security task' }));
  const dl = []; const sink = new LS.ZipSink({ trigger: async (blob, name) => { dl.push({ name, buf: Buffer.from(await blob.arrayBuffer()) }); }, now: new Date(2026, 0, 2, 3, 4, 6) });
  const r = await A.saveLocal(sink);
  ok('one download named tw-update-<counter>.zip', dl.length === 1 && dl[0].name === 'tw-update-' + A.counter + '.zip' && r.saved && A.counter === 4, [dl.map(d => d.name), A.counter]);
  const out = unzip(dl[0].buf), names = out.map(o => o.name), byName = Object.fromEntries(out.map(o => [o.name, o.data]));
  ok('manifest is after the data files, _remove.txt last', names[names.length - 1] === '_remove.txt' && names[names.length - 2] === MPATH && names.length === 4, names);
  const oldCat = (await F.filePath(KEYS, 'Secret title', 'task')), newCat = A.entries['Secret title'].p;
  ok('_remove.txt lists the deleted + moved files, one per line', byName['_remove.txt'].toString() === [delPath, oldCat].sort().join('\n') + '\n' || byName['_remove.txt'].toString().split('\n').filter(Boolean).sort().join() === [delPath, oldCat].sort().join(), byName['_remove.txt'].toString());
  const man = await F.openManifest(KEYS, new Uint8Array(byName[MPATH])); ok('manifest in zip opens, counter 4, entries Second + Secret title', man.counter === 4 && Object.keys(man.tiddlers).sort().join() === 'Second,Secret title');
  ok('every data file hash equals its manifest entry', Object.values(man.tiddlers).every(e => sha256(byName[e.p]) === e.h) && !!byName[newCat]);
  ok('zip contains no plaintext, no token', !Buffer.concat(dl.map(d => d.buf)).includes('TOP-SECRET-BODY') && !dl[0].buf.includes(TOKEN) && !dl[0].buf.includes('Secret title'));
  dumpZip('engine.zip', dl[0].buf, { files: Object.fromEntries(out.map(o => [o.name, sha256(o.data)])), order: names, remove: byName['_remove.txt'].toString() });
  // empty removals => empty _remove.txt still present
  await A.save('Third', T('Third', 't')); const dl2 = []; await A.saveLocal(new LS.ZipSink({ trigger: async (b, n) => { dl2.push(Buffer.from(await b.arrayBuffer())); } }));
  ok('_remove.txt present but empty when nothing to delete', unzip(dl2[0]).find(o => o.name === '_remove.txt').data.length === 0);
  // default download trigger: anchor + blob URL, revoked later; injectable doc/URL
  const log = []; const doc = { body: { appendChild: a => log.push('append'), }, createElement: () => ({ style: {}, click() { log.push('click ' + this.download + ' ' + this.href); }, parentNode: null }) };
  const U = { createObjectURL: b => { log.push('create ' + b.size); return 'blob:x'; }, revokeObjectURL: u => log.push('revoke ' + u) };
  await new LS.ZipSink({ document: doc, URL: U }).write({ counter: 7, files: [], manifest: { path: MPATH, bytes: new Uint8Array(3) }, removals: [] });
  ok('anchor click with blob URL and name', log[0].indexOf('create') === 0 && log.includes('click tw-update-7.zip blob:x'), log);
  const e2 = await rejects(new LS.ZipSink({ trigger: () => {} }).write({ counter: 1, files: [{ path: '../../etc/passwd', bytes: new Uint8Array(1) }], manifest: { path: MPATH, bytes: new Uint8Array(1) }, removals: [] }));
  ok('sink refuses unexpected paths', !!e2);
  const e3 = await rejects(new LS.ZipSink({ trigger: async () => { throw new Error('popup blocked'); } }).write({ counter: 1, files: [], manifest: { path: MPATH, bytes: new Uint8Array(1) }, removals: [] }));
  ok('download failure surfaces', !!e3 && /popup blocked/.test(e3.message));
});

// ---------------------------------------------------------------------------------------------------------------------------------
// folder sink with a fake File System Access directory
function fakeFs(opts = {}) {
  const log = [];
  const nf = () => Object.assign(new Error('not found'), { name: 'NotFoundError' });
  class Dir {
    constructor(name, full) { this.kind = 'directory'; this.name = name; this.full = full; this.kids = new Map(); this.perm = opts.perm || 'granted'; this.reqs = 0; }
    async getDirectoryHandle(n, o = {}) { let k = this.kids.get(n); if (!k) { if (!o.create) throw nf(); k = new Dir(n, this.full + n + '/'); this.kids.set(n, k); log.push('mkdir ' + k.full); } else if (k.kind !== 'directory') throw Object.assign(new Error('x'), { name: 'TypeMismatchError' }); return k; }
    async getFileHandle(n, o = {}) { let k = this.kids.get(n); if (!k) { if (!o.create) throw nf(); k = new File(n, this.full + n); this.kids.set(n, k); } else if (k.kind !== 'file') throw Object.assign(new Error('x'), { name: 'TypeMismatchError' }); return k; }
    async removeEntry(n) { if (!this.kids.has(n)) throw nf(); this.kids.delete(n); log.push('rm ' + this.full + n); }
    async *values() { for (const k of this.kids.values()) yield k; }
    async queryPermission() { return this.perm; }
    async requestPermission() { this.reqs++; if (opts.deny) return 'denied'; this.perm = 'granted'; return 'granted'; }
    file(rel) { const s = rel.split('/'); let d = this; for (const x of s.slice(0, -1)) d = d.kids.get(x); return d && d.kids.get(s[s.length - 1]); }
  }
  class File { constructor(n, full) { this.kind = 'file'; this.name = n; this.full = full; this.data = null; }
    async createWritable() { const self = this; let buf = null; return { async write(b) { buf = Buffer.from(b); }, async close() { self.data = buf; log.push('write ' + self.full); }, async abort() {} }; } }
  const root = new Dir('wiki', ''), store = new Map(), calls = { picker: 0, confirm: 0, del: 0 };
  const sink = (o = {}) => new LS.FolderSink({ picker: async () => { calls.picker++; if (o.cancel) throw Object.assign(new Error('x'), { name: 'AbortError' }); return root; }, confirm: () => { calls.confirm++; return !!o.confirm; },
    store: { get: async k => store.get(k), set: async (k, v) => { store.set(k, v); }, delete: async k => { calls.del++; store.delete(k); } } });
  return { root, log, store, calls, sink, Dir, File };
}
const mkPlan = async (n = 2, removals = []) => {
  const files = []; for (let i = 0; i < n; i++) files.push({ path: (await F.filePath(KEYS, 't' + i, 'cat' + (i % 2))), bytes: crypto.randomBytes(40) });
  return { counter: 9, files, manifest: { path: MPATH, bytes: crypto.randomBytes(50) }, removals };
};
test('FolderSink: refuses a wrong folder, empty folder only with confirmation, writes blobs first / manifest last / deletions after', async () => {
  const plan = await mkPlan(3);
  // 1. wrong folder (something else, no tw.html, no manifest)
  let fx = fakeFs(); await fx.root.getFileHandle('holiday.jpg', { create: true });
  let err = await rejects(fx.sink().write(plan, { interactive: true }));
  ok('wrong folder refused, nothing written, handle not persisted', !!err && err.code === 'wrong-folder' && /does not look like the wiki folder/.test(err.message) && !fx.log.some(l => l.indexOf('write') === 0) && fx.store.size === 0 && fx.calls.picker === 1);
  // 2. empty folder: confirm false -> refused; confirm true -> accepted
  fx = fakeFs(); err = await rejects(fx.sink({ confirm: false }).write(plan, { interactive: true }));
  ok('empty folder without confirmation refused', !!err && fx.calls.confirm === 1 && fx.log.length === 0);
  fx = fakeFs(); const okr = await fx.sink({ confirm: true }).write(plan, { interactive: true });
  ok('empty folder with confirmation accepted and handle persisted', okr.written === 4 && fx.store.size === 1 && fx.store.has(LS.FOLDER_KEY));
  // 3. tw.html present: order
  fx = fakeFs(); await fx.root.getFileHandle('tw.html', { create: true });
  const old1 = (await F.filePath(KEYS, 'old1', 'a')), old2 = (await F.filePath(KEYS, 'old2', 'b'));
  const dd = await fx.root.getDirectoryHandle(old1.split('/')[0], { create: true }); await dd.getFileHandle(old1.split('/')[1], { create: true });
  fx.log.length = 0;
  const plan2 = await mkPlan(3, [old1, old2]); const r = await fx.sink().write(plan2, { interactive: true });
  const w = fx.log.filter(l => /^(write|rm) /.test(l)), mi = w.indexOf('write ' + MPATH);
  ok('manifest written LAST among writes, after every data file', mi === 3 && w.slice(0, 3).every(l => l.startsWith('write ') && l !== 'write ' + MPATH), w);
  ok('deletions come after the manifest; missing file ignored', w[4] === 'rm ' + old1 && r.removed === 1 && w.length === 5, w);
  ok('subdirectories created, bytes exact', plan2.files.every(f => Buffer.compare(fx.root.file(f.path).data, Buffer.from(f.bytes)) === 0) && Buffer.compare(fx.root.file(MPATH).data, Buffer.from(plan2.manifest.bytes)) === 0);
  ok('tw.html untouched', fx.root.kids.has('tw.html') && fx.root.kids.get('tw.html').data === null);
  // 4. manifest but no tw.html
  fx = fakeFs(); const md = await fx.root.getDirectoryHandle('m', { create: true }); await md.getFileHandle(MPATH.split('/')[1], { create: true });
  ok('folder with this wiki\'s manifest (no tw.html) accepted', !(await rejects(fx.sink().write(plan, { interactive: true }))));
  // 5. persisted handle: no picker, silent write when permission is granted
  fx = fakeFs(); await fx.root.getFileHandle('tw.html', { create: true });
  await fx.sink().write(plan, { interactive: true }); const picked = fx.calls.picker;
  const s2 = fx.sink(); ok('hasPermission() true silently', (await s2.hasPermission()) === true && fx.root.reqs === 0);
  await s2.write(plan, { interactive: false }); ok('timer-style write: no picker, no permission request', fx.calls.picker === picked && fx.root.reqs === 0);
  // 6. permission lapsed: non-interactive never prompts
  fx.root.perm = 'prompt'; const s3 = fx.sink(); ok('hasPermission() false when permission lapsed, no prompt', (await s3.hasPermission()) === false && fx.root.reqs === 0);
  err = await rejects(s3.write(plan, { interactive: false })); ok('non-interactive write refused with needs-gesture, no prompt', !!err && err.code === 'needs-gesture' && fx.root.reqs === 0 && fx.calls.picker === picked);
  err = await rejects(s3.write(plan, { interactive: true })); ok('explicit save re-requests permission', !err && fx.root.reqs === 1 && fx.root.perm === 'granted');
  // 7. no stored handle + non-interactive: no picker
  const fy = fakeFs(); err = await rejects(fy.sink().write(plan, { interactive: false })); ok('no handle + timer: needs-gesture, picker never shown', !!err && err.code === 'needs-gesture' && fy.calls.picker === 0 && (await fy.sink().hasPermission()) === false);
  // 8. denied / cancelled
  const fz = fakeFs({ perm: 'prompt', deny: true }); await fz.root.getFileHandle('tw.html', { create: true });
  err = await rejects(fz.sink().write(plan, { interactive: true })); ok('denied permission reported, nothing written', !!err && err.code === 'denied' && !fz.log.some(l => l.indexOf('write') === 0));
  const fc = fakeFs(); err = await rejects(fc.sink({ cancel: true }).write(plan, { interactive: true })); ok('picker cancel reported', !!err && /cancelled/.test(err.message));
  // 9. path hygiene
  const fp = fakeFs(); await fp.root.getFileHandle('tw.html', { create: true });
  for (const bad of ['tw.html', '../x.bin', 'index.html', 'a/b.bin', MPATH + '.x']) ok('refuses path ' + bad, !!(await rejects(fp.sink().write(Object.assign({}, plan, { files: [{ path: bad, bytes: new Uint8Array(1) }] }), { interactive: true }))));
  ok('refuses removal of site files', !!(await rejects(fp.sink().write(Object.assign({}, plan, { removals: ['tw.html'] }), { interactive: true }))));
  ok('unsupported browser detection', LS.FolderSink.supported({}) === false && LS.FolderSink.supported({ showDirectoryPicker() {} }) === true);
  // 10. engine integration: a failing folder leaves everything dirty
  await reset(); const A = await ready(mk({ targets: ['folder'] })); await A.save('Q', T('Q', 'q'));
  const wrong = fakeFs(); await wrong.root.getFileHandle('other.txt', { create: true });
  const e2 = await rejects(A.saveLocal(wrong.sink(), { interactive: true })); ok('wrong folder: engine keeps changes dirty and reports', !!e2 && A.localDirty.size === 1 && A.counter === 1 && /Local save failed/.test(A.status.error));
  const good = fakeFs(); await good.root.getFileHandle('tw.html', { create: true }); await A.saveLocal(good.sink(), { interactive: true });
  ok('then the right folder works', A.localDirty.size === 0 && A.counter === 2 && good.root.file(MPATH) !== undefined && good.log.filter(l => l.startsWith('write ')).pop() === 'write ' + MPATH);
});

// ---------------------------------------------------------------------------------------------------------------------------------
test('target selection', async () => {
  const R = (t, p, f) => TG.resolveTargets(t, { protocol: p, fsa: f }).join();
  ok('file: default folder', R(undefined, 'file:', true) === 'folder'); ok('file: default without FSA falls back to zip', R(undefined, 'file:', false) === 'zip');
  ok('http(s) default github', R(undefined, 'https:', true) === 'github' && R(undefined, 'http:', false) === 'github');
  ok('explicit list, ordered github, folder, zip', R('zip, github ,folder', 'https:', true) === 'github,folder,zip');
  ok('whitespace/comma/case tolerant, unknown ignored, dups dropped', R('  GitHub ;; bogus,, folder  folder\n', 'file:', true) === 'github,folder');
  ok('blank / only unknown tokens => default (a typo never disables saving)', R('', 'file:', true) === 'folder' && R('   ', 'https:', true) === 'github' && R('foo, bar', 'https:', true) === 'github');
  ok('folder without FSA becomes zip, no duplicate', R('folder', 'https:', false) === 'zip' && R('github,folder,zip', 'file:', false) === 'github,zip');
  ok('parseTargets raw', TG.parseTargets('github,Folder, zip, nope').join() === 'github,folder,zip' && TG.parseTargets(undefined).length === 0);
});

test('unload warning only counts enabled targets', async () => {
  const E = (p, l) => ({ pending: { size: p }, localDirty: { size: l } }), W = TG.unloadWarning;
  ok('github target with pending => warns about GitHub', /GitHub/.test(W(E(2, 0), ['github'])));
  ok('github NOT a target: pending alone does not warn', W(E(5, 0), ['folder']) === null && W(E(5, 0), ['zip']) === null);
  ok('local target with localDirty warns', /local folder/.test(W(E(0, 1), ['folder'])) && /zip/.test(W(E(0, 1), ['zip'])));
  ok('local dirty ignored when no local target is enabled', W(E(0, 4), ['github']) === null);
  ok('both', /GitHub/.test(W(E(1, 1), ['github', 'folder'])) && /local/.test(W(E(1, 1), ['github', 'folder'])));
  ok('nothing unsaved => null', W(E(0, 0), ['github', 'folder', 'zip']) === null);
});

test('timer / autosave never prompts or zips; explicit save runs every target in order', async () => {
  await reset();
  const mkCtx = (eng, targets, folderPerm) => {
    const calls = []; const folder = { hasPermission: async () => { calls.push('folder.hasPermission'); return folderPerm; }, access: async () => { calls.push('folder.access'); }, write: async (p, o) => { calls.push('folder.write interactive=' + o.interactive); return {}; } };
    const zip = { write: async (p, o) => { calls.push('zip.write'); return {}; } };
    return { calls, ctx: { engine: eng, getTargets: () => targets, sinks: { folder, zip }, syncer: null } };
  };
  // timer through the real engine: capture the debounce callback
  const timers = [];
  const A = await ready(mk({ targets: ['github', 'folder', 'zip'], setTimeout: (fn, ms) => { timers.push(fn); return timers.length; } })); const c = mkCtx(A, ['github', 'folder', 'zip'], false);
  A.d.autoSave = () => TG.autoSave(c.ctx);
  await A.save('T1', T('T1', 't')); ok('timer armed', timers.length === 1);
  const c0 = (await state()).commits; await timers.pop()(); await new Promise(r => setTimeout(r, 100));
  ok('timer: github flush ran (target), folder probed silently but not written (no permission), zip never', (await state()).commits === c0 + 1 && c.calls.join() === 'folder.hasPermission', c.calls);
  ok('timer: no picker / access() call ever', !c.calls.includes('folder.access'));
  // permission granted: silent write with interactive:false
  const B = await ready(mk({ targets: ['folder', 'zip'] })); const c2 = mkCtx(B, ['folder', 'zip'], true);
  await B.save('T2', T('T2', 't')); const cb = (await state()).commits; await TG.autoSave(c2.ctx);
  ok('timer: folder written silently (interactive=false), github NOT touched (not a target), zip never', c2.calls.join() === 'folder.hasPermission,folder.write interactive=false' && (await state()).commits === cb && B.pending.size === 1 && B.localDirty.size === 0, c2.calls);
  // zip only: timer does nothing at all
  const C = await ready(mk({ targets: ['zip'] })); const c3 = mkCtx(C, ['zip'], true); await C.save('T3', T('T3', 't')); await TG.autoSave(c3.ctx);
  ok('zip-only: timer does nothing', c3.calls.length === 0 && C.localDirty.size === 1);
  // timer through engine without autoSave dep keeps the old behaviour (github flush)
  const timers2 = []; const D = await ready(mk({ setTimeout: (fn) => { timers2.push(fn); return 1; } })); await D.save('T4', T('T4', 't')); const c4 = (await state()).commits; await timers2.pop()(); await new Promise(r => setTimeout(r, 100));
  ok('default timer action = github flush', (await state()).commits === c4 + 1 && D.pending.size === 0);
  // explicit save: all targets in order; warm-up access() call comes first (user gesture), a failing github does not stop local targets
  const E = await ready(mk({ targets: ['github', 'folder', 'zip'] })); const c5 = mkCtx(E, ['github', 'folder', 'zip'], false);
  await E.save('T5', T('T5', 't')); const cc = (await state()).commits; await TG.saveAll(c5.ctx, { interactive: true });
  ok('explicit: access() warm-up, github commit, folder write (interactive), zip write', (await state()).commits === cc + 1 && c5.calls.join() === 'folder.access,folder.write interactive=true,zip.write', c5.calls);
  const F2 = await ready(mk({ targets: ['github', 'folder', 'zip'], token: undefined })); const c6 = mkCtx(F2, ['github', 'folder', 'zip'], false);
  await F2.save('T6', T('T6', 't')); const e = await rejects(TG.saveAll(c6.ctx, { interactive: true }));
  ok('github failure: error reported at the end, local targets still ran', !!e && /token/i.test(e.message) && c6.calls.includes('folder.write interactive=true') && c6.calls.includes('zip.write'), c6.calls);
  const c7 = mkCtx(E, ['github'], true); await E.save('T7', T('T7', 't')); await TG.saveAll(c7.ctx, { interactive: true }); ok('github only: no local sink touched', c7.calls.length === 0);
  const c8 = mkCtx(E, [], true); c8.ctx.sinks.zip = null; const c9 = mkCtx(E, ['zip'], true); c9.ctx.sinks.zip = null;
  ok('missing sink is a clear error', /not available/.test((await rejects(TG.saveAll(c9.ctx, {}))).message));
  // publish ignores targets
  const G1 = await ready(mk({ targets: ['zip'] })); await G1.save('T8', T('T8', 't')); const cg = (await state()).commits; await TG.publish({ engine: G1, syncer: null }); ok('publish() = flush({force:true}) regardless of targets', (await state()).commits === cg + 1);
});

test('GitHub error text names the failing step and the permission to check, never the token', async () => {
  await reset(); const A = await ready(mk()); await A.save('E', T('E', 'e'));
  const msgs = [];
  const probe = async (code, method, needle, step, hint) => {
    await mock(`/__inject/${code}/${method}/${needle}`);
    const err = await rejects(A.flush()); msgs.push(err && err.message, JSON.stringify(A.status));
    ok(`${method} ${needle} ${code} -> step "${step}"`, !!err && err.message.indexOf(`GitHub API ${method} ${code} (step: ${step})`) === 0 && (!hint || hint.test(err.message)), err && err.message);
    A.failures = 0; if (A.timer) { clearTimeout(A.timer); A.timer = null; }
    await mock('/__inject/off');
  };
  const PERM = /Contents: read & write.*Metadata: read/;
  await probe(404, 'GET', 'git/ref/', 'read ref', PERM);
  await probe(404, 'GET', 'git/commits/', 'read commit', PERM);   // the user's case: GET /git/commits/<sha> -> 404
  await probe(500, 'GET', 'contents/', 'read manifest at head');
  await probe(403, 'POST', 'git/blobs', 'create blob', PERM);
  await probe(404, 'POST', 'git/trees', 'create tree', PERM);
  await probe(403, 'POST', 'git/commits', 'create commit', PERM);
  await probe(404, 'PATCH', 'git/refs/', 'update ref', PERM);
  // a commit whose parent is gone etc. is not our business; control: flush works again
  const err = await rejects(A.flush()); ok('after the injected failures the flush works', !err && A.pending.size === 0, err && err.message);
  // 401 hint + token in the server's message is masked
  const c = new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'ghp_SECRETSECRET123', fetch: async () => new Response(JSON.stringify({ message: 'Bad credentials ghp_SECRETSECRET123' }), { status: 401 }) });
  const e401 = await rejects(c.getHead()); ok('401: step + hint, token masked', /\(step: read ref\)/.test(e401.message) && /token rejected/.test(e401.message) && e401.message.indexOf('ghp_SECRETSECRET123') === -1, e401.message);
  const e2 = await rejects(new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'ghp_SECRETSECRET123', fetch: async () => { throw new TypeError('Bearer ghp_SECRETSECRET123'); } }).createBlob(new Uint8Array(1)));
  ok('network error is labelled and scrubbed', /\(step: create blob; network/.test(e2.message) === false && /step: create blob/.test(e2.message) && e2.message.indexOf('ghp_SECRET') === -1 && e2.step === 'create blob', e2.message);
  const e3 = await rejects(new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'tok', fetch: async () => new Response('{"message":"Git Repository is empty."}', { status: 409 }) }).createBlob(new Uint8Array(1)));
  ok('empty repository hint', /repository is empty/.test(e3.message));
  ok('no message or status anywhere contains the token', MSG_TOKEN_FREE(...msgs));
  // a server message that quotes the token is masked in what the engine reports
  const T2 = await ready(mk({ fetch: async (u, i) => (i && i.method === 'POST' && /git\/blobs/.test(u) ? new Response(JSON.stringify({ message: 'denied for ' + TOKEN }), { status: 403 }) : fetch(u, i)) })); await T2.save('E2', T('E2', 'e'));
  const e4 = await rejects(T2.flush()); ok('server echo of the token is masked', !!e4 && MSG_TOKEN_FREE(e4.message, T2.status) && /\*\*\*/.test(e4.message), e4 && e4.message);
});

(async () => {
  KEYS = await F.deriveKeys(bytes()); MPATH = await F.manifestPath(KEYS);
  for (const [n, fn] of tests) { current = n; try { await fn(); } catch (e) { ok('threw ' + (e && e.stack || e), false); } }
  console.log(fails.length ? 'FAILED (' + fails.length + '):\n  ' + fails.join('\n  ') : 'ALL ENGINE CHECKS PASSED');
  process.exit(fails.length ? 1 : 0);
})();
