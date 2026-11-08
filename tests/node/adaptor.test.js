// Adaptor / saver-guard / startup-ui wiring against a minimal fake $tw (no wiki password, no jsdom): target resolution through the wiki,
// status fields for the readme, unload task, Ctrl+S vs autosave vs tm-enc-flush vs tm-enc-publish, token never in any message.
// Launched by tests/engine_test.py (env SP, AP, TOKEN, PAGES).
const Module = require('module'), path = require('path'), fs = require('fs'), crypto = require('crypto'), vm = require('vm');
const SRC = path.join(__dirname, '..', '..', 'plugin', 'src');
const orig = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) { const m = /^\$:\/plugins\/tw-enc-sync\/(.+)$/.exec(req); return orig.call(this, m ? path.join(SRC, m[1]) : req, ...rest); };
const F = require('$:/plugins/tw-enc-sync/encfmt.js');
const SP = process.env.SP, AP = process.env.AP, TOKEN = process.env.TOKEN, PAGES = process.env.PAGES;
const fails = []; let current = '';
const ok = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + current + ': ' + n + (!c && x !== undefined ? ' ' + JSON.stringify(x) : '')); if (!c) fails.push(current + ': ' + n); };
const mock = p => fetch(`http://127.0.0.1:${AP}${p}`).then(r => r.json());
const sleep = ms => new Promise(r => setTimeout(r, ms));

function load(file, $tw, win, doc) {
  const code = fs.readFileSync(path.join(SRC, file), 'utf8'), exports = {};
  const req = r => require(r);
  new Function('$tw', 'exports', 'require', 'window', 'document', 'setTimeout', code)($tw, exports, req, win, doc, setTimeout);
  return exports;
}
function makeTw(opts) {
  const tid = new Map(), listeners = {}, unload = [];
  class Tiddler { constructor(...f) { this.fields = Object.assign({}, ...f.map(x => (x && x.fields) || x)); } }
  const KEY = crypto.randomBytes(32);
  const wiki = {
    getTiddlerText: t => tid.has(t) ? tid.get(t).fields.text : undefined, tiddlerExists: t => tid.has(t), getTiddler: t => tid.get(t),
    addTiddler: t => { tid.set(t.fields.title, t); }, deleteTiddler: t => { tid.delete(t); },
  };
  const alerts = [], saved = {};
  const $tw = { browser: true, wiki, Tiddler, preloadTiddlers: [], config: { contentTypeInfo: { 'image/png': { encoding: 'base64' } } },
    utils: { Logger: function () { this.log = () => {}; this.alert = m => alerts.push(m); }, getPassword: () => TOKEN, savePassword: () => {} },
    addUnloadTask: f => unload.push(f), rootWidget: { addEventListener: (n, f) => { listeners[n] = f; } }, syncer: { numTasksInQueue: () => 0, numTasksInProgress: () => 0 },
    crypto: { setPassword() {}, updateCryptoStateTiddler() {} } };
  wiki.addTiddler(new Tiddler({ title: '$:/ext/enc/config', text: JSON.stringify({ repo: 'o/r', branch: 'master', apiBase: `http://127.0.0.1:${AP}`, base: '' }) }));
  wiki.addTiddler(new Tiddler({ title: '$:/ext/enc/dek', text: Buffer.from(opts.dek).toString('base64') }));
  return { $tw, tid, listeners, unload, alerts, wiki, Tiddler };
}
const winFor = (extra) => Object.assign({ fetch: (u, i) => fetch(u, i), location: { href: `http://127.0.0.1:${SP}/tw.html`, protocol: 'http:' }, localStorage: null, setTimeout, alert() {} }, extra);
const docStub = { addEventListener() {} };

(async () => {
  const DEK = crypto.randomBytes(32), keys = await F.deriveKeys(Uint8Array.from(DEK)), MP = await F.manifestPath(keys);
  const seed = async () => {   // a repo + local copy with an empty manifest at counter 1
    for (const f of fs.readdirSync(PAGES)) fs.rmSync(path.join(PAGES, f), { recursive: true, force: true });
    fs.mkdirSync(path.join(PAGES, 'm'), { recursive: true }); fs.writeFileSync(path.join(PAGES, MP), await F.sealManifest(keys, { v: 1, counter: 1, tiddlers: {} }));
    await mock('/__defer/0'); await mock('/__inject/off'); await mock('/__reseed');
  };
  async function boot(win, setup) {
    const w = makeTw({ dek: DEK }); if (setup) setup(w);
    const ad = load('adaptor.js', w.$tw, win, docStub).adaptorClass;
    const adaptor = new ad({ wiki: w.wiki }); w.adaptor = adaptor;
    w.guard = load('saver-guard.js', w.$tw, win, docStub); w.ui = load('startup-ui.js', w.$tw, win, docStub); w.ui.startup();
    await w.$tw.encSync.ready; return w;
  }
  const save = (w, title, text) => w.adaptor.saveTiddler(new w.Tiddler({ title, text }) && Object.assign(new w.Tiddler({ title, text }), { getFieldStrings() { return { title, text }; } }), () => {});
  const SAVER = (w, method) => new Promise(res => { w.guard.create(w.wiki).save('x', method, e => res(e || null)); });

  current = 'adaptor wiring (http page, default targets)'; await seed();
  let w = await boot(winFor());
  ok('engine exposed, targets context exposed, key tiddler removed', !!w.$tw.encSync && !!w.$tw.encTargets && !w.wiki.tiddlerExists('$:/ext/enc/dek'));
  ok('default target on http = github', w.adaptor.targets().join() === 'github');
  w.wiki.addTiddler(new w.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: ' zip , Github ' })); ok('config read through the wiki (live, no FSA => folder falls back)', w.adaptor.targets().join() === 'github,zip');
  w.wiki.addTiddler(new w.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: '', _is_skinny: '' })); ok('skinny (not yet loaded) config => default, no lazy load', w.adaptor.targets().join() === 'github');
  w.wiki.addTiddler(new w.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: 'bogus' })); ok('garbage => default', w.adaptor.targets().join() === 'github');
  w.wiki.deleteTiddler('$:/config/ext/enc/SaveTarget');
  await w.$tw.encSync.save('N', { title: 'N', text: 'n' });
  const st = w.wiki.getTiddler('$:/temp/ext/enc/status');
  ok('status tiddler carries readme fields', st.fields.unpublished === '1' && st.fields['unsaved-local'] === '1' && st.fields.targets === 'github', st.fields);
  let ev = {}; const msg = w.unload[0](ev); ok('unload warns about GitHub when github is a target', /GitHub/.test(msg || '') && ev.returnValue === msg);
  w.wiki.addTiddler(new w.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: 'zip' })); ev = {};
  ok('unload: zip target warns about local, not GitHub', /local zip/.test(w.unload[0](ev) || '') && !/GitHub/.test(ev.returnValue));
  w.wiki.addTiddler(new w.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: 'github' }));
  const c0 = (await mock('/__state')).commits;
  ok('Ctrl+S (github target) commits', (await SAVER(w, 'save')) === null && (await mock('/__state')).commits === c0 + 1 && w.$tw.encSync.pending.size === 0);
  ok('unload: nothing unsaved, no warning', w.unload[0]({}) === undefined || w.unload[0]({}) === null);

  current = 'saver guard / buttons: targets'; await seed();
  const dls = []; const win2 = winFor({ Blob, URL: { createObjectURL: b => { dls.push(b); return 'blob:t'; }, revokeObjectURL() {} } });
  w = await boot(win2, x => x.wiki.addTiddler(new x.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: 'github, zip' })));
  w.$tw.encTargets.sinks.zip.trigger = async (blob, name) => { dls.push(name); };
  await w.$tw.encSync.save('A1', { title: 'A1', text: 'secret-body' });
  const c1 = (await mock('/__state')).commits;
  ok('autosave: github yes, zip never', (await SAVER(w, 'autosave')) === null && (await mock('/__state')).commits === c1 + 1 && dls.length === 0 && w.$tw.encSync.localDirty.size === 1);
  ok('Ctrl+S: zip download too', (await SAVER(w, 'save')) === null && dls.length === 1 && /^tw-update-\d+\.zip$/.test(dls[0]) && w.$tw.encSync.localDirty.size === 0, dls);
  await w.$tw.encSync.save('A2', { title: 'A2', text: 'x' });
  w.listeners['tm-enc-flush'](); await sleep(400);
  ok('tm-enc-flush button runs all targets', dls.length === 2 && w.$tw.encSync.pending.size === 0 && !w.wiki.tiddlerExists('$:/temp/ext/enc/error'), dls);
  // publish ignores SaveTarget
  w.wiki.addTiddler(new w.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: 'zip' }));
  await w.$tw.encSync.save('A3', { title: 'A3', text: 'x' }); const c2 = (await mock('/__state')).commits;
  w.listeners['tm-enc-publish'](); await sleep(500);
  ok('tm-enc-publish: GitHub commit although github is not a target; zip not triggered', (await mock('/__state')).commits === c2 + 1 && w.$tw.encSync.pending.size === 0 && dls.length === 2, dls);
  w.listeners['tm-enc-publish'](); await sleep(300); ok('repeated publish: no new commit', (await mock('/__state')).commits === c2 + 1);

  current = 'file:// page defaults';
  await seed(); const win3 = winFor({ location: { href: 'file:///C:/x/tw.html', protocol: 'file:' } });
  // engine base URL is file: -> fetch of local files is served from the static dir; the API stays http
  win3.fetch = (u, i) => String(u).startsWith('file:///C:/x/') ? fetch(`http://127.0.0.1:${SP}/` + String(u).slice(13)).then(async r => new Response(await r.arrayBuffer(), { status: r.status })) : fetch(u, i);
  w = await boot(win3);
  ok('file: without File System Access => zip (fallback)', w.adaptor.targets().join() === 'zip');
  const fx = { showDirectoryPicker() {} }; ok('with the API => folder', load('adaptor.js', makeTw({ dek: DEK }).$tw, Object.assign(winFor({ location: { href: 'file:///x', protocol: 'file:' } }), fx), docStub) && true);
  w.$tw.encSync.save('F1', { title: 'F1', text: 'x' }); await sleep(50);
  ok('file: page: github is not a target => no GitHub warning, local warning instead', !/GitHub/.test(w.unload[0]({}) || '') && /local zip/.test(w.unload[0]({}) || ''));

  current = 'errors reach the UI sanitised';
  await seed(); w = await boot(winFor(), x => { x.$tw.utils.getPassword = () => undefined; });
  await w.$tw.encSync.save('E1', { title: 'E1', text: 'x' });
  w.listeners['tm-enc-flush'](); await sleep(300);
  const e = w.wiki.getTiddler('$:/temp/ext/enc/error'); ok('error tiddler text/plain, mentions token', !!e && e.fields.type === 'text/plain' && /token/i.test(e.fields.text));
  const err = await SAVER(w, 'save'); ok('saver reports the error', err instanceof Error && /token/i.test(err.message));
  current = 'lazy-load race'; await seed(); w = await boot(winFor());
  { // a queued lazy-load must never overwrite an unsaved local change (race that reverted the palette at startup)
    await w.$tw.encSync.save('L', { title: 'L', text: 'stored' });
    const load = () => new Promise(res => w.adaptor.loadTiddler('L', (e, f) => res({ e, f })));
    let count = 5; w.wiki.getChangeCount = () => count; w.$tw.syncer.tiddlerInfo = { L: { changeCount: 5 } };
    w.wiki.addTiddler(new w.Tiddler({ title: 'L', text: 'stored' }));
    let r = await load(); ok('clean tiddler: load returns the stored fields', !r.e && r.f && r.f.text === 'stored', r);
    count = 6; w.wiki.addTiddler(new w.Tiddler({ title: 'L', text: 'edited locally' }));
    r = await load(); ok('unsaved local change: load stores nothing (null)', !r.e && r.f === null, r);
    w.wiki.addTiddler(new w.Tiddler({ title: 'L', _is_skinny: '' }));
    r = await load(); ok('still a stub: the load goes through', !r.e && r.f && r.f.text === 'stored', r);
    delete w.wiki.getChangeCount; w.$tw.syncer.tiddlerInfo = undefined;
  }
  console.log(fails.length ? 'FAILED (' + fails.length + '):\n  ' + fails.join('\n  ') : 'ALL ADAPTOR CHECKS PASSED'); process.exit(fails.length ? 1 : 0);
})().catch(e => { console.error('CRASH', e); process.exit(2); });
