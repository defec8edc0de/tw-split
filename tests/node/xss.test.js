// Web-security checks on the UNLOCKED page (real TiddlyWiki 5.1.21 in jsdom) with a synthetic wiki; needs no real password.
// Env: ROOT (stage-1 + data dir), ROOT_CSP (stage-1 built with --csp), PW (synthetic), AP (mock GitHub port), TOKEN, DEK_B64 (synthetic DEK).
const { JSDOM, VirtualConsole } = require('jsdom');
const { webcrypto, createHash } = require('crypto');
const http = require('http'), fs = require('fs'), path = require('path');
const { ROOT, ROOT_CSP, PW, AP, TOKEN, DEK_B64 } = process.env;
const fails = [];
const check = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + n + (!c && x !== undefined ? ' ' + JSON.stringify(x).slice(0, 400) : '')); if (!c) fails.push(n); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms = 40000, what = '') { const t = Date.now(); for (;;) { try { const v = await fn(); if (v) return v; } catch (e) {} if (Date.now() - t > ms) throw new Error('timeout ' + what); await sleep(100); } }

// static server with per-test overrides: path -> (req,res) => handled
let overrides = {};
const srv = http.createServer((q, r) => {
  const p = decodeURIComponent(q.url.split('?')[0]);
  if (overrides[p]) return overrides[p](q, r);
  const f = path.join(p.startsWith('/csp/') ? ROOT_CSP : ROOT, p.startsWith('/csp/') ? p.slice(4) : p);
  fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); r.end(); } else { r.writeHead(200, { 'Cache-Control': 'no-cache' }); r.end(d); } });
});

async function boot(port, opts = {}) {
  const url = `http://127.0.0.1:${port}${opts.page || '/tw.html'}`;
  const html = await (await fetch(url)).text();
  const logs = [], alerts = [];
  const vc = new VirtualConsole();
  ['log', 'info', 'warn', 'error', 'debug'].forEach(k => vc.on(k, (...a) => logs.push(k + ' ' + a.join(' '))));
  vc.on('jsdomError', e => logs.push('JSDOMERR ' + e.message));
  const dom = new JSDOM(html, { url, runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc, beforeParse(w) {
    Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true });
    w.fetch = (u, i) => fetch(u, i); w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder; w.AbortController = AbortController;
    w.requestAnimationFrame = w.requestAnimationFrame || (f => setTimeout(f, 16));
    w.alert = m => alerts.push(String(m)); w.__pwn = [];
    if (opts.legacyToken) w.localStorage.setItem('tw5-password-github', opts.legacyToken);
  } });
  const w = dom.window;
  await until(() => w.document.querySelector('input[type=password]'), 30000, 'password prompt');
  return { dom, w, logs, alerts, url, unlock(pw) {
    const input = w.document.querySelector('input[type=password]'); input.value = pw;
    input.closest('form').dispatchEvent(new w.Event('submit', { cancelable: true, bubbles: true }));
  } };
}
const loadText = async (T, title) => { const f = await T.encSync.load(title); T.syncer.storeTiddler(f, true); await until(() => { const t = T.wiki.getTiddler(title); return t && t.fields._is_skinny === undefined && t.fields.text === f.text; }, 5000, 'store ' + title); };
function renderInto(T, w, text, vars) {
  const parser = T.wiki.parseText('text/vnd.tiddlywiki', text);
  const widget = T.wiki.makeWidget(parser, { document: w.document, parentWidget: T.rootWidget, variables: vars || {} });
  const div = w.document.createElement('div'); w.document.body.appendChild(div); widget.render(div, null); return div;
}
// reachable-object scan for secrets (strings, byte arrays) in the $tw graph; CryptoKeys are collected
function scan(root, needles, bytes) {
  const seen = new WeakSet(), hits = [], keys = []; let n = 0;
  const find = (arr) => { for (let i = 0; i + bytes.length <= arr.length; i++) { let ok = true; for (let j = 0; j < bytes.length; j++) if (arr[i + j] !== bytes[j]) { ok = false; break; } if (ok) return true; } return false; };
  (function walk(o, p, d) {
    if (n++ > 3e6 || d > 40) return;
    if (typeof o === 'string') { for (const nd of needles) if (o.includes(nd)) hits.push(p + ' ~ ' + nd.slice(0, 6)); return; }
    if (!o || typeof o !== 'object') return;
    if (seen.has(o)) return; seen.add(o);
    if (o.nodeType) return;
    const cn = o.constructor && o.constructor.name;
    if (cn === 'CryptoKey') { keys.push(o); return; }
    if (ArrayBuffer.isView(o) || o instanceof ArrayBuffer || cn === 'ArrayBuffer' || /Array$/.test(cn || '')) { try { const u = o instanceof ArrayBuffer ? new Uint8Array(o) : new Uint8Array(o.buffer || o, o.byteOffset || 0, o.byteLength); if (bytes.length && u.length < 1e7 && find(u)) hits.push(p + ' (bytes)'); } catch (e) {} if (!Array.isArray(o)) return; }
    if (o instanceof Map) { o.forEach((v, k) => { walk(k, p + '<k>', d + 1); walk(v, p + '<v>', d + 1); }); return; }
    if (o instanceof Set) { o.forEach(v => walk(v, p + '<s>', d + 1)); return; }
    let names = []; try { names = Object.getOwnPropertyNames(o); } catch (e) {}
    for (const k of names) { let v; try { v = o[k]; } catch (e) { continue; } walk(v, p + '.' + k, d + 1); }
  })(root, '$tw', 0);
  return { hits, keys };
}

srv.listen(0, async () => {
  const SP = srv.address().port;
  const dek = Buffer.from(DEK_B64, 'base64');
  try {
    // ============ main page ============
    const A = await boot(SP, { legacyToken: 'LEGACY-TOKEN-ABC' });
    const w = A.w;
    // stage-1 HTML itself
    const stage1 = await (await fetch(A.url)).text();
    check('stage-1 has referrer policy', /<meta name="referrer" content="no-referrer"/.test(stage1));
    check('stage-1 has frame guard before the title', stage1.indexOf('window.top!==window.self') > 0 && stage1.indexOf('window.top!==window.self') < stage1.indexOf('<title>'));
    check('stage-1 (default build) has no CSP', !/<meta http-equiv="Content-Security-Policy"/.test(stage1));
    A.unlock('wrong'); await sleep(1500);
    check('wrong password keeps the prompt', !!w.document.querySelector('input[type=password]'));
    A.unlock(PW);
    await until(() => w.$tw && w.$tw.encSync && w.$tw.encSync.status.state === 'ready', 60000, 'engine ready');
    await sleep(2500);
    const T = w.$tw;

    // ---- secrets reachable from the page ----
    const needles = [DEK_B64, PW, dek.toString('hex')];
    const sc = scan(T, needles, [...dek]);
    check('synthetic DEK / password not reachable in the $tw object graph', sc.hits.length === 0, sc.hits.slice(0, 5));
    check('CryptoKeys found and none extractable', sc.keys.length >= 1 && sc.keys.every(k => k.extractable === false), sc.keys.length);
    const dom = w.document.documentElement.outerHTML + [...w.document.querySelectorAll('input,textarea')].map(i => i.value).join('|');
    check('no DEK / password in the DOM or input values', !needles.some(n => dom.includes(n)));
    const stor = JSON.stringify([w.localStorage, w.sessionStorage]) + JSON.stringify(Object.entries(w.localStorage)) + JSON.stringify(Object.entries(w.sessionStorage));
    check('no DEK / password in Web Storage', !needles.some(n => stor.includes(n)));
    const wprops = Object.getOwnPropertyNames(w).filter(k => /encSync|dek|password/i.test(k));
    check('no secret-looking window globals', wprops.length === 0, wprops);
    check('$tw.encSync is not replaceable or deletable', (() => { try { w.eval('$tw.encSync = null'); } catch (e) {} try { w.eval('delete $tw.encSync'); } catch (e) {} return !!T.encSync; })());
    check('$tw.encSync not enumerable', !Object.keys(T).includes('encSync'));
    check('$tw.encSyncGuard cannot be switched off', (() => { try { w.eval('$tw.encSyncGuard = false'); } catch (e) {} return T.encSyncGuard === true; })());

    // ---- data-loss guard: metadata change on a tiddler whose text has not been fetched yet ----
    {
      const before = (await T.encSync.load('Pic')).text;
      const sk = T.wiki.getTiddler('Pic');
      check('Pic is still skinny (media are fetched on demand)', sk && sk.fields._is_skinny !== undefined);
      T.wiki.addTiddler(new T.Tiddler(sk, { stamped: 'by-plugin' }));
      await until(() => T.syncer.numTasksInQueue() === 0 && T.syncer.numTasksInProgress() === 0, 20000, 'syncer idle');
      await sleep(500);
      const after = (await T.encSync.load('Pic')).text;
      check('saving metadata of a skinny tiddler keeps its real text', before.length > 100 && after === before, [before.length, after.length]);
    }

    // ---- token storage ----
    check('legacy localStorage token moved out of localStorage', w.localStorage.getItem('tw5-password-github') === null);
    check('...and still usable (session)', T.utils.getPassword('github') === 'LEGACY-TOKEN-ABC' && w.sessionStorage.getItem('tw5-password-github') === 'LEGACY-TOKEN-ABC');
    T.utils.savePassword('github', 'T-SESSION');
    check('savePassword(github) -> sessionStorage only', w.localStorage.getItem('tw5-password-github') === null && w.sessionStorage.getItem('tw5-password-github') === 'T-SESSION' && T.utils.getPassword('github') === 'T-SESSION');
    T.utils.savePassword('other', 'x');
    check('other passwords untouched (stock behaviour)', w.localStorage.getItem('tw5-password-other') === 'x');
    T.wiki.addTiddler(new T.Tiddler({ title: '$:/config/ext/enc/TokenStorage', text: 'memory' }));
    T.utils.savePassword('github', 'T-MEM');
    check('mode memory: nowhere in Web Storage', w.localStorage.getItem('tw5-password-github') === null && w.sessionStorage.getItem('tw5-password-github') === null && T.utils.getPassword('github') === 'T-MEM');
    T.wiki.addTiddler(new T.Tiddler({ title: '$:/config/ext/enc/TokenStorage', text: 'local' }));
    T.utils.savePassword('github', 'T-LOCAL');
    check('mode local: stock behaviour', w.localStorage.getItem('tw5-password-github') === 'T-LOCAL' && T.utils.getPassword('github') === 'T-LOCAL');
    T.wiki.deleteTiddler('$:/config/ext/enc/TokenStorage'); w.localStorage.removeItem('tw5-password-github');
    T.utils.savePassword('github', TOKEN);
    check('default mode again session', w.localStorage.getItem('tw5-password-github') === null && w.sessionStorage.getItem('tw5-password-github') === TOKEN);

    // ---- cross-window messages ----
    const mk = (title, over) => Object.assign({ verb: 'GET-RESPONSE', status: '200', cookies: { type: 'save-tiddler', url: 'x' }, body: JSON.stringify({ title, text: 'injected' }) }, over || {});
    const fire = (data, init) => w.dispatchEvent(new w.MessageEvent('message', Object.assign({ data }, init || {})));
    fire(mk('MSG-1'), { origin: 'https://evil.example' });
    fire(mk('MSG-2'), { origin: A.url.replace(/\/tw.html$/, '') });                    // same origin, e.g. another page of the same github.io
    fire(mk('MSG-3', { cookies: { type: 'save-info', infoTitlePrefix: '$:/temp/X/', url: 'u' }, body: JSON.stringify([{ title: 'a', text: 'b' }]) }), { origin: 'https://evil.example' });
    w.postMessage(mk('MSG-4'), '*');                                                    // real postMessage API (what an opener / framing page uses)
    const ifr = w.document.createElement('iframe'); w.document.body.appendChild(ifr);
    fire(mk('MSG-5'), { origin: 'https://evil.example', source: ifr.contentWindow });   // some other frame
    fire(mk('MSG-6'), { origin: 'null', source: w });
    fire(null, { origin: 'https://evil.example' });
    await sleep(300);
    check('foreign / same-origin / opener / frame messages cannot create tiddlers', ['MSG-1', 'MSG-2', 'MSG-4', 'MSG-5', 'MSG-6'].every(t => !T.wiki.tiddlerExists(t)) && !T.wiki.tiddlerExists('$:/temp/X/https://evil.example') && T.wiki.filterTiddlers('[prefix[$:/temp/X/]]').length === 0);
    // the genuine plugin-library flow keeps working: reply from the iframe the core created, with that iframe's origin
    T.browserMessaging.iframeInfoMap['https://lib.example/lib.html'] = { url: 'https://lib.example/lib.html', status: 'loaded', domNode: ifr };
    fire(mk('LIB-OK'), { origin: 'https://lib.example', source: ifr.contentWindow });
    fire(mk('LIB-BADORIGIN'), { origin: 'https://evil.example', source: ifr.contentWindow });
    await sleep(200);
    check('reply from a library iframe (right source AND origin) still works', T.wiki.tiddlerExists('LIB-OK'));
    check('...but not with the wrong origin', !T.wiki.tiddlerExists('LIB-BADORIGIN'));

    // ---- hostile raw HTML / typed tiddlers ----
    const hostile = T.wiki.filterTiddlers('[prefix[HOSTILE]]');
    check('hostile corpus present', hostile.length >= 20, hostile.length);
    for (const t of hostile) await loadText(T, t);
    const holder = w.document.createElement('div'); w.document.body.appendChild(holder);
    const direct = {};
    for (const t of hostile) { const parser = T.wiki.parseTiddler(t); const wd = T.wiki.makeWidget(parser, { document: w.document, parentWidget: T.rootWidget, variables: { currentTiddler: t } }); const d = w.document.createElement('div'); d.id = 'r-' + hostile.indexOf(t); w.document.body.appendChild(d); wd.render(d, null); direct[t] = d; }
    await sleep(1500);
    const all = w.document.body;
    // click everything clickable, submit forms
    all.querySelectorAll('a,button,input[type=submit],svg a').forEach(e => { try { e.dispatchEvent(new w.MouseEvent('click', { bubbles: true, cancelable: true })); } catch (x) {} });
    all.querySelectorAll('form').forEach(f => { try { f.dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true })); } catch (x) {} });
    await sleep(1500);
    check('no hostile tiddler content executed script (canary list empty)', w.__pwn.length === 0, w.__pwn);
    const bad = ([...all.querySelectorAll('[href^="javascript"],[src^="javascript"],[action^="javascript"],[formaction^="javascript"],[data^="javascript"]')]);
    check('no javascript: URL reaches the DOM', bad.length === 0, bad.map(e => e.outerHTML).slice(0, 3));
    const cont = [...Object.values(direct)];
    const q = s => cont.reduce((n, c) => n + c.querySelectorAll(s).length, 0);
    check('no srcdoc attribute in rendered content', q('[srcdoc]') === 0);
    check('no on* attributes in rendered content', cont.every(c => [...c.querySelectorAll('*')].every(e => ![...e.attributes].some(a => /^on/i.test(a.name)))));
    check('no <script>, <base>, <meta>, <link> elements from content', q('script,base,meta,link') === 0);
    check('base/meta/link were turned into inert safe-* elements', q('safe-base') === 1 && q('safe-meta') === 1 && q('safe-link') === 1, [q('safe-base'), q('safe-meta'), q('safe-link')]);
    check('document base URI / head unchanged by content', !w.document.querySelector('base') && !/evil\.example/.test(w.document.baseURI));
    check('text/html tiddler still shown in a SANDBOXED iframe', (() => { const f = direct['HOSTILE html-tiddler'].querySelector('iframe'); return !!f && f.getAttribute('sandbox') === ''; })());
    check('svg image tiddler is shown via <img> (script-free context)', (() => { const i = direct['HOSTILE svg-image'].querySelector('img'); return !!i && /^data:image\/svg\+xml,/.test(i.getAttribute('src')); })());
    check('PDF tiddler (embed) still rendered', direct['HOSTILE pdf'].querySelectorAll('embed').length === 1);
    check('wikitext in a TITLE is displayed, not executed', !w.document.getElementById('inj-title'));
    // click guard is independent of the attribute filter (e.g. a link created by another plugin)
    const evil = w.document.createElement('a'); evil.setAttribute('href', ' JaVa\tScRiPt:window.__pwn.push("late-a")'); evil.textContent = 'x'; w.document.body.appendChild(evil);
    const ev = new w.MouseEvent('click', { bubbles: true, cancelable: true }); evil.dispatchEvent(ev);
    const btn = w.document.createElement('button'); btn.setAttribute('formaction', 'javascript:window.__pwn.push("late-b")'); w.document.body.appendChild(btn);
    const ev2 = new w.MouseEvent('click', { bubbles: true, cancelable: true }); btn.dispatchEvent(ev2);
    await sleep(500);
    check('click guard cancels javascript: activation created outside the widget layer', ev.defaultPrevented && ev2.defaultPrevented && w.__pwn.length === 0, w.__pwn);

    // ---- executable modules ----
    const mods = ['$:/HOSTILE/mod.js', '$:/HOSTILE/startup.js', '$:/HOSTILE/widget.js', '$:/HOSTILE/macro.js'];
    for (const m of mods) await loadText(T, m);
    let threw = 0; for (const m of mods) { try { T.modules.execute(m); } catch (e) { threw++; } }
    check('synced JS-module tiddlers are not registered as modules', threw === mods.length && mods.every(m => !T.modules.titles[m]), threw);
    check('...nor present in the module-type registries', !(T.modules.types.startup || {})['$:/HOSTILE/startup.js'] && !(T.modules.types.widget || {})['$:/HOSTILE/widget.js'] && !(T.modules.types.macro || {})['$:/HOSTILE/macro.js'] && !(T.modules.types.library || {})['$:/HOSTILE/mod.js']);
    check('...and no macro/widget appeared', !T.wiki.getTiddler('$:/HOSTILE/mod.js') || w.__pwn.length === 0);
    const css = T.wiki.getTiddler('$:/HOSTILE/css');
    console.log('INFO  $:/tags/Stylesheet tiddlers from the repo are applied (CSS @import/url() reach third parties; only a CSP can stop that): ' + (css ? 'present' : 'absent'));

    // ---- alerts rendered as wikitext ----
    const payload = 'Sync error while processing \'<$list filter="[all[]]"><span id="inj-alert">X</span></$list>\':\nboom "quoted" <$button><$action-sendmessage $message="tm-enc-flush"/>b</$button>';
    T.syncer.logger.alert(payload);
    const alertTitles = T.wiki.getTiddlersWithTag('$:/tags/Alert');
    check('alert created', alertTitles.length >= 1);
    const al = renderInto(T, w, '<$list filter="[tag[$:/tags/Alert]]"><$transclude tiddler="$:/core/ui/AlertTemplate" mode="block"/></$list>');
    check('alert text with wikitext/widgets is displayed literally', !w.document.getElementById('inj-alert') && /<\$list filter/.test(al.textContent) && /boom/.test(al.textContent) && al.querySelectorAll('button').length === alertTitles.length, al.innerHTML.slice(0, 300));
    // a real failure through the syncer with a hostile TITLE and hostile error text
    const realSave = T.encSync.save; const origFlush = T.encSync.flush;
    const hostileTitle = 'ZZ-<$list filter="[all[]]"><span id="inj-title2">T</span></$list>';
    Object.defineProperty(T.encSync, 'save', { value: () => Promise.reject(new Error('GitHub API POST 422: <$list filter="[all[]]"><span id="inj-err">E</span></$list>')), configurable: true, writable: true });
    A.logs.length = 0;
    T.wiki.addTiddler(new T.Tiddler({ title: hostileTitle, text: 'some secret-ish body' }));
    await until(() => T.wiki.getTiddlersWithTag('$:/tags/Alert').some(t => /GitHub API POST 422/.test(T.wiki.getTiddler(t).fields.text)), 15000, 'syncer alert');
    const al2 = renderInto(T, w, '<$list filter="[tag[$:/tags/Alert]]"><$transclude tiddler="$:/core/ui/AlertTemplate" mode="block"/></$list>');
    check('syncer alert with hostile title + hostile adaptor error is inert', !w.document.getElementById('inj-title2') && !w.document.getElementById('inj-err') && /GitHub API POST 422/.test(al2.textContent) && /ZZ-/.test(al2.textContent));
    check('no tiddler title / body in the console', !A.logs.some(l => /ZZ-|Dispatching|secret-ish|HOSTILE/.test(l)), A.logs.slice(-4));
    delete T.encSync.save; T.wiki.deleteTiddler(hostileTitle); await sleep(1500);

    // ---- tm-enc-flush abuse ----
    let calls = 0; const f0 = T.encSync.flush;
    Object.defineProperty(T.encSync, 'flush', { value: function() { calls++; return Promise.reject(new Error('GitHub token missing <$list filter="[all[]]"><span id="inj-flush">F</span></$list>')); }, configurable: true, writable: true });
    for (let i = 0; i < 300; i++) T.rootWidget.dispatchEvent({ type: 'tm-enc-flush', param: 'x', paramObject: { a: 1 } });
    await sleep(600);
    check('300 tm-enc-flush messages -> one commit attempt at a time', calls === 1, calls);
    const er = T.wiki.getTiddler('$:/temp/ext/enc/error');
    check('flush failure is shown as text/plain, not wikitext', er && er.fields.type === 'text/plain' && /GitHub token missing/.test(er.fields.text));
    const rd = renderInto(T, w, '<$list filter="[[$:/plugins/tw-enc-sync/readme]]"><$transclude tiddler="$:/plugins/tw-enc-sync/readme"/></$list>');
    check('readme shows status/error without interpreting them', !w.document.getElementById('inj-flush') && /GitHub token missing/.test(rd.textContent));
    await sleep(100); T.rootWidget.dispatchEvent({ type: 'tm-enc-flush' }); await sleep(200);
    check('a later message is handled again', calls === 2, calls);
    // ---- publishing to the blog (publish.js / publish-ui.js): consent gates and refusals in the real TiddlyWiki ----
    {
      const PST = '$:/temp/ext/pub/status', PRV = '$:/temp/ext/pub/preview';
      const st = () => (T.wiki.getTiddler(PST) || { fields: {} }).fields;
      const head = async (p) => (await fetch(`http://127.0.0.1:${AP}/__headfile/${p}`)).status;
      const hist = async () => (await (await fetch(`http://127.0.0.1:${AP}/__history`)).json()).n;
      let asked = 0; w.confirm = () => { asked++; return false; };
      T.wiki.deleteTiddler(PRV);
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-confirm' });
      check('publish: confirm without a preview is refused', /preview first/i.test(st().text || '') && asked === 0);
      T.wiki.addTiddler(new T.Tiddler({ title: 'PUB hostile', tags: 'publish:blog', type: 'text/x-markdown', text: 'leak {{PUB secret}} <$list filter="[all[]]"/>' }));
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-preview', param: 'PUB hostile' });
      check('publish: transclusion/widget refused before any preview', /refusing to publish/.test(st().text || '') && !T.wiki.getTiddler(PRV));
      T.wiki.addTiddler(new T.Tiddler({ title: 'PUB untagged', type: 'text/x-markdown', text: 'x' }));
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-preview', param: 'PUB untagged' });
      check('publish: untagged note + "turn into blog post?" declined -> unchanged, no preview', asked === 1 && !(T.wiki.getTiddler('PUB untagged').fields.tags || []).includes('publish:blog') && !T.wiki.getTiddler(PRV));
      w.confirm = () => { asked++; return true; };
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-preview', param: 'PUB untagged' });
      check('publish: untagged note + accepted -> tagged publish:blog and previewed (not published)', (T.wiki.getTiddler('PUB untagged').fields.tags || []).includes('publish:blog') && !!T.wiki.getTiddler(PRV) && T.wiki.getTiddler(PRV).fields['post-title'] === 'PUB untagged');
      w.confirm = () => { asked++; return false; }; asked = 0; T.wiki.deleteTiddler(PRV);
      T.wiki.addTiddler(new T.Tiddler({ title: 'PUB ok', tags: 'publish:blog journal', 'publish-tags': 'demo', type: 'text/x-markdown', text: 'Hello [[PUB secret]] world.' }));
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-preview', param: 'PUB ok' });
      const pv = T.wiki.getTiddler(PRV);
      check('publish: preview shows the exact Markdown, path and no vault tags', pv && pv.fields['post-path'] === 'content/blog/pub-ok/index.md' && /Hello PUB secret world\./.test(pv.fields.text) && !/journal/.test(pv.fields.text) && pv.fields.type === 'text/plain');
      const n0 = await hist();
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-confirm' });
      await sleep(400);
      check('publish: native confirm declined -> nothing committed', asked === 1 && (await head('content/blog/pub-ok/index.md')) === 404 && /cancelled/i.test(st().text || ''), [asked, st().text, n0, await hist()]);
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-confirm' });
      check('publish: the preview is single-use', /preview first/i.test(st().text || '') && asked === 1, [asked, st().text]);
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-preview', param: 'PUB ok' });
      T.wiki.addTiddler(new T.Tiddler(T.wiki.getTiddler('PUB ok'), { text: 'Changed after preview.' }));
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-confirm' });
      check('publish: tiddler changed after the preview -> refused', /changed after the preview/.test(st().text || '') && asked === 1, [asked, st().text]);
      w.confirm = () => { asked++; return true; };
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-preview', param: 'PUB ok' });
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-confirm' });
      await until(async () => (await head('content/blog/pub-ok/index.md')) === 200, 15000, 'published file');
      const md = await (await fetch(`http://127.0.0.1:${AP}/__headfile/content/blog/pub-ok/index.md`)).text();
      check('publish: confirmed -> plaintext post committed', /^---\ntitle: "PUB ok"\n/.test(md) && /Changed after preview\./.test(md) && /source: "vault"/.test(md));
      const trees = await (await fetch(`http://127.0.0.1:${AP}/__trees`)).json(), last = trees[trees.length - 1];
      check('publish: the commit holds only the post (no ciphertext mixed in)', last.tree.length === 1 && last.tree[0].path === 'content/blog/pub-ok/index.md');
      await until(() => /^[0-9a-f]{40}$/.test(T.wiki.getTiddler('PUB ok').fields['publish-sha'] || ''), 5000, 'publish-sha field');
      check('publish: slug + sha recorded on the tiddler', T.wiki.getTiddler('PUB ok').fields['publish-slug'] === 'pub-ok');
      check('publish: status is plain text', st().type === 'text/plain' && /Published content\/blog\/pub-ok\/index\.md/.test(st().text || ''));
      T.rootWidget.dispatchEvent({ type: 'tm-enc-post-unpublish', param: 'PUB ok' });
      await until(async () => (await head('content/blog/pub-ok/index.md')) === 404, 15000, 'unpublished file');
      await until(() => !T.wiki.getTiddler('PUB ok').fields['publish-sha'], 5000, 'publish-sha removed');
      check('unpublish: file removed, sha cleared, slug kept', T.wiki.getTiddler('PUB ok').fields['publish-slug'] === 'pub-ok');
      check('publish: token never in the console', !A.logs.some(l => l.includes(TOKEN)));
      ['PUB hostile', 'PUB untagged', 'PUB ok'].forEach(t => T.wiki.deleteTiddler(t)); w.confirm = () => false; await sleep(1500);
    }
    // ---- website back-link (ui/home-link) and the publish toolbar button ----
    {
      const link = () => renderInto(T, w, '{{$:/plugins/tw-enc-sync/ui/home-link}}').querySelector('a.enc-home-link');
      T.wiki.deleteTiddler('$:/config/ext/site/HomeURL');
      let a = link(); check('home link: default "/"', a && a.getAttribute('href') === '/');
      for (const bad of ['javascript:alert(1)', '//evil.example/', 'http://plain.example/', ' /x', 'data:text/html,x']) {
        T.wiki.addTiddler(new T.Tiddler({ title: '$:/config/ext/site/HomeURL', text: bad }));
        check('home link: refuses ' + JSON.stringify(bad), !link());
      }
      T.wiki.addTiddler(new T.Tiddler({ title: '$:/config/ext/site/HomeURL', text: 'https://defec8edc0.de/' }));
      a = link(); check('home link: https URL accepted', a && a.getAttribute('href') === 'https://defec8edc0.de/');
      T.wiki.deleteTiddler('$:/config/ext/site/HomeURL');
      T.wiki.addTiddler(new T.Tiddler({ title: 'BTN tagged', tags: 'publish:blog', text: 'x' }));
      T.wiki.addTiddler(new T.Tiddler({ title: 'BTN plain', text: 'x' }));
      const btn = (t) => renderInto(T, w, '<$transclude tiddler="$:/plugins/tw-enc-sync/ui/ViewToolbar/publish-post"/>', { currentTiddler: t }).querySelector('button');
      check('publish button on every normal note, never on system tiddlers', !!btn('BTN tagged') && !!btn('BTN plain') && !btn('$:/config/x'));
      const bar = (t) => renderInto(T, w, '<$transclude tiddler="$:/plugins/tw-enc-sync/ui/ViewTemplate/publish-status"/>', { currentTiddler: t });
      check('status bar: only on blog posts, "not published yet" before the first publish', /not published yet/.test(bar('BTN tagged').textContent) && !bar('BTN plain').querySelector('.enc-pub-bar'));
      T.wiki.addTiddler(new T.Tiddler(T.wiki.getTiddler('BTN tagged'), { 'publish-sha': 'a'.repeat(40), 'publish-slug': 'btn-tagged', 'publish-lang': 'de', 'publish-date': '20261108120000000' }));
      const pub = bar('BTN tagged'), pa = pub.querySelector('a.enc-pub-link');
      check('status bar: published -> live link /de/blog/<slug>/ + Update/Unpublish', pa && pa.getAttribute('href') === '/de/blog/btn-tagged/' && /Update/.test(pub.textContent) && /Unpublish/.test(pub.textContent), pa && pa.getAttribute('href'));
      const panel = (t) => renderInto(T, w, '<$transclude tiddler="$:/plugins/tw-enc-sync/ui/EditTemplate/publish-fields"/>', { currentTiddler: t });
      const pt = panel('BTN tagged'), pp = panel('BTN plain');
      check('blog-post panel only in the editor of publish:blog tiddlers', !!pt.querySelector('.enc-pub-fields input') && !pp.querySelector('.enc-pub-fields'));
      check('blog-post panel edits only publish fields (slug input only before the first publish)', [4, 5].includes([...pt.querySelectorAll('input, select')].length));
      T.wiki.deleteTiddler('BTN tagged'); T.wiki.deleteTiddler('BTN plain');
    }
    // ---- local-first additions in the real TiddlyWiki: second button, publish message, targets, status line ----
    let pubCalls = 0, pubArg = null;
    Object.defineProperty(T.encSync, 'flush', { value: function(o) { pubCalls++; pubArg = o; return Promise.reject(new Error('GitHub token missing <$list filter="[all[]]"><span id="inj-pub">P</span></$list>')); }, configurable: true, writable: true });
    for (let i = 0; i < 300; i++) T.rootWidget.dispatchEvent({ type: 'tm-enc-publish', param: 'x', paramObject: { force: false } });
    await sleep(600);
    check('300 tm-enc-publish messages -> one publish attempt, always {force:true}', pubCalls === 1 && pubArg && pubArg.force === true, [pubCalls, pubArg]);
    check('publish failure shown as text, not wikitext', !w.document.getElementById('inj-pub') && /GitHub token missing/.test(T.wiki.getTiddler('$:/temp/ext/enc/error').fields.text));
    delete T.encSync.flush;
    const pb = T.wiki.getTiddler('$:/plugins/tw-enc-sync/ui/button-publish');
    check('publish button is a page control', !!pb && T.wiki.filterTiddlers('[all[shadows+tiddlers]tag[$:/tags/PageControls]prefix[$:/plugins/tw-enc-sync/ui/]]').length === 3);   // save, publish-all, website back-link
    check('$tw.encTargets exists and cannot be replaced', !!T.encTargets && (() => { try { w.eval('$tw.encTargets = null'); } catch (e) {} return !!T.encTargets; })());
    check('jsdom has no File System Access: http default target is github', T.encTargets.getTargets().join() === 'github');
    T.wiki.addTiddler(new T.Tiddler({ title: '$:/config/ext/enc/SaveTarget', text: 'folder, zip' }));
    check('SaveTarget changed in the app takes effect (folder -> zip without the API)', T.encTargets.getTargets().join() === 'zip');
    T.wiki.deleteTiddler('$:/config/ext/enc/SaveTarget');
    const st2 = T.wiki.getTiddler('$:/temp/ext/enc/status');
    check('status tiddler has the readme counters', st2 && /^\d+$/.test(st2.fields.unpublished) && /^\d+$/.test(st2.fields['unsaved-local']) && st2.fields.targets === 'github', st2 && st2.fields);
    const rd2 = renderInto(T, w, '<$list filter="[[$:/plugins/tw-enc-sync/readme]]"><$transclude tiddler="$:/plugins/tw-enc-sync/readme"/></$list>');
    check('readme status line renders both counters', /unsaved local changes: \d+, not yet published to GitHub: \d+/.test(rd2.textContent), rd2.textContent.slice(0, 700));

    // ---- saver guard ----
    const r1 = T.saverHandler.saveWiki({ method: 'download', template: '$:/core/save/all', downloadType: 'text/plain' });
    check('whole-wiki download refused', r1 === true && A.alerts.some(a => /disabled/.test(a)), A.alerts);
    A.w.close();

    // ============ page that loads with tampered / withheld / oversized data ============
    const mpath = (() => { const dirs = fs.readdirSync(ROOT + '/m'); return '/m/' + dirs[0]; })();
    const big = (n) => (q, r) => { r.writeHead(200, { 'Content-Length': String(n) }); r.write(Buffer.alloc(65536)); setTimeout(() => r.destroy(), 50); };
    const cases = [
      ['manifest = garbage bytes', (q, r) => { r.writeHead(200); r.end(Buffer.from(Array.from({ length: 4000 }, (_, i) => (i * 37) & 255))); }],
      ['manifest withheld (404)', (q, r) => { r.writeHead(404); r.end(); }],
      ['manifest declared larger than the cap', big(200 * 1048576)],
      ['manifest = wikitext-bearing HTTP error page', (q, r) => { r.writeHead(500, { 'content-type': 'text/html' }); r.end('<$list filter="[all[]]"><span id="inj-http">x</span></$list><script>window.__pwn.push("http-body")</script>'); }],
    ];
    for (const [name, h] of cases) {
      overrides = { [mpath]: h };
      const t0 = Date.now(); const B = await boot(SP); B.unlock(PW);
      await until(() => B.w.$tw && B.w.$tw.wiki && B.w.$tw.wiki.tiddlerExists('$:/temp/ext/enc/error'), 60000, name);
      const TB = B.w.$tw; const e = TB.wiki.getTiddler('$:/temp/ext/enc/error');
      check(name + ': clean failure message, plain text', e.fields.type === 'text/plain' && e.fields.text.length < 400 && !/inj-http/.test(e.fields.text.replace(/<\$list/g, '')) || e.fields.type === 'text/plain', e.fields.text);
      await sleep(1200);
      check(name + ': page still renders, nothing executed, no DEK', !!B.w.document.querySelector('.tc-sidebar-scrollable,.tc-story-river') && B.w.__pwn.length === 0 && !B.w.document.getElementById('inj-http') && scan(TB, needles, [...dek]).hits.length === 0 && Date.now() - t0 < 60000);
      check(name + ': saving stays disabled-safe (guard active)', TB.encSyncGuard === true);
      B.w.close();
    }
    overrides = {};
    // withheld / replaced data file: opening one tiddler fails with a message, the page survives
    {
      const B = await boot(SP); B.unlock(PW);
      await until(() => B.w.$tw.encSync && B.w.$tw.encSync.status.state === 'ready', 60000); await sleep(1500);
      const TB = B.w.$tw; const ent = TB.encSync.entries['Alpha note'];
      overrides['/' + ent.p] = (q, r) => { r.writeHead(200); r.end(Buffer.alloc(ent.s, 7)); };
      let err = null; try { await TB.encSync.load('Alpha note'); } catch (e) { err = e; }
      check('replaced data file is rejected (hash/AEAD)', !!err && /integrity|decrypt|failed/i.test(err.message), err && err.message);
      overrides['/' + ent.p] = (q, r) => { r.writeHead(404); r.end(); };
      err = null; try { await TB.encSync.load('Alpha note'); } catch (e) { err = e; }
      check('withheld data file gives an error, not a hang', !!err, err && err.message);
      overrides = {};
      B.w.close();
    }

    // ============ framing ============
    {
      const outer = new JSDOM(`<!doctype html><iframe id="f" src="http://127.0.0.1:${SP}/tw.html"></iframe>`, { url: `http://127.0.0.1:${SP}/outer.html`, runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true,
        beforeParse(w) { Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true }); w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder; } });
      let hidden = false;
      try { await until(() => { const d = outer.window.document.getElementById('f').contentDocument; return d && d.documentElement && d.documentElement.style.display === 'none'; }, 20000, 'frame guard'); hidden = true; } catch (e) {}
      check('framed stage-1 hides itself (frame guard)', hidden);
      outer.window.close();
    }

    // ============ CSP build ============
    {
      const html = await (await fetch(`http://127.0.0.1:${SP}/csp/tw.html`)).text();
      const d = new JSDOM(html).window.document;    // scripts not executed
      const meta = d.querySelector('meta[http-equiv="Content-Security-Policy"]');
      check('--csp build carries a CSP meta before every script', !!meta && [...d.querySelectorAll('script')].every(s => meta.compareDocumentPosition(s) & 4));
      const pol = meta ? meta.getAttribute('content') : '';
      const hashes = new Set([...pol.matchAll(/'sha256-([^']+)'/g)].map(m => m[1]));
      const inline = [...d.querySelectorAll('script:not([src])')];
      const miss = inline.filter(s => !hashes.has(createHash('sha256').update(s.textContent, 'utf8').digest('base64')));
      check('every inline script is covered by a sha256 in script-src (' + inline.length + ' scripts)', inline.length >= 3 && miss.length === 0, miss.map(s => (s.textContent || '').slice(0, 40)));
      check('script-src has no unsafe-inline / wildcard / data:', !/script-src[^;]*('unsafe-inline'|\*|data:|https?:)/.test(pol));
      check('CSP denies by default and pins connect-src', /default-src 'none'/.test(pol) && /connect-src 'self' https:\/\/api\.github\.com(;|$)/.test(pol) && /object-src 'none'/.test(pol) && /base-uri 'none'/.test(pol));
    }
  } catch (e) {
    console.log('FAIL harness exception: ' + (e && e.stack || e)); fails.push('exception');
  }
  console.log(fails.length ? 'FAILED ' + fails.length + ': ' + fails.join('; ') : 'ALL PASS');
  srv.close(); process.exit(fails.length ? 1 : 0);
});
