// Rendering-equivalence and UI tests for the WikiText -> Markdown converter, in REAL TiddlyWiki 5.1.21 + the real anstosa/tw5-markdown
// parser (jsdom). Env: WIKI (html file: public skeleton + markdown plugin + our md-convert files, no password, no encryption).
const { JSDOM, VirtualConsole } = require('jsdom');
const fs = require('fs'), path = require('path');
const L = require(path.join(__dirname, '..', '..', 'plugin', 'src', 'md-convert.js'));
const { OK } = require('./mdcases.js');
const fails = [];
const check = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + n + (!c && x !== undefined ? ' ' + JSON.stringify(x).slice(0, 700) : '')); if (!c) fails.push(n); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms = 20000, what = '') { const t = Date.now(); for (;;) { try { const v = await fn(); if (v) return v; } catch (e) {} if (Date.now() - t > ms) throw new Error('timeout ' + what); await sleep(50); } }

(async () => {
  const html = fs.readFileSync(process.env.WIKI, 'utf8'), logs = [], confirms = [];
  const vc = new VirtualConsole(); ['log', 'info', 'warn', 'error'].forEach(k => vc.on(k, (...a) => logs.push(k + ' ' + a.join(' ')))); vc.on('jsdomError', e => logs.push('JSDOMERR ' + e.message));
  const dom = new JSDOM(html, { url: 'http://127.0.0.1/tw.html', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc, beforeParse(w) {
    w.requestAnimationFrame = f => setTimeout(f, 16);
    w.confirm = m => { confirms.push(m); return w.__answer !== false; };
  } });
  const w = dom.window;
  const T = await until(() => w.$tw && w.$tw.rootWidget && w.$tw.mdConvert && w.$tw, 60000, 'boot');
  const M = T.mdConvert;
  await M.scan({ loadTimeout: 0 }); check('parser fix self-test: markdown parser needed the fix and it is active', M.parser.state === 'active' && M.parser.installed, M.parser.state);

  const sig = (type, text) => M.renderSignature(type, text);
  const origParser = M.parser.original;
  function sigOriginal(text) {   // the unfixed plugin parser
    const P = T.Wiki.parsers, fixed = P['text/x-markdown'];
    P['text/x-markdown'] = origParser;
    try { return sig('text/x-markdown', text); } finally { P['text/x-markdown'] = fixed; }
  }

  // ---------- equivalence over the shared case table ----------
  let n = 0, bad = [], brokenWithoutFix = 0;
  for (const [name, src] of OK) {
    const a = L.analyze(src); if (a.md === null) continue;
    n++;
    const s1 = sig('text/vnd.tiddlywiki', src), s2 = sig('text/x-markdown', a.md);
    const c = L.compareSignatures(s1, s2, a.hints);
    if (!c.ok) bad.push({ name, md: a.md, diffs: c.diffs });
    if (!L.compareSignatures(s1, sigOriginal(a.md), a.hints).ok) brokenWithoutFix++;
  }
  check('rendering equivalence of WikiText vs converted Markdown (' + n + ' cases)', bad.length === 0, bad.slice(0, 4));
  console.log('INFO ' + brokenWithoutFix + ' of ' + n + ' cases would render differently with the UNFIXED tw5-markdown parser (spaces lost after inline elements, text re-read as block syntax)');

  // the parser fix keeps pragma-looking text and a leading colon / asterisk inert
  const hz = M.renderSignature('text/x-markdown', 'a **b**\n\n\\\\define foo() bar\n\n**x** : y * z');
  check('parser fix: no pragma / list syntax is read from Markdown text nodes', hz.words.join(' ') === 'a b \\define foo() bar x : y * z' && !hz.counts.li && !hz.counts.dl, hz);

  // ---------- realistic notes ----------
  const NOTES = {
    howto: "! Install nginx\n\nRun the following:\n\n```bash\nsudo apt install nginx\nsudo systemctl enable --now nginx   # //not italic//\n```\n\n!! Config\n* Edit `/etc/nginx/nginx.conf`\n** set ''worker_processes'' to //auto//\n** see [[Hardening]] and [[Nginx docs|https://nginx.org/en/docs/]]\n* Reload: `nginx -s reload`\n\n|!Option|!Meaning|\n|`gzip`|compress responses|\n|`keepalive_timeout`|idle seconds|\n\n<<<\nPremature optimisation is the root of all evil.\n<<<\n\nSee http://nginx.org/en/docs/http/ngx_http_core_module.html#server_name for more.",
    journal: "! 2024-03-05\n\nSlept badly. ''Mood'': flat, but //better// after a walk.\n\n!! Tasks\n# call the dentist\n# finish report\n## outline\n## draft\n# water plants\n\nNote to self: don't forget to read [[Attachment theory]] - it explains the pattern with ,,Mum,,.\n\n---\n\nTomorrow: ^^1st^^ session.",
    psych: "!! Cognitive biases\n\n''Confirmation bias'': we seek what we already believe. ''Anchoring'': the first number wins.\n\n* ''A'' - first\n* ''B'' - second\n\n> One line quote\n> second line\n\nFurther reading: [[Kahneman|https://en.wikipedia.org/wiki/Daniel_Kahneman]] and ~~outdated~~ [[Biases]].\n\n__Underlined__ and ''//both//''.",
    poorly: "just text, no markup at all.\nsecond line of the same paragraph.\n\nthird paragraph with 2 * 3 = 6 and a_b and C:\\tmp.",
  };
  for (const [k, src] of Object.entries(NOTES)) {
    const a = L.analyze(src);
    if (a.md === null) { check('realistic note converts: ' + k, false, a.reasons); continue; }
    const c = L.compareSignatures(sig('text/vnd.tiddlywiki', src), sig('text/x-markdown', a.md), a.hints);
    check('realistic note renders the same: ' + k, c.ok, { diffs: c.diffs, md: a.md });
  }

  // ---------- the converter's own render check refuses a bad conversion ----------
  const badv = M.verify('plain //x// y', 'plain x y', {});
  check('verify() rejects a conversion that changes the rendering', !badv.ok && badv.diffs.length > 0, badv);

  // ---------- Control Panel / actions ----------
  const wiki = T.wiki;
  const put = (f) => wiki.addTiddler(new T.Tiddler(f));
  const get = (t) => wiki.getTiddler(t) && wiki.getTiddler(t).fields;
  const HOSTILE = 'HOSTILE <b id="inj-title">T</b> <$list filter="[all[]" variable=x> {{y}} <<z>> [x]';
  const SRC = { conv: "! Head\n\n''bold'' text and [[Link]]", conv2: "//it// and `code`", conv3: "x ''y'' z", review: 'uses <<macro>> here', md: '# Already\n\n**md**', img: 'AAAA', skinnyOk: "! Lazy\n\n''was skinny''", hostile: "''h''", empty: '', loose: 'plain' };
  put({ title: 'Conv A', text: SRC.conv, tags: 'journal', created: '20200101000000000', modified: '20210101000000000' });
  put({ title: 'Conv B', text: SRC.conv2, type: 'text/vnd.tiddlywiki', modified: '20210202000000000' });
  put({ title: 'Conv C', text: SRC.conv3 });
  put({ title: 'Review A', text: SRC.review });
  put({ title: 'Md A', text: SRC.md, type: 'text/x-markdown' });
  put({ title: 'Img A', text: SRC.img, type: 'image/png' });
  put({ title: 'Empty A', text: '' });
  put({ title: HOSTILE, text: SRC.hostile });
  put({ title: 'Weird ]] title', text: "''w''" });
  put({ title: '$:/test/system', text: "''sys''" });
  put({ title: 'Skinny OK', _is_skinny: '', tags: 'demo', 'x-field': 'keep' });          // no text: a lazy-load stub
  put({ title: 'Skinny never', _is_skinny: '' });
  wiki.addEventListener('lazyLoad', title => { if (title === 'Skinny OK') setTimeout(() => wiki.addTiddler(new T.Tiddler(get('Skinny OK'), { text: SRC.skinnyOk, _is_skinny: undefined })), 300); });

  const status = () => get('$:/temp/ext/md/status') || {};
  const lst = (n) => T.utils.parseStringArray((get('$:/temp/ext/md/list/' + n) || {}).list || '') || [];
  const t0 = Date.now();
  put({ title: '$:/config/ext/md/LoadTimeout', text: '2500' });
  const res = await M.scan({ loadTimeout: 3000 });
  check('scan finishes and lazily loads a stub within the timeout (' + (Date.now() - t0) + ' ms)', res && lst('convertible').includes('Skinny OK'), lst('convertible'));
  check('scan: convertible list', ['Conv A', 'Conv B', 'Conv C', HOSTILE, 'Skinny OK'].every(t => lst('convertible').includes(t)) && lst('convertible').length === 5, lst('convertible'));
  check('scan: needs-review list has the macro note', lst('review').includes('Review A') && lst('review').length === 1, lst('review'));
  check('scan: already markdown', lst('markdown').includes('Md A'), lst('markdown'));
  check('scan: stub that never loads is reported, never converted', lst('unloaded').join() === 'Skinny never' && /not loaded/i.test(status().message), { u: lst('unloaded'), m: status().message });
  check('scan: system, image, empty tiddlers are skipped silently', ![...lst('convertible'), ...lst('review'), ...lst('markdown')].some(t => ['$:/test/system', 'Img A', 'Empty A'].includes(t)));
  check('scan: a title containing ]] is counted as unlistable, not injected into the list', get('$:/temp/ext/md/list/convertible').unlistable === '1' && !lst('convertible').some(t => /\]\]/.test(t)), get('$:/temp/ext/md/list/convertible'));
  const reasons = JSON.parse(get('$:/temp/ext/md/reasons').text);
  check('scan: review reason recorded', /macro/.test(reasons['Review A']), reasons);
  check('status counts', status()['n-convertible'] === '6' && status()['n-review'] === '1' && status()['n-markdown'] === '1' && status()['n-unloaded'] === '1' && status().state === 'idle', status());
  check('scan changed no user tiddler', get('Conv A').text === SRC.conv && get('Conv A').type === undefined && get('Skinny never').text === undefined);

  // the Control Panel tab renders titles as text only
  function renderTitle(title, vars) {
    const p = wiki.parseTiddler(title); const wd = wiki.makeWidget(p, { document: w.document, parentWidget: T.rootWidget, variables: vars || {} });
    const div = w.document.createElement('div'); w.document.body.appendChild(div); wd.render(div, null); return div;
  }
  const tab = renderTitle('$:/plugins/tw-enc-sync/md-convert/ui');
  check('control panel tab is tagged and captioned', [].concat(get('$:/plugins/tw-enc-sync/md-convert/ui').tags).join() === '$:/tags/ControlPanel' && get('$:/plugins/tw-enc-sync/md-convert/ui').caption === 'Markdown');
  check('control panel shows the report', /convertible/i.test(tab.textContent) && /Needs review/.test(tab.textContent) && tab.textContent.includes('uses') === false && /macro/.test(tab.textContent), tab.textContent.slice(0, 300));
  check('control panel: hostile title is displayed as text, not interpreted', !tab.querySelector('#inj-title') && tab.textContent.includes('<b id="inj-title">T</b>'), tab.innerHTML.slice(0, 400));
  const btns = [...tab.querySelectorAll('button')].map(b => b.textContent);
  check('control panel is list-only: just a Scan button (no convert/revert/backup buttons)', btns.length === 1 && btns[0] === 'Scan', btns);

  // convert all: confirmation first
  w.__answer = false;
  T.rootWidget.dispatchEvent({ type: 'tm-md-convert-all' });
  await until(() => confirms.length === 1 && /Cancelled/.test(status().message), 15000, 'confirm 1');
  check('convert all asks for confirmation and does nothing when declined', get('Conv A').type === undefined && /6 tiddler/.test(confirms[0]), confirms[0]);
  w.__answer = true;
  T.rootWidget.dispatchEvent({ type: 'tm-md-convert-all' });
  await until(() => confirms.length === 2 && /Converted 6/.test(status().message), 20000, 'convert');
  const A = get('Conv A'), B = get('Conv B'), S = get('Skinny OK');
  check('converted: Markdown text and backup', A.type === 'text/x-markdown' && A.text === '# Head\n\n**bold** text and [[Link]]' && A['wikitext-backup'] === SRC.conv && A['md-converted-hash'] === L.hash(A.text), A);
  check('converted: explicit wikitext type remembered', B.type === 'text/x-markdown' && B['wikitext-backup-type'] === 'text/vnd.tiddlywiki' && A['wikitext-backup-type'] === undefined);
  check('converted: lazily-loaded stub keeps its other fields', S.type === 'text/x-markdown' && [].concat(S.tags).join() === 'demo' && S['x-field'] === 'keep' && S['wikitext-backup'] === SRC.skinnyOk && S._is_skinny === undefined, S);
  check('converted: created/modified timestamps not touched', T.utils.stringifyDate(get('Conv B').modified) === '20210202000000000' && T.utils.stringifyDate(get('Conv A').created) === '20200101000000000', [get('Conv B').modified, get('Conv A').created]);
  check('not converted: review, markdown, image, system, empty, never-loaded, ]]-title...', get('Review A').text === SRC.review && get('Review A').type === undefined && get('Md A')['wikitext-backup'] === undefined &&
    get('Img A').type === 'image/png' && get('$:/test/system').type === undefined && get('Empty A').type === undefined && get('Skinny never').text === undefined && get('Skinny never').type === undefined, null);
  check('the ]]-title note was converted too (title is data, not syntax)', get('Weird ]] title').type === 'text/x-markdown' && get(HOSTILE).type === 'text/x-markdown');
  check('after conversion the report shows them as converted', lst('converted').length === 5 && status()['n-converted'] === '6' && status()['n-convertible'] === '0', status());
  check('a rendered converted note shows the same words', M.renderSignature('text/x-markdown', A.text).words.join(' ') === 'Head bold text and Link');
  check('there is no per-tiddler toolbar button any more', !get('$:/plugins/tw-enc-sync/md-convert/ui/view-button'));

  // edit one converted note, then bulk revert: the edited one is left alone
  put(Object.assign({}, get('Conv C'), { text: get('Conv C').text + '\n\nedited later' }));
  w.__answer = true;
  T.rootWidget.dispatchEvent({ type: 'tm-md-revert-all' });
  await until(() => /Reverted 5/.test(status().message), 15000, 'revert all');
  const rA = get('Conv A'), rB = get('Conv B');
  check('revert all restores text and type exactly, drops the backup fields', rA.text === SRC.conv && rA.type === undefined && rA['wikitext-backup'] === undefined && rA['md-converted-hash'] === undefined && rA['wikitext-backup-type'] === undefined &&
    rB.text === SRC.conv2 && rB.type === 'text/vnd.tiddlywiki' && get('Skinny OK').text === SRC.skinnyOk && get('Skinny OK').type === undefined && [].concat(rA.tags).join() === 'journal', { rA, rB });
  check('revert all leaves a note edited after conversion alone and lists it', get('Conv C').type === 'text/x-markdown' && /edited later/.test(get('Conv C').text) && lst('modified').join() === 'Conv C', lst('modified'));
  check('revert all: other ]]/hostile titles reverted', get('Weird ]] title').type === undefined && get(HOSTILE).type === undefined);

  // single-tiddler actions
  T.rootWidget.dispatchEvent({ type: 'tm-md-convert', param: 'Conv A' });
  await sleep(50);
  check('tm-md-convert converts one note', get('Conv A').type === 'text/x-markdown' && get('Conv A')['wikitext-backup'] === SRC.conv);
  T.rootWidget.dispatchEvent({ type: 'tm-md-convert', param: 'Review A' });
  check('tm-md-convert refuses a note that needs review and says why', get('Review A').type === undefined && /macro/i.test(status().message), status().message);
  T.rootWidget.dispatchEvent({ type: 'tm-md-convert', param: '$:/test/system' });
  check('tm-md-convert refuses system tiddlers', get('$:/test/system').type === undefined);
  T.rootWidget.dispatchEvent({ type: 'tm-md-convert', param: 'Skinny never' });
  check('tm-md-convert never converts a note whose text is not loaded', get('Skinny never').type === undefined && get('Skinny never').text === undefined);
  T.rootWidget.dispatchEvent({ type: 'tm-md-revert', param: 'Conv A' });
  check('tm-md-revert reverts one note', get('Conv A').type === undefined && get('Conv A').text === SRC.conv && get('Conv A')['wikitext-backup'] === undefined);
  w.__answer = false;
  const before = get('Conv C').text;
  T.rootWidget.dispatchEvent({ type: 'tm-md-revert', param: 'Conv C' });
  check('tm-md-revert of an edited note asks and respects "no"', get('Conv C').text === before && /edited after/.test(confirms[confirms.length - 1]));
  w.__answer = true;
  T.rootWidget.dispatchEvent({ type: 'tm-md-revert', param: 'Conv C' });
  check('tm-md-revert of an edited note reverts when confirmed', get('Conv C').text === SRC.conv3 && get('Conv C').type === undefined);

  // drop backups
  await M.convertAll();
  w.__answer = true;
  T.rootWidget.dispatchEvent({ type: 'tm-md-drop-backups' });
  await until(() => /Deleted \d+ backup/.test(status().message), 15000, 'drop');
  check('delete backups removes the backup fields but keeps the Markdown', get('Conv A').type === 'text/x-markdown' && get('Conv A')['wikitext-backup'] === undefined && get('Conv A')['md-converted-hash'] === undefined && get('Conv A').text.startsWith('# Head'));

  // nothing logs note content
  check('no note content in the console', !logs.some(l => /bold|Head|macro/.test(l)), logs.filter(l => /bold|Head|macro/.test(l)).slice(0, 3));

  console.log(fails.length ? '\nFAILED: ' + fails.length : '\nall passed');
  process.exit(fails.length ? 1 : 0);
})().catch(e => { console.log('FAIL exception ' + (e && e.stack || e)); process.exit(1); });
