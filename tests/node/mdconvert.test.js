// Pure-Node tests of plugin/src/md-convert.js (WikiText -> Markdown). No wiki, no password, no network.
const path = require('path');
const L = require(path.join(__dirname, '..', '..', 'plugin', 'src', 'md-convert.js'));
const fails = [];
const check = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + n + (!c && x !== undefined ? ' ' + JSON.stringify(x).slice(0, 500) : '')); if (!c) fails.push(n); };

const { OK, REVIEW } = require('./mdcases.js');
// a few expectations written by hand above are replaced here for clarity
const ALIGN = L.convert('| a|\n| b |\n|c |');
check('table cells with different alignment in ONE column are refused', ALIGN === '| a|\n| b |\n|c |', ALIGN);

for (const [name, src, want] of OK) {
  if (name === 'table alignment' || name === 'setext underline lookalike') continue;
  const c = L.classify(src), got = L.convert(src), raw = L.analyze(src).md;
  // text that already contains Markdown signals is (deliberately) never converted by classify/convert; the raw converter still has to be exact
  const guarded = L.looksLikeMarkdown(src);
  check('convert: ' + name, guarded ? (raw === want && c.status !== 'convertible' && got === src) : (c.status === 'convertible' && got === want), { status: c.status, reasons: c.reasons, got, want, raw });
}
check('convert: setext underline lookalike', L.convert('text\n---') === 'text\n\\---', L.convert('text\n---'));

for (const [name, src] of REVIEW) {
  const c = L.classify(src), got = L.convert(src);
  check('review: ' + name, c.status === 'review' && c.reasons.length > 0 && got === src, { status: c.status, reasons: c.reasons, got });
}

// ---- classification with fields ----
const F = (o) => Object.assign({ title: 'Note' }, o);
check('system tiddler skipped', L.classify('x', { title: '$:/config/x' }).status === 'skip');
check('plugin skipped', L.classify('{}', F({ 'plugin-type': 'plugin' })).status === 'skip');
check('module skipped', L.classify('x', F({ 'module-type': 'startup' })).status === 'skip');
check('draft skipped', L.classify('x', F({ 'draft.of': 'A' })).status === 'skip');
check('image skipped', L.classify('AAAA', F({ type: 'image/png' })).status === 'skip');
check('json skipped', L.classify('{}', F({ type: 'application/json' })).status === 'skip');
check('css skipped', L.classify('a{}', F({ type: 'text/css' })).status === 'skip');
check('system tag skipped', L.classify('x', F({ tags: 'a $:/tags/Stylesheet' })).status === 'skip');
check('canonical uri skipped', L.classify('', F({ _canonical_uri: 'x' })).status === 'skip');
check('skinny stub skipped', L.classify(undefined, F({ _is_skinny: '' })).status === 'skip' && /not loaded/.test(L.classify(undefined, F({ _is_skinny: '' })).reasons[0]));
check('skinny with placeholder text skipped', L.classify('', F({ _is_skinny: '' })).status === 'skip');
check('undefined text skipped', L.classify(undefined, F({})).status === 'skip');
check('empty text skipped', L.classify('  \n', F({})).status === 'skip');
check('markdown type recognised', L.classify('# x', F({ type: 'text/x-markdown' })).status === 'already-markdown');
check('markdown type (alias)', L.classify('# x', F({ type: 'text/markdown' })).status === 'already-markdown');
check('explicit wikitext type convertible', L.classify("''x''", F({ type: 'text/vnd.tiddlywiki' })).status === 'convertible');
check('no type convertible', L.classify("''x''", F({})).status === 'convertible');
check('markdown-looking text typed as wikitext goes to review', L.classify('some [a](http://x.com) link\n- a\n- b', F({})).status === 'review');
check('markdown-looking text without fields is already-markdown', L.classify('# Title\n\n- a\n- b\n\n**x**').status === 'already-markdown');
check('encrypt widget goes to review', L.classify('<$encrypt>x</$encrypt>', F({})).status === 'review');

// ---- idempotence ----
let idem = 0, idemBad = [];
for (const [name, src] of OK) {
  const out = L.convert(src);
  const again = L.convert(out);
  const asMd = L.classify(out, F({ type: 'text/x-markdown' })).status;
  const noFields = L.classify(out).status;
  const ok = asMd === 'already-markdown' && (again === out || noFields !== 'convertible');
  idem++; if (!ok) idemBad.push({ name, out, again, noFields });
}
check('idempotence: markdown output is never converted again (' + idem + ' cases)', idemBad.length === 0, idemBad.slice(0, 3));
check('convert(convert(x)) === convert(x) for markdown-signal inputs', ['# T\n\n- a\n- b', '[a](http://x.y)\n\n**b**'].every(s => L.convert(s) === s));

// ---- options ----
const keep = L.convert('[[Site|https://e.com/]]', { externalLinks: 'tw' });
check('externalLinks=tw keeps TiddlyWiki syntax', keep === '[[Site|https://e.com/]]', keep);

// ---- warnings are non-blocking ----
const w = L.classify("it's fine");
check('typographer warning is non-blocking', w.status === 'convertible' && w.warnings.length === 1, w);
const fz = L.classify('see google.com');
check('fuzzy link warning is non-blocking', fz.status === 'convertible' && fz.hints.fuzzy === 1, fz);
check('table header hints', L.classify('|a|b|').hints.headerCells === 2);

// ---- hash & signature helpers ----
check('hash stable and sensitive', L.hash('abc') === L.hash('abc') && L.hash('abc') !== L.hash('abd') && /^[0-9a-f]{8}$/.test(L.hash('')));
check('normalizeText undoes typographer', L.normalizeText('\u2018a\u2019 \u201cb\u201d \u2013 \u2026 \u00a9') === '\'a\' "b" - ... (c)');
const cmp = L.compareSignatures({ words: ['a', 'b'], counts: { li: 2 } }, { words: ['a', 'bx'], counts: { li: 2 } });
check('compareSignatures reports text diffs', !cmp.ok && /word 2/.test(cmp.diffs[0]), cmp);
check('compareSignatures reports count diffs', !L.compareSignatures({ words: [], counts: { a: 1 } }, { words: [], counts: { a: 3 } }).ok);
check('compareSignatures tolerates fuzzy links', L.compareSignatures({ words: [], counts: { a: 1 } }, { words: [], counts: { a: 2 } }, { fuzzy: 1 }).ok);

// ---- robustness: hostile / huge input must stay fast and never throw ----
const hostile = ['[['.repeat(20000), "''".repeat(20001), '`'.repeat(50001), '|'.repeat(100000), '\n'.repeat(100000), '* '.repeat(5000) + 'x', '<'.repeat(60000), 'a//b'.repeat(20000), '\u0000\ufffe\ud800', '[img['.repeat(5000), '|a'.repeat(30000) + '|'];
let slow = [];
for (const h of hostile) { const t = Date.now(); let ok = true; try { L.classify(h); L.convert(h); } catch (e) { ok = false; } const dt = Date.now() - t; if (!ok || dt > 5000) slow.push({ len: h.length, ok, dt }); }
check('hostile inputs: no exception, bounded time', slow.length === 0, slow);
const big = ('! H\n\ntext with ' + "''bold''" + ' and [[Link]] and //it// and `code`.\n\n* a\n** b\n\n').repeat(2000);
const t0 = Date.now(); const cb = L.classify(big); const dtBig = Date.now() - t0;
check('130 KB document classified quickly (' + dtBig + ' ms)', cb.status === 'convertible' && dtBig < 5000, cb.reasons);

console.log(fails.length ? '\nFAILED: ' + fails.length : '\nall passed');
process.exit(fails.length ? 1 : 0);
