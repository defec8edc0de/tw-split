// Pure-Node tests of plugin/src/publish.js and the plaintext methods of github.js. Synthetic data only; no network.
const path = require('path');
const P = require(path.join(__dirname, '..', '..', 'plugin', 'src', 'publish.js'));
const G = require(path.join(__dirname, '..', '..', 'plugin', 'src', 'github.js'));
const C = require(path.join(__dirname, '..', '..', 'plugin', 'src', 'md-convert.js'));
const fails = [];
const check = (n, c, x) => { console.log((c ? 'PASS ' : 'FAIL ') + n + (!c && x !== undefined ? ' ' + JSON.stringify(x).slice(0, 400) : '')); if (!c) fails.push(n); };
const throwsCode = (fn, code) => { try { fn(); return false; } catch (e) { return e instanceof P.PublishError && (!code || e.code === code); } };

const base = (o) => Object.assign({ title: 'Hello World', tags: 'notes publish:blog', type: 'text/x-markdown', text: 'Body **bold**.', created: '20261101093000000', modified: '20261102100000000' }, o);
const opts = { convert: (t, f) => { const c = C.classify(t, f); return c.status === 'convertible' ? C.convert(t) : null; } };

// ---- slugs + paths ----
check('slugify basic', P.slugify('Hello, World!') === 'hello-world');
check('slugify umlauts', P.slugify('Über Größe & Maß') === 'ueber-groesse-mass', P.slugify('Über Größe & Maß'));
check('slugify length <= 80, no trailing dash', P.slugify('a'.repeat(79) + ' b c').length <= 80 && !/-$/.test(P.slugify('a'.repeat(79) + ' b c')));
const okPaths = ['content/blog/a/index.md', 'content/blog/my-post/index.de.md', 'content/blog/x1/pic-2.webp', 'content/blog/x1/p.jpeg'];
const badPaths = ['content/blog/../x/index.md', 'content/blog/a/b/index.md', 'content/blog/A/index.md', 'content/blog/a/index.html', 'content/blog/-a/index.md',
  'content/blog/a/index.en.md', 'content/x/a/index.md', 'tw.html', '0123456789ab/' + '0'.repeat(32) + '.bin', 'm/' + '0'.repeat(32) + '.bin', 'content/blog/a/x.svg', 'content/blog/a/.htaccess'];
check('PUB_PATH_RE accepts post paths', okPaths.every((p) => P.PUB_PATH_RE.test(p)));
check('PUB_PATH_RE rejects everything else', badPaths.every((p) => !P.PUB_PATH_RE.test(p)), badPaths.filter((p) => P.PUB_PATH_RE.test(p)));
check('ciphertext PATH_RE and PUB_PATH_RE are disjoint', okPaths.every((p) => !G.PATH_RE.test(p)));
check('github.js and publish.js share the same allowlist', G.PUB_PATH_RE.source === P.PUB_PATH_RE.source);

// ---- buildPost: happy path + front matter ----
let p = P.buildPost(base({ 'publish-tags': 'k8s security', summary: 'A short\nsummary' }), opts);
check('path en', p.path === 'content/blog/hello-world/index.md' && p.slug === 'hello-world', p.path);
check('front matter: JSON-quoted title, date from created, lastmod', /^---\ntitle: "Hello World"\ndate: "2026-11-01T09:30:00Z"\nlastmod: "2026-11-02T10:00:00Z"\n/.test(p.markdown), p.markdown);
check('front matter: description collapsed', p.markdown.includes('description: "A short summary"'));
check('front matter: tags only from publish-tags', p.markdown.includes('tags: ["k8s", "security"]') && !/"notes"|publish:blog/.test(p.markdown));
check('front matter: source vault + translationKey', p.markdown.includes('source: "vault"') && p.markdown.includes('translationKey: "hello-world"'));
check('body kept', p.markdown.endsWith('\n\nBody **bold**.\n'));
p = P.buildPost(base({ title: 'Evil"\n---\nlayout: x\n{{x}}'.replace('{{x}}', ''), 'publish-slug': 'evil' }), opts);
check('YAML injection through the title is inert', p.markdown.startsWith('---\ntitle: "Evil\\"\\n---\\nlayout: x\\n"\nslug: "evil"\n'), p.markdown.slice(0, 120));
p = P.buildPost(base({ 'publish-lang': 'de', 'publish-slug': 'hallo-welt' }), opts);
check('lang de -> index.de.md, slug kept', p.path === 'content/blog/hallo-welt/index.de.md' && p.markdown.includes('slug: "hallo-welt"'));

// ---- refusals ----
check('not tagged -> refused', throwsCode(() => P.buildPost(base({ tags: 'notes' }), opts)));
check('system tiddler -> refused', throwsCode(() => P.buildPost(base({ title: '$:/config/x' }), opts)));
check('skinny (not loaded) -> refused', throwsCode(() => P.buildPost(base({ _is_skinny: '', text: undefined }), opts), 'not-loaded'));
check('draft -> refused', throwsCode(() => P.buildPost(base({ 'draft.of': 'Hello World' }), opts)));
check('bad lang -> refused', throwsCode(() => P.buildPost(base({ 'publish-lang': 'fr' }), opts)));
check('bad slug -> refused', throwsCode(() => P.buildPost(base({ 'publish-slug': '../etc' }), opts)));
for (const [name, text] of [['tag characters', 'hi\u{E0049}\u{E0066} there'], ['bidi override', 'a\u202Eb'], ['zero width', 'a\u200Bb'], ['BOM', '\uFEFFx']]) {
  check('invisible Unicode refused: ' + name, throwsCode(() => P.buildPost(base({ text }), opts), 'invisible'));
}
check('invisible Unicode in title refused', throwsCode(() => P.buildPost(base({ title: 'x\u2066y' }), opts), 'invisible'));
for (const [name, text] of [['transclusion', 'see {{Private note}}'], ['filtered transclusion', '{{{ [tag[journal]] }}}'], ['macro', '<<list-links "[tag[x]]">>'],
  ['widget', '<$list filter="[all[]]"/>'], ['script', '<script>alert(1)</script>'], ['img onerror', '<img src=x onerror=alert(1)>'], ['html comment', '<!-- x -->'],
  ['pragma', '\\define x() y\nz'], ['tw extlink', '[ext[x]]']]) {
  check('forbidden construct refused: ' + name, throwsCode(() => P.buildPost(base({ text }), opts), 'forbidden'));
}
p = P.buildPost(base({ text: 'Code may show `<script>` and `{{x}}`:\n\n```html\n<div>{{y}}</div>\n<<m>>\n```\n\nAutolink <https://example.org>.' }), opts);
check('code spans / fences and autolinks are allowed', p.markdown.includes('```html\n<div>{{y}}</div>') && p.markdown.includes('<https://example.org>'));
check('WikiText that converts is published as Markdown', P.buildPost(base({ type: '', text: "''bold'' and //it//" }), opts).markdown.endsWith('**bold** and *it*\n'));
check('WikiText that cannot be converted is refused', throwsCode(() => P.buildPost(base({ type: '', text: '|a|b|f\n' }), opts), 'not-convertible'));
check('other types refused', throwsCode(() => P.buildPost(base({ type: 'text/html', text: 'x' }), opts)));

// ---- automatic description ----
check('auto description: first real paragraph, markup stripped', P.autoDescription('## Heading\n\nSee **this** [link](https://x) and `code` here, long enough.\n\nSecond.') === 'See this link and code here, long enough.', P.autoDescription('## Heading\n\nSee **this** [link](https://x) and `code` here, long enough.\n\nSecond.'));
check('auto description: shortened on a word boundary', (() => { const d = P.autoDescription('word '.repeat(60)); return d.length <= 160 && d.endsWith('…') && !d.includes('word…'.slice(0, 0) + ' …'); })());
check('auto description: skips lists, quotes and code', P.autoDescription('- a list item that is long enough to count\n\n```\ncode block that is long enough\n```\n\nReal text starts here.') === 'Real text starts here.');
p = P.buildPost(base({ text: '## Intro\n\nGardener splits clusters into shoots and seeds, which matters.' }), opts);
check('buildPost writes an auto description when there is no summary', p.markdown.includes('description: "Gardener splits clusters into shoots and seeds, which matters."'), p.markdown.slice(0, 300));

// ---- links ----
const resolve = (t) => (t === 'Published one' ? '/blog/published-one/' : null);
p = P.buildPost(base({ text: 'See [[Private note]], [[the post|Published one]] and `[[kept in code]]`.' }), Object.assign({ resolve }, opts));
check('links: unpublished -> text, published -> URL, code untouched', p.markdown.endsWith('See Private note, [the post](/blog/published-one/) and `[[kept in code]]`.\n'), p.markdown);

// ---- media ----
const png = Buffer.from('89504e470d0a1a0a', 'hex').toString('base64');
const media = { 'Diagram.png': { title: 'Diagram.png', type: 'image/png', text: png }, 'Vec.svg': { title: 'Vec.svg', type: 'image/svg+xml', text: '<svg/>' } };
p = P.buildPost(base({ text: 'Look: ![a diagram](#Diagram.png)', 'publish-media': 'Diagram.png' }), Object.assign({ mediaFields: (t) => media[t] || null }, opts));
check('media: file path + Markdown reference rewritten', p.media.length === 1 && p.media[0].path === 'content/blog/hello-world/diagram.png' && p.markdown.includes('![a diagram](diagram.png)'), [p.media, p.markdown]);
check('media: SVG refused', throwsCode(() => P.buildPost(base({ 'publish-media': 'Vec.svg' }), Object.assign({ mediaFields: (t) => media[t] || null }, opts)), 'media'));
check('media: missing refused', throwsCode(() => P.buildPost(base({ 'publish-media': 'Nope.png' }), Object.assign({ mediaFields: () => null }, opts)), 'media'));

// ---- images referenced in the text are published automatically ----
const mf = (t) => media[t] || null;
p = P.buildPost(base({ text: 'Intro text.\n\n[img[A diagram|Diagram.png]]' }), Object.assign({ mediaFields: mf }, opts));
check('[img[alt|Title]] -> Markdown image + file, no publish-media needed', p.media.length === 1 && p.markdown.includes('![A diagram](diagram.png)'), [p.media, p.markdown]);
p = P.buildPost(base({ text: 'See ![x](#Diagram.png) and `![not](#Vec.svg)` in code.' }), Object.assign({ mediaFields: mf }, opts));
check('![alt](#Title) auto-detected; references inside code ignored', p.media.length === 1 && p.markdown.includes('![x](diagram.png)') && p.markdown.includes('`![not](#Vec.svg)`'));
check('unknown image reference refused with a clear message', (() => { try { P.buildPost(base({ text: '![x](#Nope.png)' }), Object.assign({ mediaFields: mf }, opts)); } catch (e) { return e.code === 'media' && /image not found/.test(e.message); } return false; })());
check('external image refused (site CSP)', (() => { try { P.buildPost(base({ text: '![x](https://evil.example/p.png)' }), Object.assign({ mediaFields: mf }, opts)); } catch (e) { return e.code === 'media' && /external image/.test(e.message); } return false; })());
check('[img[...]] of a missing tiddler refused', throwsCode(() => P.buildPost(base({ text: '[img[Secret.png]]' }), Object.assign({ mediaFields: () => null }, opts)), 'media'));

// ---- publish / unpublish against a fake client ----
function fakeRepo(files) {
  const st = { files: Object.assign({}, files), commits: [], blobs: 0 };
  const sha40 = (s) => require('crypto').createHash('sha1').update(s).digest('hex');
  return {
    st,
    getHead: async () => ({ commit: 'c'.repeat(40), tree: 't'.repeat(40) }),
    getContentSha: async (p) => (p in st.files ? st.files[p] : null),
    createBlob: async (bytes) => { st.blobs++; const h = require('crypto').createHash('sha1'); h.update('blob ' + bytes.length + '\0'); h.update(Buffer.from(bytes)); return h.digest('hex'); },
    listDir: async (dir) => Object.keys(st.files).filter((p) => p.startsWith(dir + '/')),
    commitPlain: async (head, entries, msg) => { entries.forEach((e) => { if (!P.PUB_PATH_RE.test(e.path)) throw new Error('bad path'); if (e.sha === null) delete st.files[e.path]; else st.files[e.path] = e.sha; }); st.commits.push({ entries, msg }); return { commit: sha40(msg + st.commits.length) }; },
  };
}
(async () => {
  const post = P.buildPost(base({}), opts);
  let repo = fakeRepo({});
  let r = await P.publish(repo, post, {});
  check('publish: new post -> one commit with only the post file', repo.st.commits.length === 1 && repo.st.commits[0].entries.length === 1 && repo.st.commits[0].entries[0].path === post.path && /^[0-9a-f]{40}$/.test(r.sha));
  check('publish: returned sha is the git blob id GitHub reports', repo.st.files[post.path] === r.sha);
  const sha1 = r.sha;
  r = await P.publish(repo, post, { lastSha: sha1 });
  check('publish: unchanged -> no commit', r.unchanged && repo.st.commits.length === 1);
  const post2 = P.buildPost(base({ text: 'Edited body.' }), opts);
  r = await P.publish(repo, post2, { lastSha: sha1 });
  check('publish: update after own publish -> commit', !r.unchanged && repo.st.commits.length === 2);
  repo.st.files[post.path] = 'e'.repeat(40);   // edited on GitHub
  let err = null; try { await P.publish(repo, post2, { lastSha: r.sha }); } catch (e) { err = e; }
  check('publish: remote edit -> conflict', err && err.code === 'conflict' && repo.st.commits.length === 2);
  r = await P.publish(repo, post2, { lastSha: r.sha, force: true });
  check('publish: force overwrites', repo.st.commits.length === 3);
  repo = fakeRepo({ [post.path]: 'f'.repeat(40) });
  err = null; try { await P.publish(repo, post, {}); } catch (e) { err = e; }
  check('publish: existing file never published by us -> conflict', err && err.code === 'conflict');
  // unpublish
  repo = fakeRepo({ 'content/blog/hello-world/index.md': 'a'.repeat(40), 'content/blog/hello-world/index.de.md': 'b'.repeat(40), 'content/blog/hello-world/diagram.png': 'c'.repeat(40) });
  r = await P.unpublish(repo, 'hello-world', 'en');
  check('unpublish en while de exists -> only index.md removed', r.removed.length === 1 && r.removed[0].endsWith('/index.md') && 'content/blog/hello-world/diagram.png' in repo.st.files);
  r = await P.unpublish(repo, 'hello-world', 'de');
  check('unpublish last language -> folder removed', Object.keys(repo.st.files).length === 0, repo.st.files);
  r = await P.unpublish(repo, 'hello-world', 'de');
  check('unpublish missing -> no commit', r.commit === null && r.removed.length === 0);
  check('unpublish bad slug refused', await P.unpublish(repo, '../x', 'en').then(() => false, () => true));

  // ---- github.js Client.commitPlain against a fake fetch ----
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, method: init.method, body: init.body && JSON.parse(init.body) });
    const json = (o, s = 200) => ({ ok: s < 300, status: s, headers: { get: () => null }, body: null, arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(o)).buffer });
    if (init.method === 'POST' && url.endsWith('/git/trees')) return json({ sha: '1'.repeat(40) }, 201);
    if (init.method === 'POST' && url.endsWith('/git/commits')) return json({ sha: '2'.repeat(40), tree: { sha: '1'.repeat(40) } }, 201);
    if (init.method === 'PATCH') return json({ object: { sha: '2'.repeat(40) } });
    if (init.method === 'GET' && url.includes('/contents/content/blog/missing/')) return json({ message: 'Not Found' }, 404);
    if (init.method === 'GET' && url.includes('/contents/')) return json({ type: 'file', sha: '3'.repeat(40) });
    return json({}, 500);
  };
  const cl = new G.Client({ repo: 'o/r', branch: 'master', apiBase: 'https://api.github.com', token: 'ghp_PUBLISHTEST0123456789', fetch: fakeFetch });
  const head = { commit: 'c'.repeat(40), tree: 'd'.repeat(40) };
  err = null; try { await cl.commitPlain(head, [{ path: '0123456789ab/' + '0'.repeat(32) + '.bin', sha: null }], 'x'); } catch (e) { err = e; }
  check('commitPlain refuses ciphertext paths', err && /unexpected path/.test(err.message) && calls.length === 0);
  err = null; try { await cl.commitPlain(head, [{ path: 'tw.html', sha: '1'.repeat(40) }], 'x'); } catch (e) { err = e; }
  check('commitPlain refuses tw.html', err && calls.length === 0);
  err = null; try { await cl.commit(head, [{ path: 'content/blog/a/index.md', sha: '1'.repeat(40) }], 'x'); } catch (e) { err = e; }
  check('ciphertext commit() refuses post paths', err && calls.length === 0);
  const res = await cl.commitPlain(head, [{ path: 'content/blog/a/index.md', sha: '9'.repeat(40) }], 'Publish: a');
  const tree = calls.find((c) => c.url.endsWith('/git/trees'));
  check('commitPlain: base_tree kept, one entry, fast-forward ref update', tree && tree.body.base_tree === head.tree && tree.body.tree.length === 1 && calls.some((c) => c.method === 'PATCH' && c.body.force === false) && res.commit === '2'.repeat(40));
  check('getContentSha: 404 -> null', (await cl.getContentSha('content/blog/missing/index.md', 'c'.repeat(40))) === null);
  check('getContentSha: file -> sha', (await cl.getContentSha('content/blog/a/index.md', 'c'.repeat(40))) === '3'.repeat(40));
  check('getContentSha refuses non-post paths', await cl.getContentSha('m/' + '0'.repeat(32) + '.bin', 'c'.repeat(40)).then(() => false, () => true));
  check('token never in a request body', !calls.some((c) => JSON.stringify(c.body || '').includes('PUBLISHTEST')));

  console.log(fails.length ? `\nFAILED ${fails.length}: ${fails.join(' | ')}` : '\nall passed');
  process.exit(fails.length ? 1 : 0);
})().catch((e) => { console.log('FAIL exception ' + (e && e.stack || e)); process.exit(1); });
