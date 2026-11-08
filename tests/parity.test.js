// Run: node tests/parity.test.js   (Node >= 20). Verifies JS format code opens Python-made files and vice versa.
const fs = require('fs'), path = require('path'), assert = require('assert');
const F = require('../plugin/src/encfmt.js');
globalThis.exports = undefined;
(async () => {
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'));
  const keys = await F.deriveKeys(F.b64decode(v.dek));
  for (const c of v.cases) {
    assert.strictEqual(await F.fileId(keys, c.title), c.id);
    assert.strictEqual(await F.catId(keys, 'task'), c.cat);
    assert.strictEqual(await F.filePath(keys, c.title, 'task'), c.path);
    const o = await F.openTiddler(keys, c.title, F.b64decode(c.blob), c.rev);
    assert.strictEqual(o.bodyEnc, c.enc);
    const text = o.bodyEnc === 'base64' ? F.b64encode(o.body) : F.utf8decode(o.body);
    assert.strictEqual(text, c.text);
    // wrong rev / wrong title must fail
    await assert.rejects(F.openTiddler(keys, c.title, F.b64decode(c.blob), c.rev + 1));
    await assert.rejects(F.openTiddler(keys, c.title + 'x', F.b64decode(c.blob), c.rev));
    // JS seal -> JS open + padding bucket check
    const s = await F.sealTiddler(keys, c.title, c.fields, o.body, o.bodyEnc, 9);
    assert.strictEqual((await F.openTiddler(keys, c.title, s, 9)).body.length, o.body.length);
    c.js_blob = F.b64encode(s);
  }
  assert.strictEqual(await F.manifestPath(keys), v.manifest_path);
  const m = await F.openManifest(keys, F.b64decode(v.manifest));
  assert.strictEqual(m.counter, 42);
  v.js_manifest = F.b64encode(await F.sealManifest(keys, {v: 1, counter: 43, tiddlers: {}}));
  fs.writeFileSync(path.join(__dirname, 'js_out.json'), JSON.stringify({cases: v.cases.map(c => ({title: c.title, rev: 9, blob: c.js_blob, text: c.text})), manifest: v.js_manifest}));
  // authentic-but-malformed payloads made by Python must be rejected
  assert.strictEqual((await F.openTiddler(keys, 't', F.b64decode(v.ok_file), 1)).body.length, 1);
  assert.strictEqual((await F.openManifest(keys, F.b64decode(v.ok_manifest))).counter, 42);
  for (const b of v.bad_files) await assert.rejects(F.openTiddler(keys, 't', F.b64decode(b), 1));
  for (const b of v.bad_manifests) await assert.rejects(F.openManifest(keys, F.b64decode(b)));
  // truncation / short blobs
  await assert.rejects(F.openTiddler(keys, 't', new Uint8Array(10), 1));
  await assert.rejects(F.openManifest(keys, new Uint8Array(10)));
  // rev must be a safe non-negative integer (String(1.0) vs Python "1.0" would diverge)
  for (const r of [1.5, -1, '1', NaN, 2 ** 53, null]) await assert.rejects(F.sealTiddler(keys, 't', {}, new Uint8Array(1), 'utf8', r));
  // lone surrogates are rejected, not aliased to U+FFFD
  await assert.rejects(F.fileId(keys, 'a\ud800'));
  await assert.rejects(F.fileId(keys, '\udc00b'));
  await assert.rejects(F.sealTiddler(keys, 't', {x: 'a\ud800'}, new Uint8Array(1), 'utf8', 1));
  assert.strictEqual(await F.fileId(keys, '\ud83d\ude00'), (await F.fileId(keys, '\u{1F600}')));
  assert.notStrictEqual(await F.fileId(keys, 'a\0'), await F.fileId(keys, 'a'));
  await assert.rejects(F.fileId(keys, undefined));
  // BOM is preserved by utf8decode
  assert.strictEqual(F.utf8decode(new Uint8Array([0xef, 0xbb, 0xbf, 0x41])), '\ufeffA');
  // manifest: counter beyond 2^53 and bad entries refused at seal time
  await assert.rejects(F.sealManifest(keys, {v: 1, counter: 2 ** 53, tiddlers: {}}));
  await assert.rejects(F.sealManifest(keys, {v: 1, counter: 1, tiddlers: {a: {p: '../x'}}}));
  // key length / type
  await assert.rejects(F.deriveKeys(new Uint8Array(31)));
  console.log('JS parity OK');
})().catch(e => { console.error(e); process.exit(1); });
