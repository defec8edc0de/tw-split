import base64, json, os, shutil, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..'); sys.path.insert(0, os.path.join(ROOT, 'tools'))
import encfmt, twlib
SRC = os.environ.get('TW_SOURCE') or os.path.join(ROOT, 'backup', 'original-tw.html'); PW = os.environ.get('TW_PASSWORD')
TOOL = [sys.executable, os.path.join(ROOT, 'tools', 'twmigrate.py')]

class FormatTests(unittest.TestCase):
    def setUp(self): self.k = encfmt.Keys(bytes(range(32)))
    def test_tamper_detected(self):
        blob = bytearray(encfmt.seal_tiddler(self.k, 't', {}, b'hello', 'utf8', 1))
        for pos in (5, 20, len(blob) - 1):
            b = bytearray(blob); b[pos] ^= 1
            with self.assertRaises(Exception): encfmt.open_tiddler(self.k, 't', bytes(b), 1)
    def test_swap_between_titles_rejected(self):
        blob = encfmt.seal_tiddler(self.k, 'a', {}, b'x', 'utf8', 1)
        with self.assertRaises(Exception): encfmt.open_tiddler(self.k, 'b', blob, 1)
    def test_rollback_rev_rejected(self):
        blob = encfmt.seal_tiddler(self.k, 'a', {}, b'x', 'utf8', 1)
        with self.assertRaises(Exception): encfmt.open_tiddler(self.k, 'a', blob, 2)
    def test_wrong_key(self):
        blob = encfmt.seal_tiddler(self.k, 'a', {}, b'x', 'utf8', 1)
        with self.assertRaises(Exception): encfmt.open_tiddler(encfmt.Keys(bytes(32)), 'a', blob, 1)
    def test_padding_buckets(self):
        sizes = {len(encfmt.seal_tiddler(self.k, 't%d' % i, {}, b'x' * n, 'utf8', 1)) for i, n in enumerate((1, 10, 100, 900))}
        self.assertEqual(len(sizes), 1)   # all small notes look identical in size
    def test_ids_depend_on_key_and_do_not_leak(self):
        self.assertNotIn('secret', encfmt.file_path(self.k, 'secret title', 'secret-cat'))
        self.assertNotEqual(encfmt.file_id(self.k, 'a'), encfmt.file_id(encfmt.Keys(bytes(32)), 'a'))
    def test_base64_roundtrip_fallback(self):
        f, body, e = encfmt.split_tiddler({'type': 'image/png', 'text': 'not base64!!'}); self.assertEqual(e, 'utf8')
        raw = os.urandom(100); t = base64.b64encode(raw).decode()
        f, body, e = encfmt.split_tiddler({'type': 'image/png', 'text': t}); self.assertEqual((body, e), (raw, 'base64'))
    def test_nul_and_unicode_titles(self):
        for t in ('a\0b', 'a', 'a\0', '\U0001F600', 'e\u0301', '\u00e9'):
            blob = encfmt.seal_tiddler(self.k, t, {}, b'x', 'utf8', 1)
            self.assertEqual(encfmt.open_tiddler(self.k, t, blob, 1)[0]['title'], t)
        ids = {encfmt.file_id(self.k, t) for t in ('a\0b', 'a', 'a\0', 'b', '', 'e\u0301', '\u00e9')}
        self.assertEqual(len(ids), 7)
        self.assertNotEqual(encfmt.file_id(self.k, 'x'), encfmt.cat_id(self.k, 'x') + '0' * 20)   # label domain separation
        with self.assertRaises(Exception): encfmt.file_id(self.k, 'a\ud800')                     # lone surrogate refused, not aliased
    def test_domain_separated_keys(self):
        self.assertEqual(len({self.k.enc, self.k.id, self.k.man}), 3)
        blob = encfmt.seal_tiddler(self.k, 't', {}, b'x', 'utf8', 1)
        with self.assertRaises(Exception): encfmt.open_manifest(self.k, blob)
    def test_rev_validation(self):
        for r in (-1, 1.0, True, '1', None, 2 ** 53):
            with self.assertRaises(ValueError): encfmt.seal_tiddler(self.k, 't', {}, b'x', 'utf8', r)
    def test_truncated_and_short_blobs(self):
        blob = encfmt.seal_tiddler(self.k, 't', {}, b'x', 'utf8', 1)
        for n in (0, 3, 15, 31, 100, len(blob) - 1):
            with self.assertRaises(Exception): encfmt.open_tiddler(self.k, 't', blob[:n], 1)
        with self.assertRaises(Exception): encfmt.open_tiddler(self.k, 't', blob + b'\0', 1)
    def test_iv_must_be_12_bytes(self):
        with self.assertRaises(ValueError): encfmt.seal_tiddler(self.k, 't', {}, b'x', 'utf8', 1, iv=b'1' * 8)
    def test_fresh_iv_each_seal(self):
        ivs = {encfmt.seal_tiddler(self.k, 't', {}, b'x', 'utf8', 1)[4:16] for _ in range(200)}
        self.assertEqual(len(ivs), 200)
    def _entry(self, **kw): return dict({'c': 'x', 'p': '0123456789ab/' + '0' * 32 + '.bin', 'r': 1, 'h': 'a' * 64, 's': 9, 'f': {}}, **kw)
    def test_manifest_roundtrip_and_padding_strip(self):
        m = {'v': 1, 'counter': 5, 'tiddlers': {'a\0': self._entry()}}
        blob = encfmt.seal_manifest(self.k, m); self.assertEqual(encfmt.open_manifest(self.k, blob), m)
        self.assertEqual(len(blob), 4 + 8 + 12 + 1024 + 16)
    def test_manifest_validation(self):
        good = {'v': 1, 'counter': 5, 'tiddlers': {'a': self._entry()}}
        bad = [dict(good, v=2), dict(good, v=True), dict(good, counter=-1), dict(good, counter=2 ** 53), dict(good, counter=True), dict(good, tiddlers=[]),
               dict(good, tiddlers={'a': self._entry(p='../../etc/x')}), dict(good, tiddlers={'a': self._entry(p='0123456789ab/' + '0' * 32 + '.bin/')}),
               dict(good, tiddlers={'a': self._entry(r=1.5)}), dict(good, tiddlers={'a': self._entry(h='A' * 64)}), dict(good, tiddlers={'a': self._entry(f=[])})]
        for m in bad:
            with self.assertRaises(ValueError): encfmt.seal_manifest(self.k, m)
    def test_manifest_counter_bound_to_header(self):
        blob = bytearray(encfmt.seal_manifest(self.k, {'v': 1, 'counter': 5, 'tiddlers': {}})); blob[11] ^= 1   # header counter edited
        with self.assertRaises(Exception): encfmt.open_manifest(self.k, bytes(blob))
    def test_bom_and_big_text_roundtrip(self):
        f, body, e = encfmt.split_tiddler({'text': '\ufeffhi'}); blob = encfmt.seal_tiddler(self.k, 't', f, body, e, 1)
        self.assertEqual(encfmt.join_tiddler(*encfmt.open_tiddler(self.k, 't', blob, 1))['text'], '\ufeffhi')
        self.assertEqual(len(encfmt.seal_tiddler(self.k, 't', {}, b'x' * 70000, 'utf8', 1)), 4 + 12 + 131072 + 16)
    def test_pad_len(self):
        self.assertEqual([encfmt.pad_len(n) for n in (0, 1, 1024, 1025, 65536, 65537, 131072, 131073)], [1024, 1024, 1024, 2048, 65536, 131072, 131072, 196608])
    def test_sjcl_roundtrip(self):
        b = twlib.sjcl_encrypt(b'{"a":1}', 'pw'); self.assertEqual(twlib.sjcl_decrypt(b, 'pw'), b'{"a":1}')
        with self.assertRaises(ValueError): twlib.sjcl_decrypt(b, 'nope')

@unittest.skipUnless(PW and os.path.exists(SRC), 'needs TW_PASSWORD and backup/original-tw.html')
class MigrateTests(unittest.TestCase):
    def test_migrate_verify_inline(self):
        tmp = tempfile.mkdtemp(); out = os.path.join(tmp, 'out')
        try:
            subprocess.check_call(TOOL + ['migrate', '--repo', 'you/notes', '--src', SRC, '--out', out], stdout=subprocess.DEVNULL)
            subprocess.check_call(TOOL + ['verify', '--src', SRC, '--out', out], stdout=subprocess.DEVNULL)
            classic = os.path.join(tmp, 'classic.html')
            subprocess.check_call(TOOL + ['inline', '--out', out, '--dest', classic], stdout=subprocess.DEVNULL)
            orig = twlib.read_encrypted_store(open(SRC, encoding='utf-8').read(), PW)
            back = twlib.read_encrypted_store(open(classic, encoding='utf-8').read(), PW)
            keep = {t for t, f in orig.items() if not (t.startswith(('$:/state/', '$:/temp/', '$:/status/', '$:/Import', '$:/StoryList', '$:/HistoryList', '$:/isEncrypted', '$:/build')))}
            self.assertEqual({t for t in back if t != '$:/isEncrypted'}, keep)
            for t in keep: self.assertEqual({k: v for k, v in back[t].items()}, {k: v for k, v in orig[t].items()}, 'field mismatch')
            # refuses to overwrite a non-empty output dir
            self.assertNotEqual(subprocess.call(TOOL + ['migrate', '--repo', 'you/notes', '--src', SRC, '--out', out], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), 0)
            # no plaintext user content/titles in any file of out/ (except tw.html which holds public plugins)
            texts = [f.get('text', '') for t, f in orig.items() if not t.startswith('$:/') and len(f.get('text', '')) > 40]
            for d, _, fs in os.walk(out):
                for x in fs:
                    if x == 'tw.html': continue
                    data = open(os.path.join(d, x), 'rb').read()
                    for tx in texts[:30]: self.assertNotIn(tx[:30].encode(), data)
        finally: shutil.rmtree(tmp, ignore_errors=True)

NODE = os.path.join(ROOT, '.venv', 'bin', 'node')

def _synthetic_source(pw, extra=None, iters=1000):
    """Minimal classic encrypted wiki with throw-away content and a throw-away password (never a real one)."""
    tids = {
        '$:/core': {'title': '$:/core', 'plugin-type': 'plugin', 'type': 'application/json', 'text': '{"tiddlers":{}}'},
        '$:/themes/x/y': {'title': '$:/themes/x/y', 'plugin-type': 'theme', 'type': 'application/json', 'text': '{"tiddlers":{}}'},
        'SECRET-TITLE-ALPHA': {'title': 'SECRET-TITLE-ALPHA', 'tags': 'task', 'text': 'SECRET-BODY-ALPHA ' + 'x' * 80},
        'Odd': {'title': 'Odd', 'plugin-type': 'plugin', 'text': 'SECRET-BODY-ODD-PLUGINTYPE ' + 'y' * 80},
        '$:/config/c': {'title': '$:/config/c', 'text': 'v'},
        '$:/StoryList': {'title': '$:/StoryList', 'list': 'Odd'},
    }
    tids.update(extra or {})
    blob = twlib.sjcl_encrypt(json.dumps(tids).encode(), pw, iter=iters)
    return ('<html><head><title>t</title></head><body>\n<!--~~ Ordinary tiddlers ~~-->\n<!--~~ Encrypted tiddlers ~~-->\n'
            + twlib.PRE_OPEN + twlib.render_store_blob(blob) + '</pre>\n<!--~~ Library modules ~~-->\n</body></html>\n')

class SyntheticMigrateTests(unittest.TestCase):
    """Runs the real CLI end to end on a synthetic wiki; needs no secrets."""
    OLD, NEW = 'unit-test-old-pw', 'unit-test-new-pw'
    def run_tool(self, args, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith('TW_')}; e.update(env)
        r = subprocess.run(TOOL + args, env=e, capture_output=True, text=True)
        for pw in (self.OLD, self.NEW): self.assertNotIn(pw, r.stdout + r.stderr)   # passwords never echoed
        return r
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.src = os.path.join(self.tmp, 'o.html')
        open(self.src, 'w', encoding='utf-8').write(_synthetic_source(self.OLD))
        self.out = os.path.join(self.tmp, 'out')
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)
    def stage1(self, d=None): return open(os.path.join(d or self.out, 'tw.html'), encoding='utf-8').read()
    def test_repo_base_migrate_and_restage(self):
        import twmigrate
        r = self.run_tool(['migrate', '--repo', 'you/notes', '--repo-base', 'vault/', '--src', self.src, '--out', self.out, '--kdf-iter', '1200'], TW_PASSWORD=self.OLD)
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg, _ = twmigrate._stage1_bootstrap(self.out, self.OLD); self.assertEqual(cfg.get('repoBase'), 'vault/')
        dest = os.path.join(self.tmp, 'restaged.html')
        r = self.run_tool(['restage', '--out', self.out, '--dest', dest, '--repo-base', '', '--kdf-iter', '1200'], TW_PASSWORD=self.OLD)
        self.assertEqual(r.returncode, 0, r.stderr)
        d2 = os.path.join(self.tmp, 'o2'); os.makedirs(d2); shutil.copy(dest, os.path.join(d2, 'tw.html'))
        cfg2, _ = twmigrate._stage1_bootstrap(d2, self.OLD); self.assertNotIn('repoBase', cfg2)
        r = self.run_tool(['restage', '--out', d2, '--dest', dest, '--repo-base', 'vault', '--kdf-iter', '1200'], TW_PASSWORD=self.OLD)
        self.assertEqual(r.returncode, 0, r.stderr); shutil.copy(dest, os.path.join(d2, 'tw.html'))
        cfg3, _ = twmigrate._stage1_bootstrap(d2, self.OLD); self.assertEqual(cfg3.get('repoBase'), 'vault/')
        self.assertEqual({k: v for k, v in cfg3.items() if k != 'repoBase'}, {k: v for k, v in cfg.items() if k != 'repoBase'})   # nothing else changes
        for bad in ('../', '/abs/', 'a b/', 'vault/../x/'):
            r = self.run_tool(['restage', '--out', d2, '--dest', dest, '--repo-base', bad], TW_PASSWORD=self.OLD)
            self.assertNotEqual(r.returncode, 0, bad)
    def test_only_system_plugins_are_plaintext_and_new_password_and_iter(self):
        r = self.run_tool(['migrate', '--repo', 'you/notes', '--src', self.src, '--out', self.out, '--kdf-iter', '2345'], TW_PASSWORD=self.OLD, TW_NEW_PASSWORD=self.NEW)
        self.assertEqual(r.returncode, 0, r.stderr)
        raw = self.stage1()
        for needle in ('SECRET-TITLE-ALPHA', 'SECRET-BODY-ALPHA', 'SECRET-BODY-ODD-PLUGINTYPE', 'Odd'):
            self.assertNotIn(needle, raw)                        # incl. the user note that merely carries a plugin-type field
        self.assertIn('$:/themes/x/y', raw)
        self.assertIn('WARNING', r.stderr)
        blob = json.loads(__import__('html').unescape(raw[twlib.find_store(raw)[1]:twlib.find_store(raw)[2]].strip()))
        self.assertEqual(blob['iter'], 2345)
        with self.assertRaises(ValueError): twlib.sjcl_decrypt(blob, self.OLD)    # old password must NOT open the new stage-1
        boot = json.loads(twlib.sjcl_decrypt(blob, self.NEW))
        dek = boot['$:/ext/enc/dek']['text']
        self.assertNotIn(dek, raw)
        for dp, _, fs in os.walk(self.out):
            for x in fs:
                if x != 'tw.html': self.assertNotIn(dek.encode(), open(os.path.join(dp, x), 'rb').read())
        # verify with and without --src, and the leak scanner really fails when stage-1 contains note text
        self.assertEqual(self.run_tool(['verify', '--src', self.src, '--out', self.out], TW_PASSWORD=self.OLD, TW_NEW_PASSWORD=self.NEW).returncode, 0)
        self.assertEqual(self.run_tool(['verify', '--out', self.out], TW_NEW_PASSWORD=self.NEW).returncode, 0)
        self.assertNotEqual(self.run_tool(['verify', '--out', self.out], TW_PASSWORD=self.OLD).returncode, 0)
        p = os.path.join(self.out, 'tw.html')
        open(p, 'w', encoding='utf-8').write(raw.replace('<title>t</title>', '<title>SECRET-BODY-ALPHA ' + 'x' * 80 + '</title>'))
        self.assertNotEqual(self.run_tool(['verify', '--src', self.src, '--out', self.out], TW_PASSWORD=self.OLD, TW_NEW_PASSWORD=self.NEW).returncode, 0)
    def test_rotate_changes_dek_and_paths_and_keeps_content(self):
        self.assertEqual(self.run_tool(['migrate', '--repo', 'you/notes', '--src', self.src, '--out', self.out], TW_PASSWORD=self.OLD).returncode, 0)
        out2 = os.path.join(self.tmp, 'out2')
        r = self.run_tool(['rotate', '--out', self.out, '--dest', out2, '--kdf-iter', '1500'], TW_PASSWORD=self.OLD, TW_NEW_PASSWORD=self.NEW)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.run_tool(['verify', '--src', self.src, '--out', out2], TW_PASSWORD=self.OLD, TW_NEW_PASSWORD=self.NEW).returncode, 0)
        sys.path.insert(0, os.path.join(ROOT, 'tools')); import twmigrate
        c1, d1 = twmigrate._stage1_bootstrap(self.out, self.OLD); c2, d2 = twmigrate._stage1_bootstrap(out2, self.NEW)
        self.assertNotEqual(d1, d2); self.assertNotEqual(c1['manifest'], c2['manifest'])
        m1 = encfmt.open_manifest(encfmt.Keys(d1), open(os.path.join(self.out, c1['manifest']), 'rb').read())
        m2 = encfmt.open_manifest(encfmt.Keys(d2), open(os.path.join(out2, c2['manifest']), 'rb').read())
        self.assertEqual(m2['counter'], m1['counter'] + 1); self.assertEqual(set(m1['tiddlers']), set(m2['tiddlers']))
        for t in m1['tiddlers']: self.assertNotEqual(m1['tiddlers'][t]['p'], m2['tiddlers'][t]['p'])
        with self.assertRaises(Exception): encfmt.open_manifest(encfmt.Keys(d1), open(os.path.join(out2, c2['manifest']), 'rb').read())
        self.assertNotEqual(self.run_tool(['rotate', '--out', self.out, '--dest', out2], TW_PASSWORD=self.OLD).returncode, 0)   # refuses non-empty dest
    def test_password_leaves_environment_after_first_read(self):
        code = 'import os,sys; sys.path.insert(0, %r); import twlib; a=twlib.get_password(); assert a=="p1"; assert "TW_PASSWORD" not in os.environ; assert twlib.get_password()=="p1"' % os.path.join(ROOT, 'tools')
        self.assertEqual(subprocess.run([sys.executable, '-c', code], env=dict(os.environ, TW_PASSWORD='p1')).returncode, 0)
    def test_hostile_blob_parameters_rejected(self):
        b = twlib.sjcl_encrypt(b'abc', 'pw', iter=1000)
        for k, v in (('iter', 10**12), ('iter', 0), ('ks', 64), ('ts', 8), ('mode', 'gcm'), ('adata', 'x')):
            with self.assertRaises(ValueError): twlib.sjcl_decrypt(dict(b, **{k: v}), 'pw')

@unittest.skipUnless(os.path.exists(NODE) and os.path.exists(SRC), 'needs node and backup/original-tw.html (for the stock sjcl.js)')
class SjclInteropTests(unittest.TestCase):
    """Our SJCL re-implementation against the real sjcl.js shipped in TiddlyWiki 5.1.21 (the code that will decrypt stage-1)."""
    @classmethod
    def setUpClass(cls):
        import html, re
        m = re.search(r'<script data-tiddler-library="yes" data-tiddler-title="\$:/library/sjcl.js"[^>]*>(.*?)</script>', open(SRC, encoding='utf-8').read(), re.S)
        cls.tmp = tempfile.mkdtemp(); cls.js = os.path.join(cls.tmp, 'sjcl.js'); open(cls.js, 'w').write(html.unescape(m.group(1)))
        cls.drv = os.path.join(cls.tmp, 'drv.js')
        open(cls.drv, 'w').write('global.window=global;const fs=require("fs");eval(fs.readFileSync(process.argv[2],"utf8")+";global.sjcl=sjcl");'
            'const j=JSON.parse(fs.readFileSync(0,"utf8"));let o;'
            'if(j.op==="dec"){o=Buffer.from(sjcl.decrypt(j.pw,JSON.stringify(j.blob)),"binary").toString("base64")}'
            'else{o=JSON.parse(sjcl.encrypt(j.pw,Buffer.from(j.data,"base64").toString("binary"),{iter:j.iter,mode:"ccm"}))}'
            'process.stdout.write(JSON.stringify(o));')
    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.tmp, ignore_errors=True)
    def node(self, **kw): return json.loads(subprocess.run([NODE, self.drv, self.js], input=json.dumps(kw), capture_output=True, text=True, check=True).stdout)
    def test_python_encrypts_sjcl_decrypts(self):
        # sizes straddle the CCM length-of-length boundaries (L=2 up to 65535 bytes, L=3 above); latin-1 safe payload (sjcl treats the text as utf8)
        for n in (0, 1, 15, 16, 65535, 65536, 70000):
            plain = bytes((i * 7) % 90 + 32 for i in range(n))
            blob = twlib.sjcl_encrypt(plain, 'pässwörd ☃', iter=1500)
            self.assertEqual(base64.b64decode(self.node(op='dec', pw='pässwörd ☃', blob=blob)), plain, n)
    def test_sjcl_encrypts_python_decrypts(self):
        for n in (1, 65535, 65536, 70000):
            plain = bytes((i * 11) % 90 + 32 for i in range(n))
            blob = self.node(op='enc', pw='pässwörd ☃', data=base64.b64encode(plain).decode(), iter=1500)
            self.assertEqual((blob['ks'], blob['ts'], blob['mode'], blob['cipher']), (128, 64, 'ccm', 'aes'))
            self.assertEqual(twlib.sjcl_decrypt(blob, 'pässwörd ☃'), plain, n)
    def test_high_iteration_count_is_honoured_by_sjcl(self):
        blob = twlib.sjcl_encrypt(b'hello', 'pw', iter=50000)
        self.assertEqual(base64.b64decode(self.node(op='dec', pw='pw', blob=blob)), b'hello')
        self.assertEqual(list(blob), ['iv', 'v', 'iter', 'ks', 'ts', 'mode', 'adata', 'cipher', 'salt', 'ct'])


@unittest.skipUnless(PW and os.path.exists(SRC), 'needs TW_PASSWORD and backup/original-tw.html')
class RestageTests(unittest.TestCase):
    def test_restage_keeps_files_valid(self):
        tmp = tempfile.mkdtemp(); out = os.path.join(tmp, 'out')
        try:
            subprocess.check_call(TOOL + ['migrate', '--repo', 'you/notes', '--src', SRC, '--out', out], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            before = {os.path.relpath(os.path.join(d, x), out): open(os.path.join(d, x), 'rb').read() for d, _, fs in os.walk(out) for x in fs if x != 'tw.html'}
            subprocess.check_call(TOOL + ['restage', '--out', out, '--dest', os.path.join(tmp, 'new.html')], stdout=subprocess.DEVNULL)
            shutil.copy(os.path.join(tmp, 'new.html'), os.path.join(out, 'tw.html'))
            subprocess.check_call(TOOL + ['verify', '--out', out], stdout=subprocess.DEVNULL)
            after = {os.path.relpath(os.path.join(d, x), out): open(os.path.join(d, x), 'rb').read() for d, _, fs in os.walk(out) for x in fs if x != 'tw.html'}
            self.assertEqual(before, after)
        finally: shutil.rmtree(tmp, ignore_errors=True)
if __name__ == '__main__': unittest.main()
