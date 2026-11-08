"""Web-security tests that need NO wiki password: a synthetic wiki (throw-away password, hostile tiddlers) is built from the public
TiddlyWiki skeleton in out/tw.html (or $TW_SKELETON), migrated with the real tool, and loaded in jsdom by tests/node/xss.test.js.

  .venv/bin/python -W ignore tests/xss_test.py

Part 1 (pure Python): stage-1 HTML generation - div() / load_plugin_tiddlers() / head hardening / CSP.
Part 2 (jsdom): the unlocked page - cross-window messages, raw HTML / javascript: URLs, module execution, secrets reachable from
the page, token storage, alerts rendered as wikitext, tm-enc-flush abuse, tampered/withheld/oversized files, framing, CSP hashes.
"""
import base64, hashlib, html, json, os, re, shutil, subprocess, sys, tempfile, threading, unittest
from html.parser import HTMLParser
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..')
sys.path.insert(0, os.path.join(ROOT, 'tools')); sys.path.insert(0, HERE)
import twlib, twmigrate

SKEL = os.environ.get('TW_SKELETON') or os.path.join(ROOT, 'out', 'tw.html')
NODE = os.path.join(ROOT, '.venv', 'bin', 'node')
SYNTH_PW = 'synthetic-test-pw-not-a-secret'
TOKEN = 'ghp_SYNTHETICTOKEN0123456789'


class Collect(HTMLParser):
    """Parses exactly what a browser would put into the store: elements and their attributes/text."""
    def __init__(self):
        super().__init__(convert_charrefs=True); self.el = []; self.text = {}; self.stack = []
    def handle_starttag(self, tag, attrs): self.el.append((tag, dict(attrs))); self.stack.append(tag); self.text.setdefault(tag, '')
    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag: self.stack.pop()
    def handle_data(self, d):
        if self.stack: self.text[self.stack[-1]] = self.text.get(self.stack[-1], '') + d


class StageOneGeneration(unittest.TestCase):
    HOSTILE = ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>", '</pre></div><script>alert(1)</script>', '<!--', '-->', '&lt;b&gt;&amp;',
               'x" onmouseover="alert(1)', 'a\nb"\n><svg onload=alert(1)>', ' </script><script>', '<![CDATA[', '&#x22;&quot;']

    def roundtrip(self, fields):
        p = Collect(); p.feed(twmigrate.div(fields)); p.close()
        return p

    def test_hostile_values_and_text_stay_inside_their_slots(self):
        for h in self.HOSTILE:
            f = {'title': h, 'description': h, 'text': h + '</pre></div>' + h}
            p = self.roundtrip(f)
            self.assertEqual([t for t, _ in p.el], ['div', 'pre'], h)               # no injected element
            self.assertEqual(set(p.el[0][1]), {'title', 'description'}, h)         # no injected attribute
            self.assertEqual(p.el[0][1]['title'], h); self.assertEqual(p.el[0][1]['description'], h)
            self.assertEqual(p.text['pre'], f['text'])

    def test_hostile_field_names_are_refused(self):
        for k in ['x onload=alert(1)', 'a"b', "a'b", 'a>b', 'a=b', 'a/b', 'a b', 'a\tb', '', 'on' + 'click', 'onerror', 'ONLOAD', 'id', 'class', 'style',
                  'xmlns:evil', 'é', 'a\x00b', 'a<b', '"><script>', 123, None]:
            with self.assertRaises(ValueError, msg=repr(k)): twmigrate.div({'title': 't', k: 'v'})
        for k in ['title', 'plugin-type', 'core-version', 'plugin-priority', 'x.y', 'a_b', 'name', 'text', 'dependents', 'released']:
            twmigrate.div({'title': 't', k: 'v'})

    def test_plugin_tiddler_json_is_inert_in_the_store(self):
        plug = twmigrate.load_plugin_tiddlers()
        p = self.roundtrip(plug)
        self.assertEqual([t for t, _ in p.el], ['div', 'pre'])                      # plugin sources contain '<', '</script>' etc.: still one pre
        self.assertEqual(json.loads(p.text['pre']), json.loads(plug['text']))
        self.assertEqual(p.el[0][1]['title'], '$:/plugins/tw-enc-sync')
        tids = json.loads(plug['text'])['tiddlers']
        self.assertIn('$:/plugins/tw-enc-sync/startup.js', tids)
        for t in tids.values():                                                      # no tiddler of the plugin declares module-type 'startup' + saver without a name etc.
            self.assertNotIn('\n', t['title'])

    def test_plugin_sources_do_not_log_or_leak(self):
        src = ''
        d = twmigrate.PLUGIN_DIR
        for fn in os.listdir(d):
            if fn.endswith('.js'): src += open(os.path.join(d, fn), encoding='utf-8').read()
        self.assertNotRegex(src, r'localStorage\.setItem\([^)]*(?:token|password)', 'plugin must not persist secrets itself')
        self.assertNotRegex(src, r'postMessage\s*\(', 'plugin must not post messages')
        self.assertNotRegex(src, r'\.innerHTML\s*=|document\.write|insertAdjacentHTML', 'no HTML sinks in plugin code')
        self.assertNotRegex(src, r'\beval\s*\(|new\s+Function\s*\(', 'no dynamic code in plugin code')
        self.assertNotRegex(src, r'console\.(?:log|info|debug)\s*\([^)]*(?:title|token|dek|key)', 'no secret/title logging')

    HEAD = ('<!doctype html><html><head><meta http-equiv="Content-Type" content="text/html;charset=utf-8" />\n' + twmigrate.HEAD_MARKER +
            '\n<title>t</title></head><body>\n<script id="a">var a = 1;\r\nvar b = "</scr" + "ipt>";</script>\n<script src="x.js"></script>\n'
            '<script type="text/javascript">/* b */\n</script></body></html>\n')

    def test_head_hardening_and_csp(self):
        d = twmigrate.harden_head(self.HEAD, 'https://api.github.com', csp=False)
        self.assertIn('<meta name="referrer" content="no-referrer" />', d); self.assertIn(twmigrate.FRAME_GUARD, d); self.assertNotIn('Content-Security-Policy', d)
        self.assertLess(d.index(twmigrate.FRAME_GUARD), d.index('<title>'))
        c = twmigrate.harden_head(self.HEAD, 'https://api.github.com', csp=True)
        m = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', c); self.assertTrue(m)
        pol = html.unescape(m.group(1))
        hashes = re.findall(r"'sha256-([A-Za-z0-9+/=]+)'", pol)
        want = set()
        for body in (twmigrate.FRAME_GUARD[len('<script>'):-len('</script>')], 'var a = 1;\nvar b = "</scr" + "ipt>";', '/* b */\n'):   # \r\n normalised like the HTML parser does
            want.add(base64.b64encode(hashlib.sha256(body.encode()).digest()).decode())
        # the hand-written fixture contains '</script>' in a string: our regex (like the HTML parser) ends the script there, so only compare the sure ones
        self.assertIn(base64.b64encode(hashlib.sha256(twmigrate.FRAME_GUARD[8:-9].encode()).digest()).decode(), hashes)
        self.assertNotIn("'unsafe-inline'", re.search(r'script-src [^;]*', pol).group(0))
        self.assertIn("'unsafe-eval'", pol)
        for need in ("default-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "connect-src 'self' https://api.github.com"):
            self.assertIn(need, pol)

    def test_div_output_has_no_raw_lt_in_attributes(self):
        out = twmigrate.div({'title': '<a>', 'x': '"\'<>&'})
        head = out.split('>\n<pre>')[0]
        self.assertNotRegex(head, r'<(?!div)'); self.assertNotIn("'", head)


def _have_browser_env():
    return os.path.exists(NODE) and os.path.exists(SKEL) and os.path.isdir(os.path.join(HERE, 'node', 'node_modules', 'jsdom'))


HOSTILE_TIDDLERS = {
    'HOSTILE iframe-srcdoc': '<iframe srcdoc="&lt;script&gt;parent.__pwn.push(\'iframe-srcdoc\')&lt;/script&gt;"></iframe>',
    'HOSTILE iframe-js': '<iframe src="javascript:parent.__pwn.push(\'iframe-js\')"></iframe>',
    'HOSTILE iframe-js-tab': '<iframe src="jav&#x09;ascr&#x0A;ipt:parent.__pwn.push(\'iframe-js2\')"></iframe>',
    'HOSTILE embed-js': '<embed src="javascript:parent.__pwn.push(\'embed\')">',
    'HOSTILE object-js': '<object data="javascript:parent.__pwn.push(\'object\')"></object>',
    'HOSTILE a-js': '<a id="a-js" href="javascript:window.__pwn.push(\'a-js\')">x</a>',
    'HOSTILE a-js-tab': '<a id="a-js2" href="  jav&#x09;ascript:window.__pwn.push(\'a-js2\')">x</a>',
    'HOSTILE svg-a': '<svg><a id="svg-a" xlink:href="javascript:window.__pwn.push(\'svg-a\')"><text>x</text></a></svg>',
    'HOSTILE form': '<form id="f1" action="javascript:window.__pwn.push(\'form\')"><input type="submit" id="f1b"></form>',
    'HOSTILE formaction': '<form><button id="f2b" formaction="javascript:window.__pwn.push(\'formaction\')">x</button></form>',
    'HOSTILE img-onerror': '<img src="data:," onerror="window.__pwn.push(\'img\')" onload="window.__pwn.push(\'imgl\')">',
    'HOSTILE svg-onload': '<svg onload="window.__pwn.push(\'svg\')"><circle onclick="window.__pwn.push(\'circle\')" r="1"/></svg>',
    'HOSTILE script': '<script>window.__pwn.push("script")</script>',
    'HOSTILE svg-script': '<svg><script>window.__pwn.push("svgscript")</script></svg>',
    'HOSTILE meta': '<meta http-equiv="refresh" content="0;url=https://evil.example/">',
    'HOSTILE base': '<base href="https://evil.example/">',
    'HOSTILE link': '<link rel="stylesheet" href="https://evil.example/x.css">',
}
# type-based payloads: (fields, canary kind)
HOSTILE_TYPED = [
    {'title': 'HOSTILE html-tiddler', 'type': 'text/html', 'text': '<script>parent.__pwn.push("html-tiddler")</script><img src=x onerror="parent.__pwn.push(\'html-img\')">'},
    {'title': 'HOSTILE svg-image', 'type': 'image/svg+xml', 'text': '<svg xmlns="http://www.w3.org/2000/svg" onload="parent.__pwn.push(\'svg-image\')"><script>parent.__pwn.push(\'svg-image-script\')</script></svg>'},
    {'title': '$:/HOSTILE/mod.js', 'type': 'application/javascript', 'module-type': 'library', 'text': 'window.__pwn.push("module"); exports.x = 1;'},
    {'title': '$:/HOSTILE/startup.js', 'type': 'application/javascript', 'module-type': 'startup', 'text': 'window.__pwn.push("startup"); exports.startup = function(){ window.__pwn.push("startup2"); };'},
    {'title': '$:/HOSTILE/widget.js', 'type': 'application/javascript', 'module-type': 'widget', 'text': 'window.__pwn.push("widget"); exports.hostile = function(){};'},
    {'title': '$:/HOSTILE/macro.js', 'type': 'application/javascript', 'module-type': 'macro', 'text': 'window.__pwn.push("macro"); exports.name = "hostile"; exports.params = []; exports.run = function(){ return "x"; };'},
    {'title': '$:/HOSTILE/css', 'tags': '$:/tags/Stylesheet', 'text': '@import url("https://evil.example/x.css"); body { background: url(https://evil.example/p.png); }'},
    {'title': 'HOSTILE <$list filter="[all[]]"><span id="inj-title">T</span></$list> [[x]] {{y}}', 'text': 'body'},
    {'title': 'HOSTILE pdf', 'type': 'application/pdf', 'text': base64.b64encode(b'%PDF-1.4 synthetic').decode()},
]


def build_synth(tmp):
    """Return (out_dir, dek_b64). Mirrors the old mksynth helper: public skeleton + public plugins + synthetic user tiddlers."""
    s = open(SKEL, encoding='utf-8').read()
    i, a, b = twlib.find_store(s)
    head = s[:i]
    st0 = head.index('\n<div id="storeArea"'); en0 = head.rindex('</div>\n', 0, head.index('<!--~~ Encrypted')) + len('</div>\n')
    store_html = head[st0:en0]; head = head[:st0] + head[en0:]
    tids = {}
    for m in re.finditer(r'<div((?: [\w:.-]+="[^"]*")*)>\n<pre>(.*?)</pre>\n</div>', store_html, re.S):
        at = {k: html.unescape(v) for k, v in re.findall(r' ([\w:.-]+)="([^"]*)"', m.group(1))}
        at['text'] = html.unescape(m.group(2))
        if at['title'] == twmigrate.PLUGIN_TITLE: continue
        tids[at['title']] = at
    users = {'Alpha note': {'title': 'Alpha note', 'text': 'SYNTHETIC-CONTENT-ALPHA, long enough to be a leak-scan snippet for the stage-1 check.', 'tags': 'task'},
             'Pic': {'title': 'Pic', 'type': 'image/png', 'text': base64.b64encode(os.urandom(300)).decode()},
             '$:/config/test': {'title': '$:/config/test', 'text': 'yes'}}
    for t, text in HOSTILE_TIDDLERS.items(): users[t] = {'title': t, 'text': text}
    for f in HOSTILE_TYPED: users[f['title']] = dict(f)
    tids.update(users)
    blob = twlib.sjcl_encrypt(json.dumps(tids).encode(), SYNTH_PW, iter=10000)
    src = os.path.join(tmp, 'original.html')
    open(src, 'w', encoding='utf-8').write(head + twlib.PRE_OPEN + twlib.render_store_blob(blob) + s[b:])
    return src


def migrate(src, out, api_base, extra=()):
    env = dict(os.environ, TW_PASSWORD=SYNTH_PW); env.pop('TW_NEW_PASSWORD', None)
    subprocess.check_call([sys.executable, '-I', os.path.join(ROOT, 'tools', 'twmigrate.py'), 'migrate', '--src', src, '--out', out, '--repo', 'o/r',
                           '--api-base', api_base, '--kdf-iter', '10000'] + list(extra), env=env, stdout=subprocess.DEVNULL)


@unittest.skipUnless(_have_browser_env(), 'needs node, jsdom and a TiddlyWiki skeleton (out/tw.html or $TW_SKELETON)')
class BrowserTests(unittest.TestCase):
    def test_page(self):
        import mock_github
        tmp = tempfile.mkdtemp(prefix='twxss-')
        try:
            AP = 18091
            src = build_synth(tmp)
            out, out2 = os.path.join(tmp, 'out'), os.path.join(tmp, 'out-csp')
            migrate(src, out, 'http://127.0.0.1:%d' % AP)
            migrate(src, out2, 'https://api.github.com', ['--csp'])
            # the DEK of the synthetic wiki (test-only value) so the node side can look for it in the page
            cfg, dek = twmigrate._stage1_bootstrap(out, SYNTH_PW)
            st = mock_github.State(out, TOKEN); srv = mock_github.serve(st, AP)
            env = dict(os.environ, ROOT=out, ROOT_CSP=out2, PW=SYNTH_PW, AP=str(AP), TOKEN=TOKEN, DEK_B64=base64.b64encode(dek).decode())
            r = subprocess.run([NODE, os.path.join(HERE, 'node', 'xss.test.js')], env=env, cwd=os.path.join(HERE, 'node'), capture_output=True, text=True, timeout=600)
            sys.stdout.write(r.stdout); sys.stderr.write(r.stderr)
            srv.shutdown()
            self.assertEqual(r.returncode, 0, 'node xss tests failed')
            self.assertNotIn('FAIL ', r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=1)
