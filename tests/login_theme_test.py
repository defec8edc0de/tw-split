import os, re, sys, unittest, base64, hashlib
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..'); sys.path.insert(0, os.path.join(ROOT, 'tools'))
import twmigrate as m
SRC = os.environ.get('TW_SOURCE') or os.path.join(ROOT, 'backup', 'original-tw.html')

@unittest.skipUnless(os.path.exists(SRC), 'needs backup/original-tw.html skeleton')
class LoginTheme(unittest.TestCase):
    def setUp(self):
        s = open(SRC, encoding='utf-8').read()
        self.doc = s[:s.index('<pre id="encryptedStoreArea"')]   # skeleton head only (public part)
    def test_idempotent_and_removable(self):
        a = m.apply_login_theme(self.doc); b = m.apply_login_theme(a)
        self.assertEqual(a, b); self.assertEqual(a.count('id="tw-login-fx"'), 1)
        self.assertEqual(m.apply_login_theme(a, enabled=False), self.doc)
    def test_inside_style_area_and_scoped(self):
        a = m.apply_login_theme(self.doc)
        self.assertLess(a.index('id="styleArea"'), a.index('id="tw-login-theme"'))
        self.assertLess(a.index('id="tw-login-fx"'), a.index('<!--~~ Static content'))
        css = open(os.path.join(ROOT, 'tools', 'login-theme.css'), encoding='utf-8').read()
        css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
        def selectors(text, depth_in_at=False):
            i = 0
            while i < len(text):
                j = text.find('{', i)
                if j < 0: break
                head = text[i:j].strip(); depth = 1; k = j + 1
                while depth and k < len(text):
                    depth += (text[k] == '{') - (text[k] == '}'); k += 1
                body = text[j + 1:k - 1]
                if head.startswith('@keyframes'): pass
                elif head.startswith('@media'): yield from selectors(body, True)
                else: yield head
                i = k
        n = 0
        for head in selectors(css):
            for sel in head.split(','):
                self.assertRegex(sel.strip(), r'^html\.tw-(login|working|deny)', sel); n += 1
        self.assertGreater(n, 20)
    def test_no_network_or_eval(self):
        for f in ('login-theme.css', 'login-theme.js'):
            t = open(os.path.join(ROOT, 'tools', f), encoding='utf-8').read()
            self.assertNotRegex(t, r'https?://|url\(|@import|eval\(|new Function|innerHTML|XMLHttpRequest|fetch\(')
    def test_csp_covers_theme_script_and_refresh(self):
        a = m.harden_head(m.apply_login_theme(self.doc), 'https://api.github.com', True)
        js = open(os.path.join(ROOT, 'tools', 'login-theme.js'), encoding='utf-8').read()
        h = "'sha256-%s'" % base64.b64encode(hashlib.sha256(('\n' + js).encode()).digest()).decode()
        h = h.strip("'"); self.assertIn(h, a)
        r = m.refresh_csp(m.apply_login_theme(a, enabled=False), 'https://api.github.com')   # theme removed -> hash must disappear
        self.assertNotIn(h, r); self.assertEqual(r.count('Content-Security-Policy'), 1)
if __name__ == '__main__': unittest.main()
