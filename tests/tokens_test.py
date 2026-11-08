"""The vault's Cyber palette must match the website's design tokens (single source: the site's data/tokens.yaml, `noir` set).
Set SITE_TOKENS=/path/to/site/data/tokens.yaml; skipped when the file is not found. No YAML library needed (flat key: "value" lines)."""
import os, re, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..')
CANDIDATES = [os.environ.get('SITE_TOKENS') or '', os.path.join(ROOT, '..', 'defec8edc0de.github.io', 'data', 'tokens.yaml'),
              os.path.join(ROOT, '..', 'defec8edc0de.github.io-next', 'data', 'tokens.yaml')]
TOKENS = next((p for p in CANDIDATES if p and os.path.exists(p)), None)
# palette key in $:/palettes/tw-split/Cyber  ->  token in the site's `noir` set
MAP = {'background': 'bg', 'page-background': 'bg', 'foreground': 'text', 'muted-foreground': 'muted',
       'primary': 'cyan', 'blockquote-bar': 'cyan', 'alert-border': 'accent', 'dirty-indicator': 'accent'}

def noir_tokens(path):
    out, inside = {}, False
    for line in open(path, encoding='utf-8'):
        if re.match(r'^\S', line):
            inside = line.startswith('noir:')
            continue
        m = re.match(r'^\s+([\w-]+):\s*"?([^"#\n]*?(?:#[0-9A-Fa-f]{3,8})?[^"\n]*?)"?\s*(?:#.*)?$', line)
        if inside and m: out[m.group(1)] = m.group(2).strip()
    return out

def palette():
    s = open(os.path.join(ROOT, 'plugin', 'src', 'palette-cyber.tid'), encoding='utf-8').read().split('\n\n', 1)[1]
    return {k.strip(): v.strip() for k, _, v in (l.partition(':') for l in s.splitlines()) if v.strip()}

@unittest.skipUnless(TOKENS, 'site data/tokens.yaml not found (set SITE_TOKENS)')
class TokenSync(unittest.TestCase):
    def test_palette_matches_site_tokens(self):
        t, p = noir_tokens(TOKENS), palette()
        for pk, tk in MAP.items():
            self.assertIn(tk, t, 'token %s missing in %s' % (tk, TOKENS))
            self.assertEqual(p.get(pk, '').lower(), t[tk].lower(), 'palette %s != site token noir.%s' % (pk, tk))
    def test_theme_uses_site_fonts(self):
        css = open(os.path.join(ROOT, 'plugin', 'src', 'theme-cyber.css.tid'), encoding='utf-8').read()
        self.assertIn('"Atkinson Hyperlegible Next"', css); self.assertIn('"JetBrains Mono"', css)
        self.assertIn('/fonts/atkinson-hyperlegible-next-latin-wght-normal.woff2', css)

if __name__ == '__main__':
    print('tokens:', TOKENS); unittest.main(verbosity=1)
