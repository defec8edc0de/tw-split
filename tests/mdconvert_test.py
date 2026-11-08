"""WikiText -> Markdown converter tests (no wiki password, no network).

  .venv/bin/python -W ignore tests/mdconvert_test.py

1. tests/node/mdconvert.test.js: pure-Node tests of plugin/src/md-convert.js (rule table, review cases, idempotence, hostile input).
2. tests/node/mdrender.test.js: a throw-away wiki (public TiddlyWiki skeleton + the tw5-markdown plugin from out/tw.html or $TW_SKELETON + the
   md-convert files, no encryption) is loaded in jsdom; WikiText and converted Markdown are rendered with the REAL parsers and compared;
   the Control Panel tab, the messages (scan / convert / revert / drop backups), lazy-loaded stubs and hostile titles are exercised.
"""
import json, os, re, subprocess, sys, tempfile, shutil
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, '..')
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import twmigrate
NODE = os.path.join(ROOT, '.venv', 'bin', 'node')
SKEL = os.environ.get('TW_SKELETON') or os.path.join(ROOT, 'out', 'tw.html')

def build_wiki(dest):
    s = open(SKEL, encoding='utf-8').read()
    i = s.index('<div id="storeArea"'); e = s.index('<!--~~ Encrypted tiddlers ~~-->'); e2 = s.index('<!--~~ Library modules ~~-->')
    store = s[i:e]
    m = re.search(r'<div title="\$:/plugins/tw-enc-sync" .*?</pre>\n</div>\n', store, re.S)
    if m: store = store[:m.start()] + store[m.end():]          # our sync plugin needs the encrypted bootstrap; only the md files are added below
    plug = json.loads(twmigrate.load_plugin_tiddlers()['text'])['tiddlers']
    mine = [t for k, t in plug.items() if '/md-convert' in k]
    assert len(mine) == 3, [t['title'] for t in mine]
    k = store.rindex('</div>')
    store = store[:k] + ''.join(twmigrate.div(t) for t in mine) + store[k:]
    open(dest, 'w', encoding='utf-8').write(s[:i] + store + '\n' + s[e2:])

def run(args, env=None):
    return subprocess.call([NODE] + args, cwd=os.path.join(HERE, 'node'), env=env)

if __name__ == '__main__':
    env = {k: v for k, v in os.environ.items() if k != 'TW_PASSWORD'}
    rc = run([os.path.join(HERE, 'node', 'mdconvert.test.js')], env)
    rc2 = 0
    if os.path.exists(SKEL) and os.path.isdir(os.path.join(HERE, 'node', 'node_modules', 'jsdom')):
        tmp = tempfile.mkdtemp(prefix='twmd-')
        try:
            dest = os.path.join(tmp, 'wiki.html'); build_wiki(dest)
            rc2 = run([os.path.join(HERE, 'node', 'mdrender.test.js')], dict(env, WIKI=dest))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        print('SKIP rendering tests (needs jsdom and a TiddlyWiki skeleton: out/tw.html or $TW_SKELETON)')
    sys.exit(rc or rc2)
