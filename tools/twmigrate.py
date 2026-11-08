#!/usr/bin/env python3
"""twmigrate - split a whole-wiki-encrypted TiddlyWiki (5.1.x) into a small stage-1 HTML + one encrypted file per tiddler.

Usage (passwords only via env, never argv/files; nothing is written to the Pages repo - you copy `out/` yourself):
  TW_PASSWORD=... twmigrate.py inspect  --src original.html
  TW_PASSWORD=... [TW_NEW_PASSWORD=...] twmigrate.py migrate --src original.html --out out/ [--branch master] [--repo owner/name] [--category-order a,b,c] [--kdf-iter N]
  TW_PASSWORD=... [TW_NEW_PASSWORD=...] twmigrate.py verify  [--src original.html] --out out/
  [TW_NEW_PASSWORD|TW_PASSWORD]=... twmigrate.py inline --out out/ --dest classic.html     (rollback: rebuild classic encrypted single file)
  [TW_PASSWORD=<current stage-1 password>] [TW_NEW_PASSWORD=<new>] twmigrate.py rotate --out out/ --dest out2/ [--kdf-iter N]
      (new random DEK + re-encrypt every file + new stage-1 blob; optionally a new password)

TW_PASSWORD     = password of the ORIGINAL wiki (migrate/inspect/verify --src) and, if TW_NEW_PASSWORD is unset, of the stage-1 blob.
TW_NEW_PASSWORD = password protecting the NEW stage-1 blob (and thereby the DEK). Use a strong, never-before-published passphrase here:
                  the old password stays exposed through the old ciphertext in git history.
The variables are removed from this process's environment as soon as they are read.
"""
import argparse, base64, collections, hashlib, html, json, os, re, shutil, subprocess, sys
from urllib.parse import urlsplit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twlib, encfmt
from Crypto.Random import get_random_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(HERE, '..', 'plugin', 'src')
PLUGIN_TITLE = '$:/plugins/tw-enc-sync'
DEFAULT_KDF_ITER = 300000   # stage-1 blob only; TiddlyWiki's decryptor reads `iter` from the blob (stock = 10000). ~1.3 s in a browser.
DROP_PREFIXES = ('$:/state/', '$:/temp/', '$:/status/', '$:/Import', '$:/StoryList', '$:/HistoryList',
                 '$:/isEncrypted', '$:/build', '$:/UpgradeLibrary')
BOOT_CFG, BOOT_DEK = '$:/ext/enc/config', '$:/ext/enc/dek'

def parse_tags(s):
    out = []
    for m in re.finditer(r'\[\[(.*?)\]\]|(\S+)', s or ''):
        out.append(m.group(1) if m.group(1) is not None else m.group(2))
    return out

def category_of(title, f, order):
    if title.startswith('$:/'): return 'sys'
    tags = parse_tags(f.get('tags', ''))
    for t in order:
        if t in tags: return t
    if tags: return tags[0]
    return 'media' if f.get('type') in encfmt.BASE64_TYPES else 'misc'

def is_plugin(title, f):
    """Plugins/themes/languages go PLAINTEXT into stage-1. Only system-titled tiddlers qualify: a user note that
    merely carries a plugin-type field must stay encrypted (title/text would otherwise be published)."""
    return bool(f.get('plugin-type')) and title.startswith('$:/') and title != '$:/temp/info-plugin'
def stage1_password():
    return twlib.get_password('TW_NEW_PASSWORD', required=False) or twlib.get_password()
def is_dropped(title): return title.startswith(DROP_PREFIXES) or title == '$:/temp/info-plugin'

# A field name becomes an HTML ATTRIBUTE NAME of the store <div>, and is not escaped. Only plain names are accepted: anything else
# (space, quote, '>', '=', '/') would let a hostile source tiddler break out of the tag and inject markup/script into the PUBLIC stage-1 page.
# 'on*' (event handlers) and id/class/style (DOM clobbering of storeArea/encryptedStoreArea, CSS) are refused as well.
FIELD_NAME_RE = re.compile(r'^[A-Za-z0-9_.:-]+$')
RESERVED_FIELDS = ('id', 'class', 'style', 'slot', 'is')
def check_field_name(k):
    if not isinstance(k, str) or not FIELD_NAME_RE.match(k) or k.lower().startswith('on') or k.lower() in RESERVED_FIELDS or k.lower().startswith('xmlns'):
        raise ValueError('refusing to write tiddler field name %r into the stage-1 HTML (not a plain attribute name)' % (k if isinstance(k, str) else type(k).__name__))
    return k

def div(fields):
    attrs = ''.join(' %s="%s"' % (check_field_name(k), html.escape(str(v), quote=True)) for k, v in fields.items() if k != 'text')
    return '<div%s>\n<pre>%s</pre>\n</div>\n' % (attrs, html.escape(fields.get('text', ''), quote=False))

def load_plugin_tiddlers():
    """Pack plugin/src into one plugin tiddler (shadow tiddlers)."""
    tids = {}
    for fn in sorted(os.listdir(PLUGIN_DIR)):
        p = os.path.join(PLUGIN_DIR, fn)
        if fn == 'plugin.info': continue
        raw = open(p, encoding='utf-8').read()
        if fn.endswith('.js'):
            m = re.match(r'/\*\\\n(.*?)\n\\\*/\n?', raw, re.S)
            hdr, text = m.group(1), raw   # keep the header comment in the module text (as TW does)
        elif fn.endswith('.tid'):
            hdr, _, text = raw.partition('\n\n')
        else:
            continue
        f = {}
        for line in hdr.split('\n'):
            k, _, v = line.partition(':')
            if v: f[k.strip()] = v.strip()
        f['text'] = text
        tids[f['title']] = f
    info = json.load(open(os.path.join(PLUGIN_DIR, 'plugin.info')))
    info['title'] = PLUGIN_TITLE; info['plugin-type'] = 'plugin'; info['type'] = 'application/json'
    info['text'] = json.dumps({'tiddlers': tids}, ensure_ascii=False)
    return info

HEAD_MARKER = '<!--~~ Raw markup for the top of the head section ~~-->'
# Runs before the TiddlyWiki boot code and therefore before the password prompt: a page that frames the wiki can neither show the prompt
# in a UI-redress overlay nor talk to the booted page. (Header-based framing protection is impossible on GitHub Pages.)
FRAME_GUARD = '<script>if(window.top!==window.self){try{window.stop()}catch(e){}document.documentElement.style.display="none"}</script>'

def csp_policy(doc, api_base):
    """Opt-in Content-Security-Policy (meta). Inline scripts are allowed by hash only (event-handler attributes and javascript: URLs are
    therefore dead), connections only to this site and the API origin. 'unsafe-eval' stays: TiddlyWiki executes its JS modules via eval()."""
    hashes = []
    for m in re.finditer(r'<script\b([^>]*)>(.*?)</script>', doc, re.S | re.I):
        if re.search(r'\bsrc\s*=', m.group(1), re.I): continue
        body = m.group(2).replace('\r\n', '\n').replace('\r', '\n')   # the HTML parser normalises newlines before the browser hashes
        h = "'sha256-%s'" % base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode()
        if h not in hashes: hashes.append(h)
    u = urlsplit(api_base)
    api = '%s://%s' % (u.scheme, u.netloc)
    return ("default-src 'none'; script-src %s 'unsafe-eval'; style-src 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; "
            "font-src 'self' data:; connect-src 'self' %s; frame-src data: blob:; object-src 'none'; base-uri 'none'; form-action 'none'") % (' '.join(hashes), api)

def harden_head(doc, api_base, csp=False):
    """referrer policy + frame guard (always); CSP (--csp). The CSP hashes are computed over the final document."""
    def put(d, text):   # right after the head marker (TiddlyWiki skeleton), else right after <head>
        if HEAD_MARKER in d: return d.replace(HEAD_MARKER, HEAD_MARKER + '\n' + text, 1)
        m = re.search(r'<head[^>]*>', d, re.I)
        if not m: sys.exit('unexpected HTML skeleton: no <head> to harden')
        return d[:m.end()] + '\n' + text + d[m.end():]
    doc = put(doc, '<meta name="referrer" content="no-referrer" />\n' + FRAME_GUARD)
    if csp: doc = put(doc, '<meta http-equiv="Content-Security-Policy" content="%s" />' % html.escape(csp_policy(doc, api_base), quote=True))
    return doc

LOGIN_BEGIN, LOGIN_END = '<!--tw-login-theme-->', '<!--/tw-login-theme-->'
STATIC_MARK = '<!--~~ Static content for Google and browsers without JavaScript ~~-->'

def apply_login_theme(doc, enabled=True):
    """Insert (or replace/remove) the cyberpunk login screen: <style> + <script>, at the end of #styleArea. Idempotent (marker comments)."""
    i = doc.find(LOGIN_BEGIN)
    if i >= 0:
        j = doc.find(LOGIN_END, i)
        if j < 0: sys.exit('corrupt login-theme markers in stage-1')
        k2 = j + len(LOGIN_END)
        if doc[k2:k2 + 1] == '\n': k2 += 1   # the newline that followed the block
        doc = doc[:i] + doc[k2:]
    if not enabled: return doc
    css = open(os.path.join(HERE, 'login-theme.css'), encoding='utf-8').read()
    js = open(os.path.join(HERE, 'login-theme.js'), encoding='utf-8').read()
    if '</style' in css.lower() or '</script' in js.lower(): sys.exit('login theme contains a closing tag')
    k = doc.find(STATIC_MARK)
    close = doc.rfind('</div>', 0, k) if k >= 0 else -1
    if close < 0 or 'id="styleArea"' not in doc[:close]:   # cosmetic feature: never block a migration on an unusual skeleton
        print('WARNING: unusual HTML skeleton, login theme skipped', file=sys.stderr); return doc
    block = '%s\n<style id="tw-login-theme" type="text/css">\n%s</style>\n<script id="tw-login-fx">\n%s</script>\n%s\n' % (LOGIN_BEGIN, css, js, LOGIN_END)
    return doc[:close] + block + doc[close:]

CSP_META_RE = re.compile(r'<meta http-equiv="Content-Security-Policy" content="[^"]*" />\n?')

def refresh_csp(doc, api_base):
    """If the stage-1 carries a CSP (migrate --csp), recompute its script hashes after the document changed."""
    if not CSP_META_RE.search(doc): return doc
    doc = CSP_META_RE.sub('', doc, count=1)
    return harden_csp_only(doc, api_base)

def harden_csp_only(doc, api_base):
    meta = '<meta http-equiv="Content-Security-Policy" content="%s" />' % html.escape(csp_policy(doc, api_base), quote=True)
    if HEAD_MARKER in doc: return doc.replace(HEAD_MARKER, HEAD_MARKER + '\n' + meta, 1)
    m = re.search(r'<head[^>]*>', doc, re.I)
    return doc[:m.end()] + '\n' + meta + doc[m.end():]

def check_repo_base(v):
    """Folder of tw.html inside the repository, e.g. 'vault/' ('' = repository root)."""
    v = v if v.endswith('/') else v + '/'
    if not re.fullmatch(r'(?:[A-Za-z0-9_-]+/)+', v): sys.exit('--repo-base must look like "vault/" (letters, digits, _ and -)')
    return v

def detect_repo_branch(args):
    repo = args.repo; branch = args.branch
    if not repo or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        sys.exit('--repo OWNER/REPO is required (the GitHub Pages repository that will hold the encrypted files)')
    return repo, branch

def cmd_inspect(a):
    j = twlib.read_encrypted_store(open(a.src, encoding='utf-8').read(), twlib.get_password())
    c = collections.Counter(); sz = collections.Counter()
    for t, f in j.items():
        k = 'plugin' if is_plugin(t, f) else 'dropped' if is_dropped(t) else 'external'
        c[k] += 1; sz[k] += len(f.get('text', ''))
    for k in c: print('%-9s %4d tiddlers %9d bytes' % (k, c[k], sz[k]))

def cmd_migrate(a):
    detect_repo_branch(a)
    pw = twlib.get_password()
    new_pw = twlib.get_password('TW_NEW_PASSWORD', required=False) or pw
    if new_pw == pw:
        print('NOTE: the stage-1 blob (which holds the key to everything) uses the SAME password as the old wiki, whose ciphertext '
              'is already public. Prefer a fresh strong passphrase via TW_NEW_PASSWORD.', file=sys.stderr)
    s = open(a.src, encoding='utf-8').read()
    j = twlib.read_encrypted_store(s, pw)
    dek = get_random_bytes(32); keys = encfmt.Keys(dek)
    order = [x for x in (a.category_order or '').split(',') if x]
    out = os.path.abspath(a.out)
    if os.path.exists(out) and os.listdir(out): sys.exit('refusing to write into non-empty %s' % out)
    os.makedirs(out, exist_ok=True)
    manifest = {'v': 1, 'counter': 1, 'tiddlers': {}}
    plugins = {}; dropped = 0; total = 0; odd = 0
    for title, f in j.items():
        if is_plugin(title, f): plugins[title] = f; continue
        if f.get('plugin-type') and not is_dropped(title): odd += 1   # kept encrypted, see is_plugin()
        if is_dropped(title): dropped += 1; continue
        cat = category_of(title, f, order)
        sf, body, e = encfmt.split_tiddler(f)
        blob = encfmt.seal_tiddler(keys, title, sf, body, e, 1)
        path = encfmt.file_path(keys, title, cat)
        os.makedirs(os.path.join(out, os.path.dirname(path)), exist_ok=True)
        open(os.path.join(out, path), 'wb').write(blob)
        manifest['tiddlers'][title] = {'c': cat, 'p': path, 'r': 1, 'h': encfmt.sha256_hex(blob), 's': len(blob), 'f': sf}
        total += 1
    mpath = encfmt.manifest_path(keys)
    os.makedirs(os.path.join(out, 'm'), exist_ok=True)
    open(os.path.join(out, mpath), 'wb').write(encfmt.seal_manifest(keys, manifest))
    # stage-1 html
    plugin = load_plugin_tiddlers()
    store = '<div id="storeArea" style="display:none;">\n' + ''.join(div(dict(f)) for f in plugins.values()) + div(plugin) + '</div>\n'
    cfg = {'v': 1, 'repo': a.repo, 'branch': a.branch, 'apiBase': a.api_base, 'base': a.base, 'manifest': mpath}
    if a.repo_base: cfg['repoBase'] = check_repo_base(a.repo_base)
    boot = {BOOT_CFG: {'title': BOOT_CFG, 'text': json.dumps(cfg)},
            BOOT_DEK: {'title': BOOT_DEK, 'text': base64.b64encode(dek).decode()}}
    blob = twlib.sjcl_encrypt(json.dumps(boot).encode('utf-8'), new_pw, iter=a.kdf_iter)
    i, a0, b0 = twlib.find_store(s)
    marker = '<!--~~ Ordinary tiddlers ~~-->'
    head = s[:i]
    if marker not in head: sys.exit('unexpected HTML skeleton: "Ordinary tiddlers" marker not found')
    head = head.replace(marker, marker + '\n' + store, 1)
    doc = apply_login_theme(head + twlib.PRE_OPEN + twlib.render_store_blob(blob) + s[b0:], not a.no_login_theme)
    doc = harden_head(doc, a.api_base, a.csp)
    open(os.path.join(out, 'tw.html'), 'w', encoding='utf-8').write(doc)
    print('external tiddlers: %d, plugins kept in stage-1: %d, dropped state/temp: %d' % (total, len(plugins), dropped))
    print('PLAINTEXT in stage-1 (public by design): ' + ', '.join(sorted(plugins)))
    if odd: print('WARNING: %d non-system tiddler(s) carry a plugin-type field; they were kept ENCRYPTED (not treated as plugins)' % odd, file=sys.stderr)
    print('stage-1 size: %d bytes (original %d)' % (os.path.getsize(os.path.join(out, 'tw.html')), len(s.encode())))

def _stage1_bootstrap(out, pw):
    s = open(os.path.join(out, 'tw.html'), encoding='utf-8').read()
    boot = twlib.read_encrypted_store(s, pw)
    return json.loads(boot[BOOT_CFG]['text']), base64.b64decode(boot[BOOT_DEK]['text'])

def cmd_restage(a):
    """Rebuild ONLY tw.html with the current plugin code (and optionally a new password); DEK, manifest and all .bin files stay valid."""
    if not a.dest: sys.exit('--dest (output tw.html path) is required')
    cands = [x for x in (twlib.get_password('TW_PASSWORD', required=False), twlib.get_password('TW_NEW_PASSWORD', required=False)) if x]
    pw = None
    for c in cands:   # whichever one the current stage-1 blob was encrypted with
        try: cfg, dek = _stage1_bootstrap(a.out, c); pw = c; break
        except ValueError: continue
    if pw is None: sys.exit('could not decrypt the current stage-1 with TW_PASSWORD / TW_NEW_PASSWORD')
    new_pw = twlib.get_password('TW_NEW_PASSWORD', required=False) or pw
    if a.repo_base is not None:
        cfg = dict(cfg)
        if a.repo_base: cfg['repoBase'] = check_repo_base(a.repo_base)
        else: cfg.pop('repoBase', None)
        print('repoBase set to %r (GitHub paths now start with it)' % cfg.get('repoBase', ''))
    s = open(os.path.join(a.out, 'tw.html'), encoding='utf-8').read()
    start = s.find('<div title="%s"' % PLUGIN_TITLE)
    if start < 0: sys.exit('plugin tiddler not found in stage-1 (unexpected layout)')
    end = s.find('</pre>\n</div>\n', start)
    if end < 0: sys.exit('unterminated plugin tiddler in stage-1')
    end += len('</pre>\n</div>\n')
    s = s[:start] + div(load_plugin_tiddlers()) + s[end:]
    boot = {BOOT_CFG: {'title': BOOT_CFG, 'text': json.dumps(cfg)},
            BOOT_DEK: {'title': BOOT_DEK, 'text': base64.b64encode(dek).decode()}}
    blob = twlib.sjcl_encrypt(json.dumps(boot).encode('utf-8'), new_pw, iter=a.kdf_iter)
    i, a0, b0 = twlib.find_store(s)
    doc = apply_login_theme(s[:i] + twlib.PRE_OPEN + twlib.render_store_blob(blob) + s[b0:], not a.no_login_theme)
    doc = refresh_csp(doc, cfg['apiBase'])
    open(a.dest, 'w', encoding='utf-8').write(doc)
    print('restaged stage-1 -> %s (keys and encrypted files unchanged%s)' % (a.dest, '; NEW password' if new_pw != pw else ''))

def cmd_verify(a):
    spw = stage1_password()
    j = twlib.read_encrypted_store(open(a.src, encoding='utf-8').read(), twlib.get_password()) if a.src else None
    cfg, dek = _stage1_bootstrap(a.out, spw); keys = encfmt.Keys(dek)
    man = encfmt.open_manifest(keys, open(os.path.join(a.out, cfg['manifest']), 'rb').read())
    bad = 0; n = 0
    for title, e in man['tiddlers'].items():          # every manifest entry: hash + AEAD + (with --src) field equality
        blob = open(os.path.join(a.out, e['p']), 'rb').read()
        if encfmt.sha256_hex(blob) != e['h']: print('HASH MISMATCH'); bad += 1; continue
        fields, body, enc = encfmt.open_tiddler(keys, title, blob, e['r'])
        if j is not None and title in j and encfmt.join_tiddler(fields, body, enc) != j[title]: print('FIELD MISMATCH for one tiddler'); bad += 1
        n += 1
    expect = {t for t, f in j.items() if not is_plugin(t, f) and not is_dropped(t)} if j is not None else set(man['tiddlers'])
    missing = expect - set(man['tiddlers']); extra = set(man['tiddlers']) - expect
    if missing: print('MISSING in manifest: %d' % len(missing)); bad += len(missing)
    files = {os.path.relpath(os.path.join(d, x), a.out) for d, _, fs in os.walk(a.out) for x in fs}
    expected = {e['p'] for e in man['tiddlers'].values()} | {cfg['manifest'], 'tw.html'}
    print('verified %d tiddlers, mismatches: %d, extra manifest entries: %d, stray files: %d' % (n, bad, len(extra), len(files - expected)))
    leaks = 0
    if j is not None:
        # leak check 1: no tiddler title / tag word in any file name
        names = ' '.join(files).lower()
        for t, f in j.items():
            if is_plugin(t, f) or is_dropped(t): continue
            w = t.lower()
            if len(w) > 3 and w in names: leaks += 1
        # leak check 2: stage-1 (public) must not contain user note text, nor the DEK
        raw = open(os.path.join(a.out, 'tw.html'), encoding='utf-8').read()
        for t, f in j.items():
            if is_plugin(t, f) or is_dropped(t) or t.startswith('$:/'): continue   # system tiddlers often equal public skeleton/theme text
            tx = f.get('text', '')
            for snip in {tx[:60], tx[-60:]}:
                if len(snip.strip()) >= 40 and (snip in raw or html.escape(snip, quote=True) in raw or html.escape(snip, quote=False) in raw
                                                 or json.dumps(snip)[1:-1] in raw): leaks += 1; break
        if base64.b64encode(dek).decode() in raw: leaks += 1
        tl = sum(1 for t, f in j.items() if not (is_plugin(t, f) or is_dropped(t)) and len(t) >= 12 and (t in raw or html.escape(t) in raw))
        if tl: print('WARNING: %d tiddler title(s) of 12+ chars also occur in stage-1 text (probably coincidence with plugin docs)' % tl)
    print('filename/stage-1 leaks:', leaks)
    sys.exit(1 if bad or extra or leaks or (files - expected) else 0)

def cmd_rotate(a):
    """New random DEK + every file re-sealed + new stage-1 blob (optionally a new password). Writes a NEW directory."""
    old_pw = twlib.get_password(); new_pw = twlib.get_password('TW_NEW_PASSWORD', required=False) or old_pw
    cfg, dek = _stage1_bootstrap(a.out, old_pw); keys = encfmt.Keys(dek)
    man = encfmt.open_manifest(keys, open(os.path.join(a.out, cfg['manifest']), 'rb').read())
    dest = os.path.abspath(a.dest)
    if os.path.exists(dest) and os.listdir(dest): sys.exit('refusing to write into non-empty %s' % dest)
    os.makedirs(os.path.join(dest, 'm'), exist_ok=True)
    ndek = get_random_bytes(32); nk = encfmt.Keys(ndek)
    nman = {'v': 1, 'counter': man['counter'] + 1, 'tiddlers': {}}   # counter keeps increasing: clients warn on decreases
    for title, e in man['tiddlers'].items():
        blob = open(os.path.join(a.out, e['p']), 'rb').read()
        if encfmt.sha256_hex(blob) != e['h']: sys.exit('hash mismatch in source; refusing to rotate')
        fields, body, enc = encfmt.open_tiddler(keys, title, blob, e['r'])
        nb = encfmt.seal_tiddler(nk, title, fields, body, enc, 1)
        path = encfmt.file_path(nk, title, e['c'])
        os.makedirs(os.path.join(dest, os.path.dirname(path)), exist_ok=True)
        open(os.path.join(dest, path), 'wb').write(nb)
        nman['tiddlers'][title] = {'c': e['c'], 'p': path, 'r': 1, 'h': encfmt.sha256_hex(nb), 's': len(nb), 'f': e['f']}
    mpath = encfmt.manifest_path(nk)
    open(os.path.join(dest, mpath), 'wb').write(encfmt.seal_manifest(nk, nman))
    s = open(os.path.join(a.out, 'tw.html'), encoding='utf-8').read()
    ncfg = dict(cfg, manifest=mpath)
    boot = {BOOT_CFG: {'title': BOOT_CFG, 'text': json.dumps(ncfg)}, BOOT_DEK: {'title': BOOT_DEK, 'text': base64.b64encode(ndek).decode()}}
    blob = twlib.sjcl_encrypt(json.dumps(boot).encode('utf-8'), new_pw, iter=a.kdf_iter)
    i, a0, b0 = twlib.find_store(s)
    open(os.path.join(dest, 'tw.html'), 'w', encoding='utf-8').write(s[:i] + twlib.PRE_OPEN + twlib.render_store_blob(blob) + s[b0:])
    print('rotated %d tiddlers -> %s (counter %d). The OLD key still opens everything already published in git history.' % (len(nman['tiddlers']), dest, nman['counter']))

def cmd_inline(a):
    pw = stage1_password()
    cfg, dek = _stage1_bootstrap(a.out, pw); keys = encfmt.Keys(dek)
    man = encfmt.open_manifest(keys, open(os.path.join(a.out, cfg['manifest']), 'rb').read())
    s = open(os.path.join(a.out, 'tw.html'), encoding='utf-8').read()
    # pull plugin divs back out of storeArea
    st = s.index('<div id="storeArea"'); en = s.index('</div>\n<!--~~ Encrypted', st) if '</div>\n<!--~~ Encrypted' in s else None
    store = {}
    pos = st   # linear scan (a regex with .*? is quadratic on hostile input)
    while True:
        i0 = s.find('<div ', pos)
        if i0 < 0: break
        j0 = s.find('>', i0)
        if j0 < 0 or not s.startswith('>\n<pre>', j0): pos = i0 + 5; continue
        k0 = s.find('</pre>\n</div>', j0)
        if k0 < 0: break
        attrs = {k: html.unescape(v) for k, v in re.findall(r' ([\w:.-]+)="([^"]*)"', s[i0 + 4:j0])}
        attrs['text'] = html.unescape(s[j0 + 7:k0])
        pos = k0 + len('</pre>\n</div>')
        if 'title' not in attrs or attrs.get('title') == PLUGIN_TITLE: continue
        store[attrs['title']] = attrs
    for title, e in man['tiddlers'].items():
        fields, body, enc = encfmt.open_tiddler(keys, title, open(os.path.join(a.out, e['p']), 'rb').read(), e['r'])
        store[title] = encfmt.join_tiddler(fields, body, enc)
    store['$:/isEncrypted'] = {'title': '$:/isEncrypted', 'text': 'yes'}
    i, a0, b0 = twlib.find_store(s)
    head = s[:i]
    st0 = head.index('\n<div id="storeArea"'); en0 = head.rindex('</div>\n', 0, head.index('<!--~~ Encrypted')) + len('</div>\n')
    head = head[:st0] + head[en0:]
    blob = twlib.sjcl_encrypt(json.dumps(store).encode('utf-8'), pw, iter=a.kdf_iter)
    open(a.dest, 'w', encoding='utf-8').write(head + twlib.PRE_OPEN + twlib.render_store_blob(blob) + s[b0:])
    print('wrote classic single-file wiki with %d tiddlers -> %s' % (len(store), a.dest))

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest='cmd', required=True)
    for n in ('inspect', 'migrate', 'verify', 'inline', 'rotate', 'restage'):
        q = sp.add_parser(n)
        q.add_argument('--src'); q.add_argument('--out'); q.add_argument('--dest')
        q.add_argument('--repo', default=None, help='OWNER/REPO of the GitHub Pages repository (required for migrate/rotate)'); q.add_argument('--branch', default='master')
        q.add_argument('--base', default=''); q.add_argument('--repo-base', default=None, help='migrate/restage: folder of tw.html inside the repository, e.g. vault/ (restage: "" resets to the root)'); q.add_argument('--api-base', default='https://api.github.com'); q.add_argument('--category-order', default=''); q.add_argument('--kdf-iter', type=int, default=DEFAULT_KDF_ITER); q.add_argument('--no-login-theme', action='store_true', help='migrate/restage: keep the stock TiddlyWiki login screen'); q.add_argument('--csp', action='store_true', help='migrate: add a restrictive Content-Security-Policy meta (see docs/THREAT-MODEL.md)')
    a = p.parse_args()
    {'inspect': cmd_inspect, 'migrate': cmd_migrate, 'verify': cmd_verify, 'inline': cmd_inline, 'restage': cmd_restage, 'rotate': cmd_rotate}[a.cmd](a)

if __name__ == '__main__': main()
