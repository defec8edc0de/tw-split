"""Shared helpers: parse TiddlyWiki 5 single-file HTML, SJCL-compatible (stock TW) store encryption.
Passwords are NEVER read from disk: only from env TW_PASSWORD (or passed in by caller)."""
import base64, hashlib, html, json, os, re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PRE_OPEN = '<pre id="encryptedStoreArea" type="text/plain" style="display:none;">'

def _ccm_L(n, ivlen=16):
    """Length-of-length exactly as sjcl.mode.ccm: smallest L in [2,4] with n < 2^(8L), but at least 15 - len(iv)."""
    L = 2
    while L < 4 and (n >> (8 * L)):
        L += 1
    return max(L, 15 - ivlen)

# Parameters we are willing to process. SJCL itself trusts the blob; a local tool should not.
_ALLOWED_KS = (128, 192, 256)
_ALLOWED_TS = (32, 48, 64, 80, 96, 112, 128)    # CCM tag lengths (bits)
MAX_ITER = 100_000_000
DEFAULT_ITER = 10000      # stock TiddlyWiki 5.1.x value

def _check_params(iter, ks, ts, ivlen):
    if not (isinstance(iter, int) and 1 <= iter <= MAX_ITER): raise ValueError('unsupported PBKDF2 iteration count')
    if ks not in _ALLOWED_KS or ts not in _ALLOWED_TS: raise ValueError('unsupported key/tag size')
    if not 7 <= ivlen <= 16: raise ValueError('unsupported IV length')

def sjcl_decrypt(blob, password):
    """blob: dict from the encryptedStoreArea JSON. Returns plaintext bytes or raises ValueError.
    Nothing is returned unless the CCM tag verifies (pycryptodome's decrypt_and_verify)."""
    if not (isinstance(blob, dict) and blob.get('mode') == 'ccm' and blob.get('cipher') == 'aes' and blob.get('adata', '') == ''):
        raise ValueError('unsupported SJCL parameters (need ccm/aes/no adata)')
    salt = base64.b64decode(blob['salt']); iv = base64.b64decode(blob['iv']); ct = base64.b64decode(blob['ct'])
    _check_params(blob['iter'], blob['ks'], blob['ts'], len(iv))
    ts = blob['ts'] // 8
    if len(ct) < ts: raise ValueError('bad password or corrupted store')
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, blob['iter'], blob['ks'] // 8)
    L = _ccm_L(len(ct) - ts, len(iv))
    nonce = iv[:15 - L]
    c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=ts, msg_len=len(ct) - ts)
    try:
        return c.decrypt_and_verify(ct[:-ts], ct[-ts:])
    except ValueError:
        raise ValueError('bad password or corrupted store')

def sjcl_encrypt(plain, password, iter=DEFAULT_ITER, ks=128, ts=64):
    """Stock-TiddlyWiki-compatible blob. Fresh random 8-byte salt and 16-byte IV (CSPRNG) per call.
    `iter` is honoured by TiddlyWiki's decryptor (it reads it from the blob), so it may exceed the stock 10000."""
    _check_params(iter, ks, ts, 16)
    salt = get_random_bytes(8); iv = get_random_bytes(16)
    L = _ccm_L(len(plain)); nonce = iv[:15 - L]
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iter, ks // 8)
    c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=ts // 8, msg_len=len(plain))
    ct, tag = c.encrypt_and_digest(plain)
    b = lambda x: base64.b64encode(x).decode()
    # same key order as sjcl.json.encode in TW's output
    return {"iv": b(iv), "v": 1, "iter": iter, "ks": ks, "ts": ts, "mode": "ccm", "adata": "",
            "cipher": "aes", "salt": b(salt), "ct": b(ct + tag)}

def find_store(s):
    i = s.find(PRE_OPEN)
    if i < 0: raise ValueError('no encryptedStoreArea')
    a = i + len(PRE_OPEN); b = s.find('</pre>', a)
    if b < 0: raise ValueError('unterminated encryptedStoreArea')   # s[a:-1] would silently drop a byte
    return i, a, b

def read_encrypted_store(s, password):
    _, a, b = find_store(s)
    blob = json.loads(html.unescape(s[a:b].strip()))
    return json.loads(sjcl_decrypt(blob, password).decode('utf-8'))

def render_store_blob(blob):
    return '\n' + html.escape(json.dumps(blob, separators=(',', ':')), quote=True).replace('&#x27;', "'") + '\n'

_pw_cache = {}
def get_password(var='TW_PASSWORD', required=True):
    """Passwords come ONLY from the environment (never argv, never a file). The variable is removed from this
    process's environment on first read so that child processes / later os.environ dumps do not inherit it."""
    if var not in _pw_cache:
        _pw_cache[var] = os.environ.pop(var, None)
    pw = _pw_cache[var]
    if not pw:
        if required: raise SystemExit('%s env var not set' % var)
        return None
    return pw
