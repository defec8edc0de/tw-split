"""Reference implementation of the 'TWE1' encrypted-tiddler storage format (see docs/FORMAT.md).
The browser plugin (plugin/src/encfmt.js) must stay byte-compatible; tests/vectors.json pins both."""
import base64, hashlib, hmac, json, re, struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

MAGIC_FILE = b'TWE1'
MAGIC_MAN = b'TWM1'
HKDF_SALT = b'tw-enc-sync/v1'
BASE64_TYPES = {
    "application/epub+zip", "application/font-woff", "application/octet-stream", "application/pdf",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/x-font-ttf", "application/zip", "audio/mp3", "audio/mp4", "audio/ogg", "image/gif",
    "image/heic", "image/heif", "image/jpeg", "image/png", "image/webp", "image/x-icon", "video/mp4"}

MANIFEST_PATH_RE = re.compile(r'^[0-9a-f]{12}/[0-9a-f]{32}\.bin$')
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')
MAX_SAFE_INT = 2**53 - 1      # JS Number.MAX_SAFE_INTEGER: rev/counter/sizes must round-trip through JS

def _is_uint(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= MAX_SAFE_INT

def _no_const(name):          # reject NaN / Infinity / -Infinity (JSON.parse rejects them too)
    raise ValueError('non-finite number in JSON')

def _loads(b: bytes):
    return json.loads(b.decode('utf-8'), parse_constant=_no_const)

class Keys:
    def __init__(self, dek: bytes):
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != 32: raise ValueError('DEK must be 32 bytes')
        self.enc = HKDF(dek, 32, HKDF_SALT, SHA256, context=b'enc')
        self.id = HKDF(dek, 32, HKDF_SALT, SHA256, context=b'id')
        self.man = HKDF(dek, 32, HKDF_SALT, SHA256, context=b'manifest')

def _hmac_hex(key, label: bytes, value: str, n: int) -> str:
    # Framing: label is exactly 1 byte, then NUL, then the value => injective for every value (incl. values containing NUL).
    # str.encode raises on lone surrogates (the JS side rejects them too) instead of silently aliasing titles.
    if not isinstance(value, str): raise TypeError('id input must be str')
    return hmac.new(key, label + b'\0' + value.encode('utf-8'), hashlib.sha256).hexdigest()[:n]

def file_id(keys, title): return _hmac_hex(keys.id, b't', title, 32)
def cat_id(keys, category): return _hmac_hex(keys.id, b'c', category, 12)
def manifest_path(keys): return 'm/' + _hmac_hex(keys.id, b'm', '', 32) + '.bin'
def file_path(keys, title, category): return cat_id(keys, category) + '/' + file_id(keys, title) + '.bin'

def pad_len(n: int) -> int:
    """Padded plaintext length for n bytes (bucket padding to limit size leakage)."""
    if n <= 1024: return 1024
    if n <= 65536:
        b = 1024
        while b < n: b *= 2
        return b
    return ((n + 65535) // 65536) * 65536

def _aad(magic, ident: str, rev: int) -> bytes:
    # ident is always 32 lowercase hex chars (fixed length) => magic|ident|0x00|decimal(rev) is unambiguous.
    if not _is_uint(rev): raise ValueError('rev must be an integer in [0, 2^53)')
    return magic + ident.encode('ascii') + b'\0' + str(rev).encode('ascii')

def _iv(iv):
    iv = get_random_bytes(12) if iv is None else bytes(iv)
    if len(iv) != 12: raise ValueError('IV must be 12 bytes')
    return iv

def seal_tiddler(keys, title, fields: dict, body: bytes, body_enc: str, rev: int, iv=None):
    """fields: tiddler fields WITHOUT 'text'. Returns file bytes."""
    hdr = dict(fields); hdr['title'] = title
    meta = json.dumps({"f": hdr, "enc": body_enc, "bl": len(body)}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if not isinstance(body, (bytes, bytearray)) or body_enc not in ('utf8', 'base64'): raise ValueError('bad body')
    plain = struct.pack('>I', len(meta)) + meta + body
    plain += b'\0' * (pad_len(len(plain)) - len(plain))
    iv = _iv(iv)
    ident = file_id(keys, title)
    c = AES.new(keys.enc, AES.MODE_GCM, nonce=iv, mac_len=16)
    c.update(_aad(MAGIC_FILE, ident, rev))
    ct, tag = c.encrypt_and_digest(plain)
    return MAGIC_FILE + iv + ct + tag

def open_tiddler(keys, title, blob: bytes, rev: int):
    """Returns (fields, body_bytes, body_enc). Raises on any malformation; nothing is parsed before the GCM tag verifies."""
    if len(blob) < 4 + 12 + 16 + 1024 or blob[:4] != MAGIC_FILE: raise ValueError('bad magic or truncated file')
    iv, ct, tag = blob[4:16], blob[16:-16], blob[-16:]
    c = AES.new(keys.enc, AES.MODE_GCM, nonce=iv, mac_len=16)
    c.update(_aad(MAGIC_FILE, file_id(keys, title), rev))
    plain = c.decrypt_and_verify(ct, tag)
    (ml,) = struct.unpack('>I', plain[:4])
    if 4 + ml > len(plain): raise ValueError('bad meta length')
    meta = _loads(plain[4:4 + ml])
    if not isinstance(meta, dict) or not isinstance(meta.get('f'), dict) or meta['f'].get('title') != title: raise ValueError('title mismatch')
    if meta.get('enc') not in ('utf8', 'base64'): raise ValueError('bad body encoding')
    bl = meta.get('bl')
    if not _is_uint(bl) or 4 + ml + bl > len(plain): raise ValueError('bad body length')
    if len(plain) != pad_len(4 + ml + bl): raise ValueError('non-canonical padding')
    return meta['f'], plain[4 + ml:4 + ml + bl], meta['enc']

def split_tiddler(fields: dict):
    """-> (fields_without_text, body_bytes, enc). Falls back to utf8 if base64 does not round-trip exactly."""
    f = {k: v for k, v in fields.items() if k != 'text'}
    text = fields.get('text', '')
    if fields.get('type') in BASE64_TYPES:
        try:
            raw = base64.b64decode(text, validate=True)
            if base64.b64encode(raw).decode('ascii') == text:
                return f, raw, 'base64'
        except Exception:
            pass
    return f, text.encode('utf-8'), 'utf8'

def join_tiddler(fields: dict, body: bytes, enc: str):
    f = dict(fields)
    f['text'] = base64.b64encode(body).decode('ascii') if enc == 'base64' else body.decode('utf-8')
    return f

def _check_manifest(m):
    """Structural validation (applied on seal and after open). Entry: {c: category, p: path, r: rev, h: sha256 hex of file, s: size, f: skinny fields}."""
    if not isinstance(m, dict) or m.get('v') != 1 or isinstance(m.get('v'), bool): raise ValueError('bad manifest version')
    if not _is_uint(m.get('counter')) or not isinstance(m.get('tiddlers'), dict): raise ValueError('bad manifest')
    for t, e in m['tiddlers'].items():
        if not (isinstance(e, dict) and isinstance(e.get('p'), str) and MANIFEST_PATH_RE.match(e['p']) and _is_uint(e.get('r'))
                and isinstance(e.get('h'), str) and HEX64_RE.match(e['h']) and isinstance(e.get('f'), dict)
                and _is_uint(e.get('s')) and isinstance(e.get('c'), str)):
            raise ValueError('corrupt manifest entry')
    return m

def seal_manifest(keys, manifest: dict, iv=None):
    _check_manifest(manifest)
    plain = json.dumps(manifest, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    # padding is NUL bytes; JSON text of an object always ends with '}', so stripping trailing NULs on open is unambiguous.
    plain += b'\0' * (pad_len(len(plain)) - len(plain))
    iv = _iv(iv)
    c = AES.new(keys.man, AES.MODE_GCM, nonce=iv, mac_len=16)
    c.update(MAGIC_MAN + struct.pack('>Q', manifest['counter']))
    ct, tag = c.encrypt_and_digest(plain)
    return MAGIC_MAN + struct.pack('>Q', manifest['counter']) + iv + ct + tag

def open_manifest(keys, blob: bytes):
    if len(blob) < 4 + 8 + 12 + 16 + 1024 or blob[:4] != MAGIC_MAN: raise ValueError('bad magic or truncated manifest')
    counter = struct.unpack('>Q', blob[4:12])[0]
    iv, ct, tag = blob[12:24], blob[24:-16], blob[-16:]
    c = AES.new(keys.man, AES.MODE_GCM, nonce=iv, mac_len=16)
    c.update(MAGIC_MAN + blob[4:12])
    plain = c.decrypt_and_verify(ct, tag)
    body = plain.rstrip(b'\0')
    if len(plain) != pad_len(len(body)): raise ValueError('non-canonical padding')
    m = _check_manifest(_loads(body))
    if m['counter'] != counter: raise ValueError('counter mismatch')
    return m

def sha256_hex(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
