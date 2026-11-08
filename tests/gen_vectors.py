import sys, json, base64, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
import encfmt
dek = bytes(range(32))
k = encfmt.Keys(dek)
v = {"dek": base64.b64encode(dek).decode(), "cases": []}
for title, fields, text in [
    ("Hello wörld ☃", {"tags": "a [[b c]]", "created": "20200101000000000"}, "text with ünïcode ✓\nline2"),
    ("pic.png", {"type": "image/png"}, base64.b64encode(os.urandom(5000)).decode()),
    ("$:/config/x", {}, ""),
    ("nul\0in\0title", {}, "x"),                       # NUL inside a title (HMAC framing / AAD must not care)
    ("emoji \U0001F600 \u00e9 \u0065\u0301", {}, "\ufeffleading BOM must survive"),
    ("big", {"tags": "z"}, "y" * 70000)]:
    f, body, e = encfmt.split_tiddler(dict(fields, text=text))
    blob = encfmt.seal_tiddler(k, title, f, body, e, 7)
    v["cases"].append({"title": title, "fields": f, "text": text, "rev": 7, "enc": e,
                       "id": encfmt.file_id(k, title), "cat": encfmt.cat_id(k, "task"),
                       "path": encfmt.file_path(k, title, "task"), "blob": base64.b64encode(blob).decode()})
ENTRY = {"c": "task", "p": "0123456789ab/" + "0" * 32 + ".bin", "r": 1, "h": "f" * 64, "s": 1234, "f": {"tags": "x"}}
man = {"v": 1, "counter": 42, "tiddlers": {"a": ENTRY}}
v["manifest"] = base64.b64encode(encfmt.seal_manifest(k, man)).decode()
v["manifest_path"] = encfmt.manifest_path(k)
# Authentic (correct key + AAD) but malformed payloads: every implementation must reject them.
import struct
from Crypto.Cipher import AES
def raw_file(plain, title='t', rev=1):
    iv = os.urandom(12); c = AES.new(k.enc, AES.MODE_GCM, nonce=iv, mac_len=16); c.update(encfmt._aad(encfmt.MAGIC_FILE, encfmt.file_id(k, title), rev))
    ct, tag = c.encrypt_and_digest(plain); return encfmt.MAGIC_FILE + iv + ct + tag
def pad(b, n=1024): return b + b'\0' * (n - len(b))
def mp(meta, body=b''): m = json.dumps(meta, separators=(',', ':')).encode(); return struct.pack('>I', len(m)) + m + body
def raw_man(obj_bytes, counter_hdr=42):
    iv = os.urandom(12); hdr = encfmt.MAGIC_MAN + struct.pack('>Q', counter_hdr)
    c = AES.new(k.man, AES.MODE_GCM, nonce=iv, mac_len=16); c.update(hdr); ct, tag = c.encrypt_and_digest(obj_bytes); return hdr + iv + ct + tag
good = {"f": {"title": "t"}, "enc": "utf8", "bl": 1}
b64 = lambda b: base64.b64encode(b).decode()
v["bad_files"] = [b64(raw_file(x)) for x in (
    pad(mp(dict(good, bl=5000), b'x')),                        # body length beyond plaintext
    pad(mp(dict(good, bl=-1))),                                # negative length
    pad(mp(dict(good, enc="hex"), b'x')),                      # unknown body encoding
    pad(mp({"f": {"title": "other"}, "enc": "utf8", "bl": 1}, b'x')),   # title mismatch inside
    pad(mp({"f": None, "enc": "utf8", "bl": 1}, b'x')),
    pad(mp(good, b'x'), 2048),                                 # padding not the canonical bucket
    struct.pack('>I', 99999) + b'\0' * 1020,                   # meta length beyond plaintext
    )]
mj = lambda o: json.dumps(o, separators=(',', ':')).encode()
bad_man = [pad(mj(dict(man, v=2))), pad(mj({k_: x for k_, x in man.items() if k_ != 'v'})), pad(mj(dict(man, counter=41))),
           pad(mj(dict(man, tiddlers=[]))), pad(mj({"v": 1, "counter": 42, "tiddlers": {"a": dict(ENTRY, p="../../x")}})),
           pad(mj({"v": 1, "counter": 42, "tiddlers": {"a": dict(ENTRY, r=1.5)}})), pad(b'{"v":1,"counter":NaN,"tiddlers":{}}'),
           pad(mj(man)[:-1]), pad(mj(man)) + b'\0' * 1024]   # truncated JSON; non-canonical padding
v["ok_file"] = b64(raw_file(pad(mp(good, b'x'))))           # controls: same helpers, well-formed => must open
v["ok_manifest"] = b64(raw_man(pad(mj(man))))
v["bad_manifests"] = [b64(raw_man(x)) for x in bad_man]
json.dump(v, open(os.path.join(os.path.dirname(__file__), 'vectors.json'), 'w'), indent=1)
print("ok")
