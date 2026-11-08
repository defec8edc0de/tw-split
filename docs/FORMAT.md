# File format (v1)

Keys: random 256-bit DEK (stored only inside the stock-encrypted bootstrap blob of `tw.html`). `HKDF-SHA256(DEK, salt="tw-enc-sync/v1", info∈{"enc","id","manifest"}, L=32)` → `k_enc`, `k_id`, `k_man` (three independent keys; each output is one HKDF block, distinct `info` = domain separation; the fixed salt is fine because the DEK is uniformly random).

## Identifiers
* `file_id = hex(HMAC-SHA256(k_id, "t" ‖ 0x00 ‖ UTF8(title)))[:32]` (128 bit), `cat_id = hex(HMAC-SHA256(k_id, "c" ‖ 0x00 ‖ UTF8(category)))[:12]` (48 bit; a collision only merges two folders, the manifest keeps real paths), manifest path `m/` + `hex(HMAC(k_id, "m" ‖ 0x00))[:32]` + `.bin`.
* Framing: the label is exactly one byte followed by NUL, so the encoding is injective for every value (titles may contain NUL). Labels give domain separation between the three id kinds. Ids are keyed, so a guessable title cannot be confirmed without the DEK.
* Strings must be well-formed Unicode: a lone surrogate is **rejected** by both implementations (Python raises; JS `TextEncoder` would silently map it to U+FFFD and alias distinct titles, so `encfmt.js` throws instead). No Unicode normalisation is applied (NFC and NFD titles are different tiddlers, as in TiddlyWiki).

## Tiddler file
`"TWE1" | IV(12) | AES-256-GCM(k_enc, iv, aad, plain) | tag(16)`

* `aad = "TWE1" ‖ file_id(32 ASCII hex) ‖ 0x00 ‖ ASCII-decimal(rev)`. `file_id` has fixed length, so the AAD is unambiguous. `rev` must be an integer in `[0, 2^53)` (both implementations reject anything else, so `1.0`/`"1"`/`true` can never produce divergent AADs).
* `plain = u32be(len(meta)) ‖ meta ‖ body ‖ zero padding`, `meta = JSON{f: fields-without-text (incl. title), enc: "utf8"|"base64", bl: len(body)}`, padded to 1 KiB…64 KiB power-of-two buckets, then multiples of 64 KiB. Leaks only the bucket, not the exact size. Binary types (TW `contentTypeInfo` base64) are stored as raw bytes (`enc:"base64"`, only if the base64 round-trips exactly, i.e. is canonical; otherwise the text is stored as UTF-8).
* Opening is strict, and happens only **after** the GCM tag verified (no parsing of unauthenticated data): blob ≥ 1068 bytes, magic, `4+ml ≤ len(plain)`, `meta.f.title == title`, `enc` known, `bl` a non-negative safe integer with `4+ml+bl ≤ len(plain)`, and `len(plain) == pad_len(4+ml+bl)` (canonical padding). Python's `json` rejects `NaN`/`Infinity` like `JSON.parse`.
* Text decoding must be fatal and BOM-preserving (`TextDecoder("utf-8",{fatal:true,ignoreBOM:true})`; `encfmt.js` exports `utf8decode`/`utf8encode`). The default `TextDecoder` strips a leading U+FEFF, which Python keeps.

## Manifest
`"TWM1" | u64be(counter) | IV(12) | AES-256-GCM(k_man, aad="TWM1"‖u64be(counter), JSON + NUL padding) | tag`

* JSON: `{v:1, counter, tiddlers:{title:{c,p,r,h,s,f}}}`. `h` = SHA-256 (hex) of the entire tiddler file, `r` = revision (in the file's AAD ⇒ no per-file rollback), `c` = category, `p` = path (must match `^[0-9a-f]{12}/[0-9a-f]{32}\.bin$`), `s` = file size, `f` = skinny fields.
* Padding is NUL bytes to the same buckets. A JSON object always ends in `}`, so stripping trailing NULs is unambiguous; the padded length must equal `pad_len(len(stripped))`.
* Validated on seal and after open in both implementations: `v == 1` (exact; unknown versions are refused, there is no negotiation/downgrade), `counter` a safe integer **equal to the authenticated header counter**, `tiddlers` an object, every entry shaped as above (`r`,`s` safe non-negative ints, `h` 64 lowercase hex).
* Counter semantics: every commit and every local save (folder/zip target) writes a manifest with a higher counter; a commit uses `max(remote, local) + 1`. The rollback floor is only raised by counters observed from the remote/page or by own commits (see THREAT-MODEL), so local-only bumps are harmless.
* The counter only detects rollback to a manifest older than one this browser has already seen; it cannot stop a repo writer from replaying an entire older consistent repo state to a fresh browser (see THREAT-MODEL).

## Nonces
96-bit random IV per encryption (`os.urandom` / `crypto.getRandomValues`), shared key `k_enc` for all files. Birthday collision probability for n encryptions is ≈ n²/2⁹⁷: for 10⁴ encryptions ≈ 6·10⁻²², and stays below NIST's 2⁻³² bound up to ≈ 2³² encryptions. Every save is a fresh encryption (new IV). If a wiki ever approached 2³⁰ saves, rotate the DEK with `migrate`.

## Known residuals
* Duplicate JSON keys: last one wins (both parsers); only key holders can produce authenticated JSON, so this is not attacker-reachable.
* Field values are not type-checked inside `f` (TiddlyWiki fields are strings; the engine produces strings).
