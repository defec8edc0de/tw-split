/*\
title: $:/plugins/tw-enc-sync/encfmt.js
type: application/javascript
module-type: library

Encrypted tiddler file format "TWE1" / manifest "TWM1" (WebCrypto). Must stay byte-compatible with tools/encfmt.py.
Pure functions, no TiddlyWiki dependency => unit-testable in Node >= 20.

\*/
(function(){
/*jslint node: true, browser: true */
"use strict";

var subtle = (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) || null;
var enc = new TextEncoder(), dec = new TextDecoder("utf-8",{fatal: true, ignoreBOM: true});   // ignoreBOM:true => a leading U+FEFF is preserved (Python parity)
var MAX_SAFE = Number.MAX_SAFE_INTEGER;
var MANIFEST_PATH_RE = /^[0-9a-f]{12}\/[0-9a-f]{32}\.bin$/, HEX64_RE = /^[0-9a-f]{64}$/;
var MAGIC_FILE = enc.encode("TWE1"), MAGIC_MAN = enc.encode("TWM1");
var HKDF_SALT = enc.encode("tw-enc-sync/v1");

function cat() {
	var n = 0, i, out, p = 0;
	for(i=0; i<arguments.length; i++) { n += arguments[i].length; }
	out = new Uint8Array(n);
	for(i=0; i<arguments.length; i++) { out.set(arguments[i],p); p += arguments[i].length; }
	return out;
}
function hex(buf) {
	var a = new Uint8Array(buf), s = "";
	for(var i=0; i<a.length; i++) { s += (a[i] < 16 ? "0" : "") + a[i].toString(16); }
	return s;
}
function b64decode(s) {
	var bin = atob(s), out = new Uint8Array(bin.length);
	for(var i=0; i<bin.length; i++) { out[i] = bin.charCodeAt(i); }
	return out;
}
function b64encode(bytes) {
	var s = "", CH = 0x8000;
	for(var i=0; i<bytes.length; i+=CH) { s += String.fromCharCode.apply(null,bytes.subarray(i,i+CH)); }
	return btoa(s);
}
function isUint(n) { return typeof n === "number" && Number.isSafeInteger(n) && n >= 0; }
/* Strict UTF-8: TextEncoder silently turns lone surrogates into U+FFFD (aliasing distinct strings); Python raises. We throw. */
function wellFormed(s) { return !/[\ud800-\udbff](?![\udc00-\udfff])|(?:[^\ud800-\udbff]|^)[\udc00-\udfff]/.test(s); }
function utf8encode(s) {
	if(typeof s !== "string") { throw new TypeError("string expected"); }
	if(!wellFormed(s)) { throw new Error("lone surrogate in string"); }
	return enc.encode(s);
}
/* JSON.stringify escapes lone surrogates (\udXXX) which Python's encoder would reject; refuse them in every key and string value. */
function strictJson(v) {
	return JSON.stringify(v,function(k,val) {
		if(!wellFormed(k) || (typeof val === "string" && !wellFormed(val))) { throw new Error("lone surrogate in string"); }
		return val;
	});
}
function utf8decode(bytes) { return dec.decode(bytes); }   // fatal, BOM-preserving
/* realm-agnostic (iframes / test harnesses create Uint8Arrays in other realms) */
function isU8(x) { return Object.prototype.toString.call(x) === "[object Uint8Array]"; }
function u32(n) { var b = new Uint8Array(4); new DataView(b.buffer).setUint32(0,n,false); return b; }
function u64(n) { if(!isUint(n)) { throw new Error("counter must be a safe non-negative integer"); } var b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0,BigInt(n),false); return b; }

function padLen(n) {
	if(n <= 1024) { return 1024; }
	if(n <= 65536) { var b = 1024; while(b < n) { b *= 2; } return b; }
	return Math.ceil(n / 65536) * 65536;
}

/* dek: Uint8Array(32). Returns {enc: CryptoKey(AES-GCM), id: CryptoKey(HMAC), man: CryptoKey(AES-GCM)} */
async function deriveKeys(dek) {
	if(!subtle) { throw new Error("WebCrypto unavailable (needs https:// or localhost)"); }
	if(!isU8(dek) || dek.length !== 32) { throw new Error("bad key length"); }
	var base = await subtle.importKey("raw",dek,"HKDF",false,["deriveBits","deriveKey"]);
	function params(label) { return {name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: enc.encode(label)}; }
	return {
		enc: await subtle.deriveKey(params("enc"),base,{name: "AES-GCM", length: 256},false,["encrypt","decrypt"]),
		man: await subtle.deriveKey(params("manifest"),base,{name: "AES-GCM", length: 256},false,["encrypt","decrypt"]),
		id: await subtle.importKey("raw",await subtle.deriveBits(params("id"),base,256),{name: "HMAC", hash: "SHA-256"},false,["sign"])
	};
}
async function hmacHex(keys,label,value,n) {
	var mac = await subtle.sign("HMAC",keys.id,cat(enc.encode(label),new Uint8Array([0]),utf8encode(value)));
	return hex(mac).substr(0,n);
}
function fileId(keys,title) { return hmacHex(keys,"t",title,32); }
function catId(keys,category) { return hmacHex(keys,"c",category,12); }
async function manifestPath(keys) { return "m/" + await hmacHex(keys,"m","",32) + ".bin"; }
async function filePath(keys,title,category) { return (await catId(keys,category)) + "/" + (await fileId(keys,title)) + ".bin"; }

/* ident is always 32 lowercase hex chars (fixed length) => magic|ident|0x00|decimal(rev) is unambiguous. */
function aad(magic,ident,rev) { if(!isUint(rev)) { throw new Error("rev must be an integer in [0, 2^53)"); } return cat(magic,enc.encode(ident),new Uint8Array([0]),enc.encode(String(rev))); }

/* fields: plain object of string fields WITHOUT text; body: Uint8Array; bodyEnc: "utf8"|"base64"; rev: integer */
async function sealTiddler(keys,title,fields,body,bodyEnc,rev) {
	var hdr = {}, k;
	for(k in fields) { if(Object.prototype.hasOwnProperty.call(fields,k) && k !== "text") { hdr[k] = fields[k]; } }
	hdr.title = title;
	if(!isU8(body) || (bodyEnc !== "utf8" && bodyEnc !== "base64")) { throw new Error("bad body"); }
	var meta = enc.encode(strictJson({f: hdr, enc: bodyEnc, bl: body.length}));
	var plain = cat(u32(meta.length),meta,body);
	var padded = new Uint8Array(padLen(plain.length)); padded.set(plain);
	var iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
	var ct = new Uint8Array(await subtle.encrypt({name: "AES-GCM", iv: iv, additionalData: aad(MAGIC_FILE,await fileId(keys,title),rev), tagLength: 128},keys.enc,padded));
	return cat(MAGIC_FILE,iv,ct);
}
/* returns {fields (no text), body: Uint8Array, bodyEnc}. Nothing is parsed before the GCM tag verifies. */
async function openTiddler(keys,title,blob,rev) {
	blob = new Uint8Array(blob);
	if(blob.length < 4 + 12 + 16 + 1024) { throw new Error("truncated file"); }
	for(var i=0; i<4; i++) { if(blob[i] !== MAGIC_FILE[i]) { throw new Error("bad file magic"); } }
	var plain = new Uint8Array(await subtle.decrypt({name: "AES-GCM", iv: blob.subarray(4,16), additionalData: aad(MAGIC_FILE,await fileId(keys,title),rev), tagLength: 128},keys.enc,blob.subarray(16)));
	var ml = new DataView(plain.buffer,plain.byteOffset).getUint32(0,false);
	if(4+ml > plain.length) { throw new Error("bad meta length"); }
	var meta = JSON.parse(utf8decode(plain.subarray(4,4+ml)));
	if(!meta || typeof meta !== "object" || !meta.f || typeof meta.f !== "object" || Array.isArray(meta.f) || meta.f.title !== title) { throw new Error("title mismatch"); }
	if(meta.enc !== "utf8" && meta.enc !== "base64") { throw new Error("bad body encoding"); }
	if(!(isUint(meta.bl) && 4+ml+meta.bl <= plain.length)) { throw new Error("bad body length"); }
	if(plain.length !== padLen(4+ml+meta.bl)) { throw new Error("non-canonical padding"); }
	return {fields: meta.f, body: plain.subarray(4+ml,4+ml+meta.bl), bodyEnc: meta.enc};
}
/* Structural validation, applied on seal and after open. Entry: {c: category, p: path, r: rev, h: sha256 hex of file, s: size, f: skinny fields}. */
function checkManifest(m) {
	if(!m || typeof m !== "object" || m.v !== 1 || !isUint(m.counter) || !m.tiddlers || typeof m.tiddlers !== "object" || Array.isArray(m.tiddlers)) { throw new Error("bad manifest"); }
	for(var t in m.tiddlers) {
		if(!Object.prototype.hasOwnProperty.call(m.tiddlers,t)) { continue; }
		var e = m.tiddlers[t];
		if(!(e && typeof e === "object" && typeof e.p === "string" && MANIFEST_PATH_RE.test(e.p) && isUint(e.r) && typeof e.h === "string" && HEX64_RE.test(e.h) &&
			e.f && typeof e.f === "object" && !Array.isArray(e.f) && isUint(e.s) && typeof e.c === "string")) { throw new Error("corrupt manifest entry"); }
	}
	return m;
}
async function sealManifest(keys,manifest) {
	checkManifest(manifest);
	// padding is NUL bytes; JSON text of an object always ends with '}', so stripping trailing NULs on open is unambiguous.
	var plain = enc.encode(strictJson(manifest));
	var padded = new Uint8Array(padLen(plain.length)); padded.set(plain);
	var iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
	var counter = u64(manifest.counter);
	var ct = new Uint8Array(await subtle.encrypt({name: "AES-GCM", iv: iv, additionalData: cat(MAGIC_MAN,counter), tagLength: 128},keys.man,padded));
	return cat(MAGIC_MAN,counter,iv,ct);
}
async function openManifest(keys,blob) {
	blob = new Uint8Array(blob);
	if(blob.length < 4 + 8 + 12 + 16 + 1024) { throw new Error("truncated manifest"); }
	for(var i=0; i<4; i++) { if(blob[i] !== MAGIC_MAN[i]) { throw new Error("bad manifest magic"); } }
	var counterBytes = blob.subarray(4,12);
	var plain = new Uint8Array(await subtle.decrypt({name: "AES-GCM", iv: blob.subarray(12,24), additionalData: cat(MAGIC_MAN,counterBytes), tagLength: 128},keys.man,blob.subarray(24)));
	var end = plain.length; while(end > 0 && plain[end-1] === 0) { end--; }
	if(plain.length !== padLen(end)) { throw new Error("non-canonical padding"); }
	var m = checkManifest(JSON.parse(utf8decode(plain.subarray(0,end))));
	var big = new DataView(counterBytes.buffer,counterBytes.byteOffset,8).getBigUint64(0,false);
	if(big > BigInt(MAX_SAFE) || m.counter !== Number(big)) { throw new Error("counter mismatch"); }
	return m;
}
async function sha256Hex(bytes) { return hex(await subtle.digest("SHA-256",bytes)); }

exports.deriveKeys = deriveKeys; exports.fileId = fileId; exports.catId = catId;
exports.manifestPath = manifestPath; exports.filePath = filePath; exports.padLen = padLen;
exports.sealTiddler = sealTiddler; exports.openTiddler = openTiddler;
exports.sealManifest = sealManifest; exports.openManifest = openManifest;
exports.utf8encode = utf8encode; exports.utf8decode = utf8decode; exports.sha256Hex = sha256Hex; exports.b64encode = b64encode; exports.b64decode = b64decode; exports.hex = hex;
})();
