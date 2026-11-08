/*\
title: $:/plugins/tw-enc-sync/localsink.js
type: application/javascript
module-type: library

Local save targets (no TiddlyWiki dependency, unit-testable in Node). Both sinks receive the same "plan" from engine.saveLocal():
  plan = {counter, files: [{path, bytes}], manifest: {path, bytes}, removals: [path]}
(paths are relative to the folder that holds tw.html; every byte is already AES-GCM ciphertext - nothing in a sink is plaintext).

 * ZipSink    - a STORE-only (no compression) ZIP with every changed/new file, the new manifest and `_remove.txt` (paths to delete,
                one per line), delivered as the browser download `tw-update-<counter>.zip`. Works everywhere, needs a user gesture only
                as far as the browser's own download policy requires it.
 * FolderSink - File System Access API (Chromium): writes straight into the wiki folder. The directory handle is kept in IndexedDB;
                a folder picker / permission prompt is only ever shown for an explicit save (`interactive: true`), never from a timer.
                Crash safety: ciphertext files first, the manifest LAST, deletions after that.

\*/
(function(){
"use strict";

/* Same shape as github.js PATH_RE (duplicated on purpose: this module must not depend on anything else). */
var PATH_RE = /^(?:[A-Za-z0-9_-]+\/)*(?:[0-9a-f]{12}\/[0-9a-f]{32}\.bin|m\/[0-9a-f]{32}\.bin)$/;
var MAX_ZIP_BYTES = 1.5 * 1073741824, MAX_ZIP_ENTRIES = 65535;
var FOLDER_KEY = "tw-enc-sync/folder-handle";

function SinkError(msg,code) { this.name = "SinkError"; this.message = msg; if(code) { this.code = code; } }
SinkError.prototype = Object.create(Error.prototype);

/* ------------------------------------------------------------------------------------------------------------------------------- */
/* ZIP (store only)                                                                                                                  */
/* ------------------------------------------------------------------------------------------------------------------------------- */
var CRC_TABLE = (function() {
	var t = new Uint32Array(256), n, k, c;
	for(n=0; n<256; n++) { c = n; for(k=0; k<8; k++) { c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); } t[n] = c >>> 0; }
	return t;
})();
function crc32(bytes,crc) {
	var c = ~(crc || 0) >>> 0, i, n = bytes.length;
	for(i=0; i<n; i++) { c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8); }
	return (~c) >>> 0;
}
var enc = typeof TextEncoder === "function" ? new TextEncoder() : null;
function utf8(s) {
	if(enc) { return enc.encode(s); }
	var bin = unescape(encodeURIComponent(s)), out = new Uint8Array(bin.length), i;   // very old engines
	for(i=0; i<bin.length; i++) { out[i] = bin.charCodeAt(i); }
	return out;
}
function dosDateTime(d) {
	var y = Math.max(1980,d.getFullYear());
	return {date: ((y - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(), time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)};
}
function checkZipName(n) {
	if(typeof n !== "string" || !n || n.length > 1000 || n.charAt(0) === "/" || n.indexOf("\\") !== -1 || n.indexOf("\0") !== -1 ||
			n.split("/").some(function(s) { return s === "" || s === "." || s === ".."; })) { throw new SinkError("invalid file name for the zip"); }
}
/* files: [{name, bytes: Uint8Array}] -> {parts: Uint8Array[], size}. No zip64: entries <= 65535, total <= 1.5 GiB. */
function buildZip(files,opts) {
	opts = opts || {};
	if(files.length > MAX_ZIP_ENTRIES) { throw new SinkError("too many files for one zip (" + files.length + " > " + MAX_ZIP_ENTRIES + "): use the folder target or publish to GitHub"); }
	var total = 0, i, seen = Object.create(null);
	for(i=0; i<files.length; i++) {
		checkZipName(files[i].name);
		if(seen[files[i].name]) { throw new SinkError("duplicate file name in the zip"); }
		seen[files[i].name] = true;
		total += files[i].bytes.length + 2 * utf8(files[i].name).length + 76;
	}
	if(total > MAX_ZIP_BYTES) { throw new SinkError("update too large for one zip (" + Math.round(total / 1048576) + " MiB, limit 1536 MiB): use the folder target or publish to GitHub"); }
	var dt = dosDateTime(opts.now instanceof Date ? opts.now : new Date()), parts = [], central = [], offset = 0;
	files.forEach(function(f) {
		var name = utf8(f.name), crc = crc32(f.bytes), h = new DataView(new ArrayBuffer(30));
		h.setUint32(0,0x04034b50,true); h.setUint16(4,20,true); h.setUint16(6,0x0800,true); h.setUint16(8,0,true);
		h.setUint16(10,dt.time,true); h.setUint16(12,dt.date,true); h.setUint32(14,crc,true);
		h.setUint32(18,f.bytes.length,true); h.setUint32(22,f.bytes.length,true); h.setUint16(26,name.length,true); h.setUint16(28,0,true);
		parts.push(new Uint8Array(h.buffer),name,f.bytes);
		var c = new DataView(new ArrayBuffer(46));
		c.setUint32(0,0x02014b50,true); c.setUint16(4,(3 << 8) | 20,true); c.setUint16(6,20,true); c.setUint16(8,0x0800,true); c.setUint16(10,0,true);
		c.setUint16(12,dt.time,true); c.setUint16(14,dt.date,true); c.setUint32(16,crc,true);
		c.setUint32(20,f.bytes.length,true); c.setUint32(24,f.bytes.length,true); c.setUint16(28,name.length,true);
		c.setUint16(30,0,true); c.setUint16(32,0,true); c.setUint16(34,0,true); c.setUint16(36,0,true);
		c.setUint32(38,((0o100644 << 16) >>> 0),true); c.setUint32(42,offset,true);
		central.push(new Uint8Array(c.buffer),name);
		offset += 30 + name.length + f.bytes.length;
	});
	var cdSize = 0; central.forEach(function(p) { cdSize += p.length; });
	var e = new DataView(new ArrayBuffer(22));
	e.setUint32(0,0x06054b50,true); e.setUint16(4,0,true); e.setUint16(6,0,true); e.setUint16(8,files.length,true); e.setUint16(10,files.length,true);
	e.setUint32(12,cdSize,true); e.setUint32(16,offset,true); e.setUint16(20,0,true);
	parts = parts.concat(central,[new Uint8Array(e.buffer)]);
	return {parts: parts, size: offset + cdSize + 22};
}
function concat(parts,size) {
	var out = new Uint8Array(size), p = 0;
	parts.forEach(function(x) { out.set(x,p); p += x.length; });
	return out;
}

/* Default download trigger: anchor + Blob URL, revoked afterwards. Injectable (opts.trigger) for tests / other environments. */
function browserDownload(blob,filename,env) {
	var doc = (env && env.document) || (typeof document !== "undefined" ? document : null), U = (env && env.URL) || (typeof URL !== "undefined" ? URL : null);
	if(!doc || !U || typeof U.createObjectURL !== "function") { throw new SinkError("downloads are not available in this environment"); }
	var url = U.createObjectURL(blob), a = doc.createElement("a");
	a.href = url; a.download = filename; a.rel = "noopener"; a.style.display = "none";
	(doc.body || doc.documentElement).appendChild(a);
	try { a.click(); } finally {
		setTimeout(function() { try { if(a.parentNode) { a.parentNode.removeChild(a); } } catch(e) {} try { U.revokeObjectURL(url); } catch(e) {} },60000);
	}
}

function ZipSink(opts) {
	opts = opts || {};
	this.name = "zip";
	this.trigger = opts.trigger || function(blob,filename) { return browserDownload(blob,filename,opts); };
	this.now = opts.now;
	this.BlobCtor = opts.BlobCtor || (typeof Blob !== "undefined" ? Blob : null);
	this.files = [];
	this.removals = [];
}
ZipSink.prototype.add = function(path,bytes) { this.files.push({name: path, bytes: bytes}); return this; };
ZipSink.prototype.remove = function(path) { this.removals.push(path); return this; };
/* -> {name, parts, size}: files first, manifest after them, `_remove.txt` last */
ZipSink.prototype.build = function(counter,manifest) {
	var list = this.files.slice();
	if(manifest) { list.push({name: manifest.path, bytes: manifest.bytes}); }
	var rm = this.removals.length ? this.removals.join("\n") + "\n" : "";
	list.push({name: "_remove.txt", bytes: utf8(rm)});
	var z = buildZip(list,{now: this.now});
	return {name: "tw-update-" + counter + ".zip", parts: z.parts, size: z.size};
};
ZipSink.prototype.write = function(plan) {
	var self = this;
	return new Promise(function(resolve,reject) {
		if(!/^\d{1,15}$/.test(String(plan.counter))) { throw new SinkError("invalid counter"); }
		self.files = []; self.removals = [];
		plan.files.forEach(function(f) { if(!PATH_RE.test(f.path)) { throw new SinkError("refusing unexpected path"); } self.add(f.path,f.bytes); });
		if(!plan.manifest || !PATH_RE.test(plan.manifest.path)) { throw new SinkError("refusing unexpected manifest path"); }
		(plan.removals || []).forEach(function(p) { if(!PATH_RE.test(p)) { throw new SinkError("refusing unexpected path"); } self.remove(p); });
		var z = self.build(plan.counter,plan.manifest);
		if(!self.BlobCtor) { throw new SinkError("Blob is not available"); }
		var blob = new self.BlobCtor(z.parts,{type: "application/zip"});
		self.files = []; self.removals = [];
		Promise.resolve(self.trigger(blob,z.name)).then(function() { resolve({name: z.name, size: z.size, files: plan.files.length, removals: (plan.removals || []).length}); },reject);
	});
};

/* ------------------------------------------------------------------------------------------------------------------------------- */
/* Folder (File System Access API)                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------------------------- */
/* IndexedDB key/value store for the directory handle. Injectable (opts.store: {get(key), set(key,val), delete(key)} -> Promise). */
function idbStore(indexedDB) {
	function open() {
		return new Promise(function(resolve,reject) {
			var rq = indexedDB.open("tw-enc-sync",1);
			rq.onupgradeneeded = function() { try { rq.result.createObjectStore("handles"); } catch(e) {} };
			rq.onsuccess = function() { resolve(rq.result); };
			rq.onerror = function() { reject(rq.error || new Error("IndexedDB unavailable")); };
		});
	}
	function run(mode,fn) {
		return open().then(function(db) {
			return new Promise(function(resolve,reject) {
				var tx = db.transaction("handles",mode), rq = fn(tx.objectStore("handles"));
				tx.oncomplete = function() { db.close(); resolve(rq && rq.result); };
				tx.onerror = tx.onabort = function() { db.close(); reject(tx.error || new Error("IndexedDB error")); };
			});
		});
	}
	return {
		get: function(k) { return run("readonly",function(s) { return s.get(k); }); },
		set: function(k,v) { return run("readwrite",function(s) { return s.put(v,k); }); },
		delete: function(k) { return run("readwrite",function(s) { return s.delete(k); }); }
	};
}
function nullStore() { return {get: function() { return Promise.resolve(undefined); }, set: function() { return Promise.resolve(); }, delete: function() { return Promise.resolve(); }}; }

function FolderSink(opts) {
	opts = opts || {};
	var w = opts.window || (typeof window !== "undefined" ? window : null);
	this.name = "folder";
	this.picker = opts.picker || (w && typeof w.showDirectoryPicker === "function" ? w.showDirectoryPicker.bind(w) : null);
	this.confirm = opts.confirm || (w && typeof w.confirm === "function" ? w.confirm.bind(w) : function() { return false; });
	this.key = opts.key || FOLDER_KEY;
	var idb = opts.indexedDB || (w && w.indexedDB);
	this.store = opts.store || (idb ? idbStore(idb) : nullStore());
	this.handle = null; this.validated = false; this.mode = "readwrite";
}
FolderSink.supported = function(w) {
	w = w || (typeof window !== "undefined" ? window : null);
	return !!(w && typeof w.showDirectoryPicker === "function");
};
FolderSink.prototype.loadHandle = function() {
	var self = this;
	if(this.handle) { return Promise.resolve(this.handle); }
	return Promise.resolve(this.store.get(this.key)).then(function(h) {
		if(h && typeof h.queryPermission === "function" && h.kind === "directory") { self.handle = h; return h; }
		return null;
	},function() { return null; });
};
FolderSink.prototype.forget = function() {
	this.handle = null; this.validated = false;
	return Promise.resolve(this.store.delete(this.key)).catch(function() {});
};
/* Silent probe (never prompts): is there a stored folder we may write to right now? */
FolderSink.prototype.hasPermission = function() {
	var self = this;
	return this.loadHandle().then(function(h) {
		if(!h) { return false; }
		return Promise.resolve(h.queryPermission({mode: self.mode})).then(function(p) { return p === "granted"; });
	}).catch(function() { return false; });
};

function walkTo(dir,segments,create) {
	var p = Promise.resolve(dir);
	segments.forEach(function(s) { p = p.then(function(d) { return d.getDirectoryHandle(s,{create: !!create}); }); });
	return p;
}
function isNotFound(e) { return !!e && (e.name === "NotFoundError" || e.name === "TypeMismatchError"); }
function exists(dir,rel,kind) {
	var segs = rel.split("/"), name = segs.pop();
	return walkTo(dir,segs,false).then(function(d) { return kind === "dir" ? d.getDirectoryHandle(name) : d.getFileHandle(name); }).then(function() { return true; },function(e) {
		if(isNotFound(e)) { return false; }
		throw e;
	});
}
function isEmptyDir(dir) {
	if(typeof dir.values === "function") {
		var it = dir.values();
		return Promise.resolve(it.next()).then(function(r) { return !!r.done; });
	}
	if(typeof dir.keys === "function") { return Promise.resolve(dir.keys().next()).then(function(r) { return !!r.done; }); }
	return Promise.resolve(false);
}
/* The chosen folder must be the wiki folder: it holds tw.html or this wiki's manifest. An EMPTY folder is accepted only with the user's confirmation. */
FolderSink.prototype.validate = function(handle,manifestPath,interactive) {
	var self = this;
	return exists(handle,"tw.html","file").then(function(a) { return a || exists(handle,manifestPath,"file"); }).then(function(ok) {
		if(ok) { return; }
		return isEmptyDir(handle).then(function(empty) {
			if(empty && interactive && self.confirm("The chosen folder is empty. Write the encrypted wiki files here? (Choose Cancel if this is not the folder that contains tw.html.)")) { return; }
			throw new SinkError("The chosen folder does not look like the wiki folder (neither tw.html nor the manifest was found in it). Pick the folder that contains tw.html.","wrong-folder");
		});
	});
};
/* Resolves a writable, validated directory handle. Prompts (picker / permission) only when interactive. */
FolderSink.prototype.access = function(manifestPath,interactive) {
	var self = this, fresh = false;
	function needGesture(what) { return new SinkError("Local folder: " + what + " needs a click on Save (it is never requested automatically).","needs-gesture"); }
	return this.loadHandle().then(function(h) {
		if(h) { return h; }
		if(!interactive) { throw needGesture("choosing the wiki folder"); }
		if(!self.picker) { throw new SinkError("This browser cannot write to a folder (File System Access API missing).","unsupported"); }
		return Promise.resolve(self.picker({mode: self.mode})).then(function(p) { fresh = true; self.handle = p; self.validated = false; return p; },function(e) {
			throw new SinkError(e && e.name === "AbortError" ? "Folder selection was cancelled." : "Could not open the folder picker.","cancelled");
		});
	}).then(function(h) {
		return Promise.resolve(h.queryPermission({mode: self.mode})).then(function(p) {
			if(p === "granted") { return h; }
			if(!interactive) { throw needGesture("permission to write to the folder"); }
			return Promise.resolve(h.requestPermission({mode: self.mode})).then(function(p2) {
				if(p2 !== "granted") { throw new SinkError("Permission to write to the wiki folder was not granted.","denied"); }
				return h;
			});
		});
	}).then(function(h) {
		if(self.validated) { return h; }
		return self.validate(h,manifestPath,interactive).then(function() { self.validated = true; return h; },function(e) {
			return (fresh || (e && e.code === "wrong-folder") ? self.forget() : Promise.resolve()).then(function() { throw e; });
		});
	}).then(function(h) {
		if(!fresh) { return h; }
		return Promise.resolve(self.store.set(self.key,h)).then(function() { return h; },function() { return h; });   // not persisting is not fatal
	});
};
function writeFile(root,rel,bytes) {
	var segs = rel.split("/"), name = segs.pop();
	return walkTo(root,segs,true).then(function(d) { return d.getFileHandle(name,{create: true}); }).then(function(fh) {
		return fh.createWritable();
	}).then(function(w) {
		return Promise.resolve(w.write(bytes)).then(function() { return w.close(); },function(e) { try { var r = w.abort && w.abort(); if(r && r.catch) { r.catch(function() {}); } } catch(e2) {} throw e; });
	});
}
function removeFile(root,rel) {
	var segs = rel.split("/"), name = segs.pop();
	return walkTo(root,segs,false).then(function(d) { return d.removeEntry(name); }).then(function() { return true; },function(e) {
		if(isNotFound(e)) { return false; }
		throw e;
	});
}
FolderSink.prototype.write = function(plan,opts) {
	var self = this, interactive = !!(opts && opts.interactive);
	try {
		[plan.manifest].concat(plan.files,(plan.removals || []).map(function(p) { return {path: p}; })).forEach(function(f) {
			if(!f || !PATH_RE.test(f.path)) { throw new SinkError("refusing unexpected path"); }
		});
	} catch(e) { return Promise.reject(e); }
	return this.access(plan.manifest.path,interactive).then(function(root) {
		var p = Promise.resolve(), n = 0;
		plan.files.forEach(function(f) { p = p.then(function() { return writeFile(root,f.path,f.bytes); }).then(function() { n++; }); });
		p = p.then(function() { return writeFile(root,plan.manifest.path,plan.manifest.bytes); });   // manifest LAST: a crash leaves the old, still consistent manifest
		var removed = 0;
		(plan.removals || []).forEach(function(r) { p = p.then(function() { return removeFile(root,r); }).then(function(did) { if(did) { removed++; } }); });
		return p.then(function() { return {written: n + 1, removed: removed}; });
	});
};

exports.crc32 = crc32; exports.buildZip = buildZip; exports.concat = concat; exports.browserDownload = browserDownload;
exports.ZipSink = ZipSink; exports.FolderSink = FolderSink; exports.SinkError = SinkError; exports.PATH_RE = PATH_RE;
exports.MAX_ZIP_BYTES = MAX_ZIP_BYTES; exports.FOLDER_KEY = FOLDER_KEY;
})();
