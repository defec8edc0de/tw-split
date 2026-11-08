/*\
title: $:/plugins/tw-enc-sync/engine.js
type: application/javascript
module-type: library

Storage engine (independent of TiddlyWiki internals; dependencies are injected so it can be unit-tested in Node).
Keeps: authenticated manifest (title -> entry), pending write queue, sealed-blob cache; commits batches in ONE git commit.

\*/
(function(){
"use strict";

var F = require("$:/plugins/tw-enc-sync/encfmt.js");
var G = require("$:/plugins/tw-enc-sync/github.js");

var BASE_RE = /^(?:[A-Za-z0-9_-]+\/)*$/, HEX64_RE = /^[0-9a-f]{64}$/;
var MAX_PARALLEL = 6, MAX_MANIFEST_BYTES = 32 * 1048576, MAX_FILE_BYTES = 128 * 1048576, MAX_ENTRIES = 100000, CACHE_BYTES = 32 * 1048576;
function originOf(u) { try { var o = new URL(u).origin; return o; } catch(e) { return null; } }
var COUNTER_KEY = "tw-enc-sync/counter/";   // + manifest path: keeps wikis on the same origin apart

/*
deps: {
  cfg: {repo, branch, apiBase, base, manifest},
  dek: Uint8Array(32)  (consumed and zeroed),
  fetch: fetch impl, baseUrl: absolute URL string that relative paths resolve against,
  getToken: function() -> string|undefined,
  storage: {getItem,setItem} or null (only used for the anti-rollback counter),
  isBase64Type: function(type)->bool, categoryOrder: function()->string[],
  onStatus: function(statusObject), setTimeout/clearTimeout optional,
  optional: getTargets: function() -> ["github","folder","zip"] subset (default ["github"]),
            autoSave: function(engine) -> Promise (debounce timer action; default: engine.flush())
}
Invariants: (1) every manifest entry's path is exactly filePath(title, c), so no two titles share a file and a
manifest can never name an arbitrary path; (2) a file is sealed with the revision recorded in its entry and the
revision of a title never decreases across commits (re-sealed at commit time if another device got ahead);
(3) deletions are derived only from the authoritative remote manifest at commit time;
(4) the anti-rollback floor comes only from counters observed on the remote / the page (see this.floor, readSeen): the counter
    bump of a purely local save never raises it, so a locally-ahead state can always be published to an older or empty repository.
Two commit modes (doFlush): "reconcile" (remote empty, or remote.counter < this.counter: local is ahead) makes the remote equal to the local
state by hash diff; otherwise (remote.counter >= this.counter) the pending ops are overlaid on the remote manifest (equal counters never
overwrite another device's work).
*/
function Engine(deps) {
	this.d = deps;
	var c0 = deps.cfg || {};
	if(c0.base !== undefined && c0.base !== null && typeof c0.base !== "string") { throw new Error("invalid base path"); }
	// private snapshot of the configuration: later mutation of the caller's object cannot redirect fetches / commits
	this.cfg = {repo: c0.repo, branch: c0.branch, apiBase: c0.apiBase, base: c0.base || "", repoBase: c0.repoBase || "", manifest: c0.manifest};
	if(!BASE_RE.test(this.cfg.base)) { throw new Error("invalid base path"); }
	if(!BASE_RE.test(this.cfg.repoBase) || this.cfg.repoBase.split("/").some(function(x) { return x === "." || x === ".."; })) { throw new Error("invalid repoBase path"); }
	this.base = this.cfg.base;
	// repoBase: folder of tw.html inside the repository (e.g. "vault/"). Used ONLY for GitHub API paths; fetches and local sinks stay relative to tw.html.
	this.rbase = this.cfg.repoBase;
	this.pageOrigin = originOf(deps.baseUrl);
	// A <base href> injected into the page changes document.baseURI (the usual baseUrl): never fetch from another origin than the page itself.
	var loc = typeof location !== "undefined" && location && location.origin;
	if(!this.pageOrigin || (loc && loc !== "null" && this.pageOrigin !== "null" && loc !== this.pageOrigin)) { throw new Error("base URL is not on the page's origin"); }
	this.blobShas = new Map();            // sha256 hex of an uploaded file -> git blob sha (survives failed commits: a rate-limited bulk save makes progress)
	this.entries = Object.create(null);   // title -> {c,p,r,h,s,f}
	this.counter = 0;                     // manifest counter our in-memory entries are based on
	this.pending = new Map();             // title -> {kind,title,path,blob,body,bodyEnc,fields,entry}   (= not yet published to GitHub)
	this.localDirty = new Map();          // path -> ciphertext blob | null (delete)                      (= not yet written to the local folder / zip)
	this.floor = 0;                       // highest manifest counter observed from the remote or the page (never raised by local-only bumps)
	this.localChain = Promise.resolve();  // saveLocal calls run strictly one after another
	try { this.protocol = new URL(deps.baseUrl).protocol; } catch(e) { this.protocol = ""; }
	this.blobCache = new Map();           // path -> {h,blob}: what we last wrote (served until Pages catches up)
	this.status = {pending: 0, localDirty: 0, lastCommit: null, error: null, state: "idle"};
	this.flushing = null; this.timer = null; this.firstQueued = 0; this.failures = 0; this.rollbackOk = false; this.counterKey = null;
	this.serial = Promise.resolve();      // save/remove run strictly in call order
	var self = this, dek = deps.dek;
	this.ready = F.deriveKeys(dek).then(function(k) {
		dek.fill(0); self.keys = k;
		return self.loadManifest();
	});
	this.ready.catch(function(e) { dek.fill(0); self.setStatus({error: "Init failed: " + (e && e.message), state: "error"}); });
}
Engine.prototype.setStatus = function(patch) {
	for(var k in patch) { this.status[k] = patch[k]; }
	this.status.pending = this.pending.size; this.status.localDirty = this.localDirty.size;
	if(this.d.onStatus) { this.d.onStatus(this.status); }
};
/* configured save targets (default: GitHub only, as before targets existed) */
Engine.prototype.targets = function() {
	try { var t = this.d.getTargets && this.d.getTargets(); return Array.isArray(t) ? t : ["github"]; } catch(e) { return ["github"]; }
};
Engine.prototype.localEnabled = function() { var t = this.targets(); return t.indexOf("folder") !== -1 || t.indexOf("zip") !== -1; };
Engine.prototype.exclusive = function(fn) {
	var p = this.serial.then(fn);
	this.serial = p.then(null,function() {});
	return p;
};
Engine.prototype.url = function(path) {
	var u = new URL(this.base + path,this.d.baseUrl);
	if(u.origin !== this.pageOrigin || u.username || u.password) { throw new Error("refusing cross-origin URL"); }
	return u.href;
};
/* Same-origin only, no redirects, hard size cap on the streamed body, overall timeout. */
Engine.prototype.fetchBytes = function(path,bust,max) {
	max = max || MAX_FILE_BYTES;
	var self = this, u;
	try { u = this.url(path) + (bust ? "?v=" + encodeURIComponent(bust) : ""); } catch(e) { return Promise.reject(e); }
	return G.request(this.d.fetch,u,{cache: "no-cache", credentials: "omit", referrerPolicy: "no-referrer", mode: "same-origin"},{max: max, timeoutMs: this.d.requestTimeoutMs || 120000}).then(function(r) {
		if(!r.res.ok) { throw new Error("HTTP " + r.res.status + " for encrypted file"); }
		if(r.res.url && originOf(r.res.url) !== self.pageOrigin) { throw new Error("response came from another origin"); }
		return r.bytes;
	},function(e) {
		throw new Error(/too large/.test(e && e.message) ? "encrypted file too large" : /timed out/.test(e && e.message) ? "encrypted file request timed out" : "encrypted file request failed");
	});
};
/* anti-rollback counter (highest manifest counter this browser has seen), per manifest path */
Engine.prototype.readSeen = function() {
	try { var v = parseInt(this.d.storage && this.d.storage.getItem(this.counterKey) || "0",10); return v > 0 ? v : 0; } catch(e) { return 0; }
};
Engine.prototype.writeSeen = function(n,force) {
	try { if(this.d.storage && (force || n > this.readSeen())) { this.d.storage.setItem(this.counterKey,String(n)); } } catch(e) {}
};
/* Validate an (authenticated) manifest and return Promise<{counter, map}> with sanitised copies of the entries. */
Engine.prototype.checkManifest = function(m) {
	var self = this, map = Object.create(null);
	if(!m || !Number.isSafeInteger(m.counter) || m.counter < 0 || !m.tiddlers || typeof m.tiddlers !== "object" || Array.isArray(m.tiddlers)) { return Promise.reject(new Error("corrupt manifest")); }
	var titles = Object.keys(m.tiddlers);
	if(titles.length > MAX_ENTRIES) { return Promise.reject(new Error("manifest too large")); }
	return Promise.all(titles.map(function(t) {
		var e = m.tiddlers[t];
		if(!e || typeof e !== "object" || typeof e.c !== "string" || typeof e.p !== "string" || !Number.isSafeInteger(e.r) || e.r < 0 || typeof e.h !== "string" || !HEX64_RE.test(e.h) ||
				!Number.isSafeInteger(e.s) || e.s < 0 || !e.f || typeof e.f !== "object" || Array.isArray(e.f)) { throw new Error("corrupt manifest entry"); }
		return F.filePath(self.keys,t,e.c).then(function(p) {
			if(p !== e.p || !G.PATH_RE.test(p)) { throw new Error("manifest entry path does not match its title"); }
			var f = {}, k;
			for(k in e.f) { if(Object.prototype.hasOwnProperty.call(e.f,k) && k !== "__proto__") { f[k] = e.f[k]; } }
			map[t] = {c: e.c, p: p, r: e.r, h: e.h, s: e.s, f: f};
		});
	})).then(function() { return {counter: m.counter, map: map}; });
};
Engine.prototype.loadManifest = function() {
	var self = this, mpath;
	function fetchOpen(bust) { return self.fetchBytes(mpath,bust,MAX_MANIFEST_BYTES).then(function(b) { return F.openManifest(self.keys,b); }); }
	return F.manifestPath(this.keys).then(function(p) {
		mpath = p; self.counterKey = COUNTER_KEY + p;
		if(self.cfg.manifest && self.cfg.manifest !== p) { throw new Error("manifest path does not match key"); }
		return fetchOpen().catch(function() { return fetchOpen(String(Date.now())); });   // CDN/cache skew retry
	}).then(function(m) {
		var seen = self.readSeen();
		if(m.counter >= seen) { return m; }
		// older than something this browser has already seen: maybe a stale CDN copy, so ask once more with a cache-buster
		return fetchOpen(String(Date.now())).then(function(m2) { return m2.counter > m.counter ? m2 : m; },function() { return m; });
	}).then(function(m) {
		return self.checkManifest(m).then(function(c) {
			var seen = self.readSeen(), fromRemote = self.protocol === "http:" || self.protocol === "https:";
			if(c.counter < seen) {
				self.setStatus({warning: "Manifest counter went backwards (" + c.counter + " < " + seen + "): " + (fromRemote ? "possible rollback or stale cache" : "this local copy is older than the last state seen on GitHub (stale folder?)")});
			} else if(fromRemote) {
				// only a counter served over http(s) (GitHub Pages) counts as an observation of the remote; a file:// copy may carry local-only bumps
				self.writeSeen(c.counter); self.floor = c.counter;
			}
			self.entries = c.map; self.counter = c.counter;
			self.setStatus({state: "ready"});
		});
	});
};
Engine.prototype.titles = function() { return Object.keys(this.entries); };
/* skinny field objects for the syncer */
Engine.prototype.skinny = function() {
	var out = [], t;
	for(t in this.entries) {
		var f = {}, k, src = this.entries[t].f;
		for(k in src) { if(Object.prototype.hasOwnProperty.call(src,k)) { f[k] = src[k]; } }
		f.title = t; f.revision = String(this.entries[t].r); f._is_skinny = "";
		out.push(f);
	}
	return out;
};
Engine.prototype.entrySize = function(t) { return this.entries[t] ? this.entries[t].s : 0; };

Engine.prototype.cacheBlob = function(path,h,blob) {
	this.blobCache.delete(path); this.blobCache.set(path,{h: h, blob: blob});
	var total = 0, self = this;
	this.blobCache.forEach(function(v) { total += v.blob.length; });
	this.blobCache.forEach(function(v,p) {   // evict oldest first; never the file we just stored
		if(total > CACHE_BYTES && p !== path) { total -= v.blob.length; self.blobCache.delete(p); }
	});
};
/* The ciphertext of an entry: our own cache, else fetched from the page's origin and verified against the manifest hash. */
Engine.prototype.entryBlob = function(e) {
	var self = this, cached = this.blobCache.get(e.p);
	if(cached && cached.h === e.h) { return Promise.resolve(cached.blob); }
	return this.fetchBytes(e.p,undefined,e.s + 64).then(function(b) {
		return F.sha256Hex(b).then(function(h) {
			if(h === e.h) { return b; }
			return self.fetchBytes(e.p,e.h,e.s + 64).then(function(b2) {   // cache-busted retry
				return F.sha256Hex(b2).then(function(h2) { if(h2 !== e.h) { throw new Error("integrity check failed"); } return b2; });
			});
		});
	});
};
Engine.prototype.load = function(title) {
	var self = this;
	return this.ready.then(function() {
		var e = self.entries[title];
		if(!e) { throw new Error("unknown tiddler"); }
		var getBlob = self.entryBlob(e);
		return getBlob.then(function(blob) { return F.openTiddler(self.keys,title,blob,e.r); }).then(function(o) {
			var f = {}, k;
			for(k in o.fields) { if(Object.prototype.hasOwnProperty.call(o.fields,k) && k !== "__proto__") { f[k] = o.fields[k]; } }
			f.title = title; f.revision = String(e.r);
			f.text = o.bodyEnc === "base64" ? F.b64encode(o.body) : F.utf8decode(o.body);
			delete f._is_skinny;
			return f;
		});
	});
};

Engine.prototype.categoryOf = function(title,fields) {
	if(title.indexOf("$:/") === 0) { return "sys"; }
	var tags = [], re = /\[\[(.*?)\]\]|(\S+)/g, m, s = fields.tags || "";
	while((m = re.exec(s))) { tags.push(m[1] !== undefined ? m[1] : m[2]); }
	var order = this.d.categoryOrder ? this.d.categoryOrder() : [], i;
	for(i=0; i<order.length; i++) { if(tags.indexOf(order[i]) !== -1) { return order[i]; } }
	if(tags.length) { return tags[0]; }
	return this.d.isBase64Type(fields.type) ? "media" : "misc";
};

/* fieldStrings: all fields as strings incl. text. Returns Promise<revision string>. Resolves once sealed+queued (not committed). */
Engine.prototype.save = function(title,fieldStrings) {
	var self = this;
	return this.exclusive(function() { return self.ready.then(function() {
		if(typeof title !== "string" || !title) { throw new Error("invalid title"); }
		var f = {}, k, text = fieldStrings.text === undefined ? "" : fieldStrings.text;
		for(k in fieldStrings) { if(Object.prototype.hasOwnProperty.call(fieldStrings,k) && k !== "text" && k !== "revision" && k !== "_is_skinny" && k !== "__proto__") { f[k] = fieldStrings[k]; } }
		var body, bodyEnc = "utf8";
		if(self.d.isBase64Type(f.type)) {
			try { var raw = F.b64decode(text); if(F.b64encode(raw) === text) { body = raw; bodyEnc = "base64"; } } catch(e) {}
		}
		if(!body) { body = F.utf8encode(text); }
		var old = self.entries[title], rev = old ? old.r + 1 : 1, cat = self.categoryOf(title,f);
		if(body.length > MAX_FILE_BYTES - 1048576) { throw new Error("tiddler too large to store (limit " + ((MAX_FILE_BYTES >> 20) - 1) + " MiB)"); }   // it could never be read back
		return F.filePath(self.keys,title,cat).then(function(path) {
			return F.sealTiddler(self.keys,title,f,body,bodyEnc,rev).then(function(blob) {
				return F.sha256Hex(blob).then(function(h) {
					var entry = {c: cat, p: path, r: rev, h: h, s: blob.length, f: f};
					self.pending.set(title,{kind: "save", title: title, path: path, blob: blob, body: body, bodyEnc: bodyEnc, fields: f, entry: entry});
					self.entries[title] = entry; self.cacheBlob(path,h,blob);
						self.localDirty.set(path,blob);
						if(old && old.p !== path) { self.localDirty.set(old.p,null); }   // category move: the old file goes away locally too
					self.queued();
					return String(rev);
				});
			});
		});
	}); });
};
Engine.prototype.remove = function(title) {
	var self = this;
	return this.exclusive(function() { return self.ready.then(function() {
		var old = self.entries[title], prev = self.pending.get(title);
		if(!old && !prev) { return; }
		var p = old ? old.p : prev.path;
		self.pending.set(title,{kind: "delete", title: title, path: p, blob: null, entry: null});
		delete self.entries[title]; self.blobCache.delete(p);
			self.localDirty.set(p,null);
		self.queued();
	}); });
};
Engine.prototype.queued = function(keepState,minWait) {
	var self = this, now = Date.now();
	if(!this.firstQueued) { this.firstQueued = now; }
	this.setStatus(keepState ? {} : {state: "pending"});
	if(this.timer) { (this.d.clearTimeout || clearTimeout)(this.timer); }
	var wait = Math.min(this.d.debounceMs || 5000,Math.max(0,this.firstQueued + (this.d.maxWaitMs || 20000) - now));
	if(this.failures) { wait = Math.min(300000,(this.d.debounceMs || 5000) * Math.pow(2,Math.min(this.failures,6))); }   // exponential back-off after errors
	if(minWait > wait) { wait = minWait; }   // server-requested pause (Retry-After / rate limit) beats our own back-off
	this.timer = (this.d.setTimeout || setTimeout)(function() {
		self.timer = null;
		var p; try { p = self.d.autoSave ? self.d.autoSave(self) : self.flush(); } catch(e) { p = null; }
		Promise.resolve(p).catch(function() {});
	},wait);
};
/* Explicit user override after a "remote rolled back" refusal: the next commit rebuilds on whatever the repo holds now. */
Engine.prototype.acceptRollback = function() {
	this.rollbackOk = true; this.counter = 0; this.failures = 0;
	if(this.pending.size) { this.queued(); }
};

/* Publish pending changes to GitHub in ONE git commit; resolves when done (or immediately if nothing is pending).
   flush({force:true}) runs the reconcile/merge even when nothing is pending and creates no commit if the diff is empty. */
Engine.prototype.flush = function(opts) {
	var self = this, force = !!(opts && opts.force);
	if(this.flushing) { return this.flushing.then(function() { return (self.pending.size || force) ? self.flush(opts) : undefined; }); }
	if(!this.pending.size && !force) { return Promise.resolve(); }
	this.firstQueued = 0;
	if(this.timer) { (this.d.clearTimeout || clearTimeout)(this.timer); this.timer = null; }
	this.flushing = this.ready.then(function() { return self.doFlush(3,force); }).then(function(r) {
		self.flushing = null; self.failures = 0;
		var patch = {state: self.pending.size ? "pending" : "ready", error: /^Local save failed/.test(self.status.error || "") ? self.status.error : null, warning: null, info: null};
		if(r && r.committed) { patch.lastCommit = new Date().toISOString(); }
		self.setStatus(patch);
		if(self.pending.size) { self.queued(); }
		return r;
	},function(e) {
		self.flushing = null;
		self.setStatus({state: "error", error: (e && e.message) || "commit failed"});
		if(!(e && e.fatal)) { self.failures++; if(self.pending.size) { self.queued(true,e && e.retryAfterMs); } }   // retry with back-off; fatal (rollback) waits for acceptRollback()
		throw e;
	});
	return this.flushing;
};
/* If another device already committed this title at an equal/higher revision, re-seal our version above it (rev is bound into the AAD). */
Engine.prototype.ensureRev = function(op,prior) {
	var self = this, e = op.entry;
	if(op.kind !== "save" || !prior || e.r > prior.r || (e.r === prior.r && e.h === prior.h)) { return Promise.resolve(); }
	var rev = prior.r + 1;
	return F.sealTiddler(this.keys,op.title,op.fields,op.body,op.bodyEnc,rev).then(function(blob) {
		return F.sha256Hex(blob).then(function(h) {
			op.blob = blob; e.r = rev; e.h = h; e.s = blob.length;
			self.cacheBlob(op.path,h,blob);
			self.localDirty.set(op.path,blob);   // the local copy of this file is now outdated too
		});
	});
};
/* Same for an entry that is NOT pending (it came from the local copy): decrypt it and seal it again at a higher revision. */
Engine.prototype.resealEntry = function(title,e,rev) {
	var self = this;
	return this.entryBlob(e).then(function(blob) { return F.openTiddler(self.keys,title,blob,e.r); }).then(function(o) {
		return F.sealTiddler(self.keys,title,o.fields,o.body,o.bodyEnc,rev);
	}).then(function(blob) {
		return F.sha256Hex(blob).then(function(h) {
			e.r = rev; e.h = h; e.s = blob.length;
			self.cacheBlob(e.p,h,blob);
			self.localDirty.set(e.p,blob);
		});
	});
};
/* Plan A (remote.counter >= this.counter): start from the remote manifest (other devices' changes), overlay our batch (last writer wins per tiddler). */
Engine.prototype.planOverlay = function(rmap,batch) {
	var self = this, ops = []; batch.forEach(function(op) { ops.push(op); });
	return Promise.all(ops.map(function(op) { return self.ensureRev(op,rmap[op.title]); })).then(function() {
		var merged = Object.create(null), t, deletions = [], uploads = [];
		for(t in rmap) { merged[t] = rmap[t]; }
		batch.forEach(function(op,title) {
			var prior = rmap[title];
			if(prior && (op.kind === "delete" || prior.p !== op.entry.p)) { deletions.push(prior.p); }   // only files the authoritative manifest knows about
			if(op.kind === "save") { merged[title] = op.entry; uploads.push({path: op.entry.p, blob: op.blob, key: op.entry.h}); }
			else { delete merged[title]; }
		});
		return {merged: merged, uploads: uploads, deletions: deletions, batch: batch, reconcile: false, empty: batch.size === 0};
	});
};
/* Plan B (remote empty or remote.counter < this.counter, i.e. local is ahead): make the remote equal to the local state.
   Upload every local entry whose remote entry is missing or has another hash, delete remote entries that are gone locally
   (paths come from the authenticated remote manifest only). */
Engine.prototype.planReconcile = function(rmap) {
	var self = this, local = Object.create(null), t, batch = new Map(this.pending), ops = [];
	for(t in this.entries) { local[t] = this.entries[t]; }   // snapshot: edits made while we talk to GitHub stay pending for the next round
	batch.forEach(function(op) { ops.push(op); });
	return Promise.all(ops.map(function(op) { return self.ensureRev(op,rmap[op.title]); })).then(function() {
		var re = [];
		for(t in local) {
			var e = local[t], prior = rmap[t], op = batch.get(t);
			if(prior && prior.h !== e.h && e.r <= prior.r && !(op && op.kind === "save")) { re.push(t); }
		}
		return Promise.all(re.map(function(title) { return self.resealEntry(title,local[title],rmap[title].r + 1); }));
	}).then(function() {
		var uploads = [], deletions = [];
		for(t in local) {
			var e = local[t], prior = rmap[t], op = batch.get(t);
			if(!prior || prior.h !== e.h || prior.p !== e.p) {
				uploads.push({path: e.p, blob: op && op.kind === "save" && op.entry === e ? op.blob : null, key: e.h, entry: e});
				if(prior && prior.p !== e.p) { deletions.push(prior.p); }
			}
		}
		for(t in rmap) { if(!local[t]) { deletions.push(rmap[t].p); } }
		return {merged: local, uploads: uploads, deletions: deletions, batch: batch, reconcile: true};
	});
};
Engine.prototype.doFlush = function(attempts,force) {
	var self = this, token = this.d.getToken(), gh;
	if(!token) { return Promise.reject(new Error("GitHub token missing: enter it in Control Panel > Saving > GitHub")); }
	try { gh = new G.Client({repo: this.cfg.repo, branch: this.cfg.branch, apiBase: this.cfg.apiBase, token: token, fetch: this.d.fetch, timeoutMs: this.d.requestTimeoutMs}); } catch(e) { return Promise.reject(e); }
	var head, manifestPath, remote, remoteEmpty = false, plan, newCounter;
	return F.manifestPath(this.keys).then(function(mp) {
		manifestPath = mp;
		return gh.getHead();
	}).then(function(h) {
		head = h;
		return gh.getRaw(self.rbase + self.base + manifestPath,head.commit,MAX_MANIFEST_BYTES).then(function(b) {
			if(b.byteLength > MAX_MANIFEST_BYTES) { throw new Error("manifest too large"); }
			return F.openManifest(self.keys,new Uint8Array(b));
		},function(e) {
			// The branch exists (we just read its commit) but holds no manifest: a fresh repository. That is "remote empty", not a rollback.
			if(e && e.status === 404) { remoteEmpty = true; self.setStatus({info: "repository has no manifest yet: it will be seeded from your local files"}); return null; }
			throw e;
		});
	}).then(function(rm) {
		return rm ? self.checkManifest(rm) : {counter: 0, map: Object.create(null)};
	}).then(function(rc) {
		remote = rc;
		// Floor = highest counter seen from the remote / the page. NOT this.counter: local-only saves raise that without anyone having seen it remotely.
		var floor = Math.max(self.floor,self.protocol === "file:" ? 0 : self.readSeen());   // file:// profiles (e.g. a temp --user-data-dir) keep stale counters from older builds: not evidence of a rollback
		if(rc.counter < floor && !self.rollbackOk) {
			var err = new Error(remoteEmpty ? "Repository holds no manifest although one with counter " + floor + " was seen before: deleted or rolled back; refusing to publish onto it. If intended, run $tw.encSync.acceptRollback()"
				: "Repository manifest counter went backwards (" + rc.counter + " < " + floor + "): possible rollback; refusing to commit on top of it. If intended, run $tw.encSync.acceptRollback()");
			err.fatal = true; throw err;
		}
		// local ahead (or nothing there at all) => fast-forward the remote to our state; equal/higher remote counter => overlay merge
		return (remoteEmpty || rc.counter < self.counter) ? self.planReconcile(rc.map) : self.planOverlay(rc.map,new Map(self.pending));
	}).then(function(pl) {
		plan = pl;
		var uploads = pl.uploads, merged = pl.merged, t, keep = {}, uniq = {}, deletions;
		newCounter = Math.max(remote.counter,self.counter) + 1;
		keep[manifestPath] = 1;
		uploads.forEach(function(u) { keep[u.path] = 1; });
		for(t in merged) { keep[merged[t].p] = 1; }
		// never delete a path that is written in this commit or that any surviving entry still references
		deletions = pl.deletions.filter(function(p) { if(keep[p] || uniq[p]) { return false; } uniq[p] = 1; return true; });
		if(pl.reconcile ? (!uploads.length && !deletions.length) : pl.empty) {
			// nothing to publish: no commit. Whatever was pending is already what the remote holds.
			pl.batch.forEach(function(op,title) { if(pl.reconcile && self.pending.get(title) === op) { self.pending.delete(title); } });
			if(remote.counter > 0) { self.floor = Math.max(self.floor,remote.counter); self.writeSeen(remote.counter); }
			return {committed: false};
		}
		return F.sealManifest(self.keys,{v: 1, counter: newCounter, tiddlers: merged}).then(function(mblob) {
			var all = uploads.concat([{path: manifestPath, blob: mblob}]);
			var shas = [], i = 0, failed = false;
			function worker() {
				if(failed || i >= all.length) { return Promise.resolve(); }
				var u = all[i++];
				var known = u.key && self.blobShas.get(u.key);   // already uploaded by an earlier (rate-limited / failed) attempt
				if(known) { shas.push({path: self.rbase + self.base + u.path, sha: known}); return worker(); }
				// bytes: the pending op / cache, else the local copy fetched from the page's origin and verified against its manifest hash
				var bytes = u.blob ? Promise.resolve(u.blob) : self.entryBlob(u.entry).then(null,function(e) {
					throw new Error("Cannot publish: a local encrypted file is missing or corrupt (" + String(e && e.message).replace(/[^\x20-\x7e]/g," ").substr(0,100) + "). Save the wiki locally again or restore the folder.");
				});
				return bytes.then(function(b) { return gh.createBlob(b); }).then(function(sha) {
					if(u.key) { if(self.blobShas.size >= 20000) { self.blobShas.clear(); } self.blobShas.set(u.key,sha); }
					shas.push({path: self.rbase + self.base + u.path, sha: sha}); return worker();
				},function(e) { failed = true; throw e; });
			}
			var workers = []; for(var w=0; w<Math.min(MAX_PARALLEL,all.length); w++) { workers.push(worker()); }
			return Promise.all(workers).then(function() {
				var entries = shas.concat(deletions.map(function(p) { return {path: self.rbase + self.base + p, sha: null}; }));
				return gh.commit(head,entries,"Update");
			}).then(function() {
				// success: adopt the merged view, then re-apply anything queued while we were committing
				pl.batch.forEach(function(op,title) {
					if(self.pending.get(title) === op) { self.pending.delete(title); }
				});
				if(pl.reconcile || !self.localEnabled()) {
					var cur2 = Object.create(null), k;
					for(k in merged) { cur2[k] = merged[k]; }
					self.pending.forEach(function(op,title) { if(op.kind === "save") { cur2[title] = op.entry; } else { delete cur2[title]; } });
					self.entries = cur2;
				}   // else: local-first mode - the local copy stays the master; other devices' tiddlers are preserved in the commit but not pulled in (their files are not in the local folder)
				self.counter = newCounter; self.floor = newCounter; self.rollbackOk = false;
				self.writeSeen(newCounter,true);
				return {committed: true};
			});
		});
	}).catch(function(e) {
		if(e && e.status === 422) { self.blobShas.clear(); }   // maybe a cached blob was garbage-collected server side: upload everything again
		if(attempts > 1 && e && (e.status === 422 || e.status === 409)) { return self.doFlush(attempts - 1,force); }   // lost the ref race: re-fetch head, re-merge
		throw e;
	});
};

/* ---- local targets ------------------------------------------------------------------------------------------------------------- */
/* manifest file path relative to the folder that holds tw.html */
Engine.prototype.manifestFile = function() {
	var self = this;
	return this.ready.then(function() { return F.manifestPath(self.keys); }).then(function(p) { return self.base + p; });
};
/* Everything the sink needs, taken atomically with respect to save()/remove(). Resolves null when there is nothing to write. */
Engine.prototype.localSnapshot = function(opts) {
	var self = this;
	return this.exclusive(function() { return self.ready.then(function() {
		if(!self.localDirty.size && !opts.full && !opts.force) { return null; }
		var snap = new Map(self.localDirty), ent = Object.create(null), t, counter = Math.max(self.counter,self.floor) + 1;   // never below what was seen remotely (acceptRollback() resets this.counter)
		for(t in self.entries) { ent[t] = self.entries[t]; }
		return F.manifestPath(self.keys).then(function(mp) {
			return F.sealManifest(self.keys,{v: 1, counter: counter, tiddlers: ent}).then(function(mblob) {
				var keep = {}, files = [], removals = [], written = {}, extra = [];
				keep[mp] = 1;
				for(t in ent) { keep[ent[t].p] = 1; }
				snap.forEach(function(blob,p) {
					if(blob) { files.push({path: self.base + p, bytes: blob}); written[p] = 1; }
					else if(!keep[p]) { removals.push(self.base + p); }
				});
				if(opts.full) { for(t in ent) { if(!written[ent[t].p]) { extra.push(ent[t]); } } }
				return Promise.all(extra.map(function(e) { return self.entryBlob(e).then(function(b) { files.push({path: self.base + e.p, bytes: b}); }); })).then(function() {
					return {snap: snap, counter: counter, plan: {counter: counter, files: files, manifest: {path: self.base + mp, bytes: mblob}, removals: removals}};
				});
			});
		});
	}); });
};
/* Write the pending local changes (changed/new files, a new manifest with counter+1, deletions) through a sink (see localsink.js);
   `sink` may be an array: every sink gets the same plan, localDirty is cleared only when ALL succeeded (the first error is thrown).
   opts: {interactive (default true: the sink may show a picker/permission prompt), full (rewrite every file), force (even if nothing changed)}.
   Success clears localDirty; failure leaves everything as it was (counter unchanged) and sets status.error. */
Engine.prototype.saveLocal = function(sink,opts) {
	var self = this; opts = opts || {};
	function run() {
		return self.localSnapshot(opts).then(function(s) {
			if(!s) { return {skipped: true}; }
			var sinks = Array.isArray(sink) ? sink : [sink], errs = [], results = [], chain = Promise.resolve();
			sinks.forEach(function(sk) {
				chain = chain.then(function() { return sk.write(s.plan,{interactive: opts.interactive !== false}); }).then(function(r) { results.push(r); },function(e) { errs.push(e); });
			});
			return chain.then(function() { if(errs.length) { throw errs[0]; } return sinks.length === 1 ? results[0] : results; }).then(function(r) {
				s.snap.forEach(function(blob,p) { if(self.localDirty.has(p) && self.localDirty.get(p) === blob) { self.localDirty.delete(p); } });
				self.counter = Math.max(self.counter,s.counter);
				self.setStatus({error: /^Local save failed/.test(self.status.error || "") ? null : self.status.error, lastLocalSave: new Date().toISOString()});
				return {saved: true, counter: s.counter, result: r};
			});
		}).then(null,function(e) {
			var msg = "Local save failed: " + String(e && e.message || "error").replace(/[^\x20-\x7e -￿]/g," ").substr(0,300);
			self.setStatus({error: msg});
			var err = new Error(msg); if(e && e.code) { err.code = e.code; }
			throw err;
		});
	}
	var p = this.localChain.then(run,run);
	this.localChain = p.then(null,function() {});
	return p;
};
exports.Engine = Engine;
})();
