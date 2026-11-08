/*\
title: $:/plugins/tw-enc-sync/github.js
type: application/javascript
module-type: library

Minimal GitHub Git Data API client (fast-forward-only commits of many files at once).
The token is held only in this object's closure and only ever sent in the Authorization header.

\*/
(function(){
"use strict";

var REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, BRANCH_RE = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;
var TOKEN_RE = /^[\x21-\x7e]{1,500}$/, SHA_RE = /^[0-9a-f]{40}$/;
/* https API base (github.com or GHES "/api/v3"): no userinfo/query/dot segments; plain http only for loopback (tests). */
var API_RE = /^https:\/\/[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/, API_LOCAL_RE = /^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$/;
function dotted(s) { return s.split("/").some(function(x) { return x === "." || x === ".." || x === ".git"; }); }   // repo name / branch segments
var PATH_RE = /^(?:[A-Za-z0-9_-]+\/)*(?:[0-9a-f]{12}\/[0-9a-f]{32}\.bin|m\/[0-9a-f]{32}\.bin)$/;
/* Plaintext blog posts (publish.js). A SEPARATE allowlist: never mixed with ciphertext paths in one commit. Keep in sync with publish.js. */
var PUB_PATH_RE = /^content\/blog\/[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\/(?:index(?:\.de)?\.md|[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\.(?:webp|png|jpe?g))$/;
var PUB_DIR_RE = /^content\/blog\/[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/;

function GitHubError(status,msg,retryAfterMs,step) { this.name = "GitHubError"; this.status = status; this.message = msg; if(retryAfterMs) { this.retryAfterMs = retryAfterMs; } if(step) { this.step = step; } }
GitHubError.prototype = Object.create(Error.prototype);

/* Fixed, human-readable hints (never built from server text or the token). GitHub answers 404 (not 403) for a private repository
   the token cannot see, and a fine-grained token only works for repositories it was created for, so "Not Found" on any step usually
   means "wrong repo/branch name or this token has no access to this repository". */
var PERMS = "a fine-grained token needs this repository selected, with Contents: read & write and Metadata: read";
function hintFor(status,step,msg) {
	if(status === 401) { return "token rejected (wrong, revoked or expired); enter a new one in Control Panel > Saving > GitHub"; }
	if(status === 403) { return "permission denied: check that " + PERMS; }
	if(status === 404) {
		if(step === "read manifest at head") { return "repository has no manifest yet: it will be seeded from your local files"; }
		if(step === "read ref") { return "branch not found or repository not visible to this token (or the repository is empty): check repo and branch, and that " + PERMS; }
		if(step === "read commit") { return "commit not readable with this token (GitHub reports missing permission as 404): check that " + PERMS + "; also check that the branch was not just deleted or force-pushed"; }
		return "repository not found or not writable with this token: check that " + PERMS;
	}
	if(status === 409 && /empty/i.test(msg || "")) { return "the repository is empty: create an initial commit (for example upload tw.html) first"; }
	return "";
}

var MAX_API_BYTES = 8 * 1048576, ERR_BYTES = 65536, DEFAULT_TIMEOUT_MS = 60000, MAX_RETRY_MS = 3600000;
var utf8 = new TextDecoder("utf-8");   // lenient: used for diagnostics / JSON text only

/* Read a response body with a hard byte cap that also holds for chunked / content-length-less / lying responses.
   truncate:true => return what fits instead of failing (used for error bodies). Resolves Uint8Array. */
function readBody(res,max,truncate) {
	var len = parseInt((res.headers && res.headers.get && res.headers.get("content-length")) || "0",10);
	function cancel() { try { var p = res.body && res.body.cancel && res.body.cancel(); if(p && p.catch) { p.catch(function() {}); } } catch(e) {} }
	if(len > max && !truncate) { cancel(); return Promise.reject(new Error("response too large")); }
	if(!res.body || typeof res.body.getReader !== "function") {   // no streaming API: best effort
		return res.arrayBuffer().then(function(b) {
			if(b.byteLength > max) { if(truncate) { return new Uint8Array(b,0,max); } throw new Error("response too large"); }
			return new Uint8Array(b);
		});
	}
	var reader = res.body.getReader(), chunks = [], total = 0;
	function finish() {
		var out = new Uint8Array(total), p = 0;
		for(var i=0; i<chunks.length; i++) { out.set(chunks[i],p); p += chunks[i].length; }
		return out;
	}
	function pump() {
		return reader.read().then(function(r) {
			if(r.done) { return finish(); }
			var v = r.value;
			if(total + v.length > max) {
				try { reader.cancel().catch(function() {}); } catch(e) {}
				if(!truncate) { throw new Error("response too large"); }
				chunks.push(v.subarray(0,max - total)); total = max; return finish();
			}
			chunks.push(v); total += v.length;
			return pump();
		});
	}
	return pump();
}
/* One bounded request: never follows redirects (so an Authorization header can never be forwarded anywhere and a POST can
   never be silently downgraded to a GET), aborts after timeoutMs (covers the body as well, so a slow-drip server cannot
   hang the caller), caps the body size. o: {max, timeoutMs}. Resolves {res, bytes}; an error status gets <=64 KiB of body. */
function request(fetchImpl,url,init,o) {
	var ctl = typeof AbortController === "function" ? new AbortController() : null, timer, guard;
	init.redirect = "error";
	if(ctl) { init.signal = ctl.signal; }
	guard = new Promise(function(resolve,reject) {
		timer = setTimeout(function() { try { if(ctl) { ctl.abort(); } } catch(e) {} reject(new Error("request timed out")); },o.timeoutMs || DEFAULT_TIMEOUT_MS);
	});
	var work = Promise.resolve().then(function() { return fetchImpl(url,init); }).then(function(res) {
		if(res.redirected || res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) { throw new Error("unexpected redirect"); }
		return readBody(res,res.ok ? o.max : ERR_BYTES,!res.ok).then(function(bytes) { return {res: res, bytes: bytes}; });
	});
	return Promise.race([work,guard]).then(function(r) { clearTimeout(timer); return r; },function(e) { clearTimeout(timer); try { if(ctl) { ctl.abort(); } } catch(e2) {} throw e; });
}
/* Retry-After (seconds or HTTP date) or an exhausted primary rate limit (X-RateLimit-Reset) => ms to wait, clamped to [1 s, 1 h]. */
function retryDelay(res,now) {
	var h = function(n) { return res.headers && res.headers.get && res.headers.get(n); }, ra = h("retry-after"), ms = 0;
	if(ra) {
		if(/^\d{1,9}$/.test(ra.trim())) { ms = parseInt(ra,10) * 1000; } else { var d = Date.parse(ra); if(!isNaN(d)) { ms = d - now; } }
	} else if(h("x-ratelimit-remaining") === "0" && /^\d{1,12}$/.test(h("x-ratelimit-reset") || "")) {
		ms = parseInt(h("x-ratelimit-reset"),10) * 1000 - now;
	}
	if(!(ms > 0)) { return 0; }
	return Math.min(MAX_RETRY_MS,Math.max(1000,ms));
}

function b64(bytes) {
	var s = "", CH = 0x8000;
	for(var i=0; i<bytes.length; i+=CH) { s += String.fromCharCode.apply(null,bytes.subarray(i,i+CH)); }
	return btoa(s);
}

function Client(opts) {
	if(typeof opts.repo !== "string" || !REPO_RE.test(opts.repo) || dotted(opts.repo)) { throw new Error("invalid repo name"); }
	if(typeof opts.branch !== "string" || opts.branch.length > 100 || !BRANCH_RE.test(opts.branch) || dotted(opts.branch) || opts.branch.indexOf("..") !== -1 || /\.lock(?:\/|$)/.test(opts.branch)) { throw new Error("invalid branch name"); }
	if(typeof opts.apiBase !== "string" || (!API_RE.test(opts.apiBase) && !API_LOCAL_RE.test(opts.apiBase))) { throw new Error("invalid api base"); }
	var token = typeof opts.token === "string" ? opts.token.trim() : "";
	if(!TOKEN_RE.test(token)) { throw new Error("GitHub token missing or contains invalid characters"); }   // never echo the value
	var fetchImpl = opts.fetch || globalThis.fetch.bind(globalThis), timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
	this.repo = opts.repo; this.branch = opts.branch;
	var self = this;
	function clean(t) {   // GitHub's message is shown in the UI: printable ASCII only, no markup/wikitext metacharacters, never the token
		return String(t).split(token).join("***").replace(/[^\x20-\x7e]/g," ").replace(/[<>{}\[\]|$`\\"&%]/g,"?").substr(0,200);
	}
	this.api = function(method,path,body,accept,max,step) {
		var label = step ? " (step: " + step + ")" : "";
		var headers = {"Authorization": "Bearer " + token, "Accept": accept || "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"};
		var init = {method: method, headers: headers, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer"};
		if(body !== undefined) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
		var raw = !!(accept && accept.indexOf("raw") !== -1);
		return request(fetchImpl,opts.apiBase + "/repos/" + self.repo + path,init,{max: max || MAX_API_BYTES, timeoutMs: timeoutMs}).then(function(r) {
			var res = r.res;
			if(!res.ok) {
				// Never echo response headers that could contain request data; status + a sanitised GitHub message only
				var m = ""; try { m = clean(JSON.parse(utf8.decode(r.bytes)).message || ""); } catch(e) {}
				var wait = (res.status === 429 || res.status === 403 || res.status === 503) ? retryDelay(res,Date.now()) : 0;
				if(!wait && (res.status === 429 || (res.status === 403 && /rate limit|abuse/i.test(m)))) { wait = 60000; }   // secondary limit without a header: GitHub says wait >= 1 min
				var hint = wait ? "" : hintFor(res.status,step,m);
				throw new GitHubError(res.status,"GitHub API " + method + " " + res.status + label + (m ? ": " + m : "") + (hint ? ". Hint: " + hint : ""),wait,step);
			}
			if(raw) { return r.bytes.buffer.slice(r.bytes.byteOffset,r.bytes.byteOffset + r.bytes.byteLength); }
			if(res.status === 204 || !r.bytes.length) { return null; }
			return JSON.parse(utf8.decode(r.bytes));
		}).catch(function(e) {
			if(e instanceof GitHubError) { throw e; }
			throw new GitHubError(0,"GitHub API " + method + " failed" + label + " (network, redirect, size or response error)",0,step);   // drop the original message: it may quote request headers
		});
	};
}
Client.prototype.getHead = function() {
	var self = this;
	return this.api("GET","/git/ref/heads/" + this.branch.split("/").map(encodeURIComponent).join("/"),undefined,undefined,undefined,"read ref").then(function(ref) {
		var sha = ref && ref.object && ref.object.sha;
		if(typeof sha !== "string" || !SHA_RE.test(sha)) { throw new GitHubError(0,"unexpected ref response"); }
		return self.api("GET","/git/commits/" + sha,undefined,undefined,undefined,"read commit").then(function(c) {
			var tree = c && c.tree && c.tree.sha;
			if(typeof tree !== "string" || !SHA_RE.test(tree)) { throw new GitHubError(0,"unexpected commit response"); }
			return {commit: sha, tree: tree};
		});
	});
};
Client.prototype.getRaw = function(path,ref,max) {
	if(!PATH_RE.test(path)) { return Promise.reject(new Error("refusing unexpected path")); }
	if(!SHA_RE.test(ref)) { return Promise.reject(new Error("refusing unexpected ref")); }
	return this.api("GET","/contents/" + path.split("/").map(encodeURIComponent).join("/") + "?ref=" + encodeURIComponent(ref),undefined,"application/vnd.github.raw+json",max,"read manifest at head");
};
Client.prototype.createBlob = function(bytes) {
	return this.api("POST","/git/blobs",{content: b64(bytes), encoding: "base64"},undefined,undefined,"create blob").then(function(r) {
		if(!r || typeof r.sha !== "string" || !SHA_RE.test(r.sha)) { throw new GitHubError(0,"unexpected blob response"); }
		return r.sha;
	});
};
/* entries: [{path, sha|null}] */
Client.prototype.commit = function(head,entries,message) {
	var self = this;
	if(!SHA_RE.test(head.commit) || !SHA_RE.test(head.tree)) { return Promise.reject(new Error("refusing unexpected head")); }
	try { entries.forEach(function(e) { if(!PATH_RE.test(e.path)) { throw new Error("refusing unexpected path"); } }); } catch(e) { return Promise.reject(e); }
	return this.api("POST","/git/trees",{base_tree: head.tree, tree: entries.map(function(e) { return {path: e.path, mode: "100644", type: "blob", sha: e.sha}; })},undefined,undefined,"create tree").then(function(t) {
		return self.api("POST","/git/commits",{message: message, tree: t.sha, parents: [head.commit]},undefined,undefined,"create commit");
	}).then(function(c) {
		if(!c || typeof c.sha !== "string" || !SHA_RE.test(c.sha)) { throw new GitHubError(0,"unexpected commit response"); }
		return self.api("PATCH","/git/refs/heads/" + self.branch.split("/").map(encodeURIComponent).join("/"),{sha: c.sha, force: false},undefined,undefined,"update ref").then(function() { return {commit: c.sha, tree: c.tree && c.tree.sha}; });
	});
};
/* --- plaintext publishing (publish.js) ------------------------------------------------------------------------------------- */
/* sha of a published file at ref, or null if absent. */
Client.prototype.getContentSha = function(path,ref) {
	if(!PUB_PATH_RE.test(path)) { return Promise.reject(new Error("refusing unexpected path")); }
	if(!SHA_RE.test(ref)) { return Promise.reject(new Error("refusing unexpected ref")); }
	return this.api("GET","/contents/" + path.split("/").map(encodeURIComponent).join("/") + "?ref=" + encodeURIComponent(ref),undefined,undefined,1048576,"read published file").then(function(r) {
		var sha = r && r.sha;
		if(typeof sha !== "string" || !SHA_RE.test(sha) || r.type !== "file") { throw new GitHubError(0,"unexpected contents response"); }
		return sha;
	},function(e) { if(e && e.status === 404) { return null; } throw e; });
};
/* paths of the files in a post folder at ref ([] if absent). */
Client.prototype.listDir = function(dir,ref) {
	if(!PUB_DIR_RE.test(dir)) { return Promise.reject(new Error("refusing unexpected folder")); }
	if(!SHA_RE.test(ref)) { return Promise.reject(new Error("refusing unexpected ref")); }
	return this.api("GET","/contents/" + dir.split("/").map(encodeURIComponent).join("/") + "?ref=" + encodeURIComponent(ref),undefined,undefined,1048576,"list post folder").then(function(r) {
		if(!Array.isArray(r)) { throw new GitHubError(0,"unexpected contents response"); }
		return r.filter(function(x) { return x && x.type === "file" && typeof x.path === "string"; }).map(function(x) { return x.path; });
	},function(e) { if(e && e.status === 404) { return []; } throw e; });
};
/* Commit plaintext post files only (entries: [{path, sha|null}]); the ciphertext allowlist is NOT accepted here and vice versa. */
Client.prototype.commitPlain = function(head,entries,message) {
	var self = this;
	if(!SHA_RE.test(head.commit) || !SHA_RE.test(head.tree)) { return Promise.reject(new Error("refusing unexpected head")); }
	if(!entries.length) { return Promise.reject(new Error("nothing to commit")); }
	try { entries.forEach(function(e) { if(!PUB_PATH_RE.test(e.path) || PATH_RE.test(e.path)) { throw new Error("refusing unexpected path"); } }); } catch(e) { return Promise.reject(e); }
	return this.api("POST","/git/trees",{base_tree: head.tree, tree: entries.map(function(e) { return {path: e.path, mode: "100644", type: "blob", sha: e.sha}; })},undefined,undefined,"create tree").then(function(t) {
		return self.api("POST","/git/commits",{message: message, tree: t.sha, parents: [head.commit]},undefined,undefined,"create commit");
	}).then(function(c) {
		if(!c || typeof c.sha !== "string" || !SHA_RE.test(c.sha)) { throw new GitHubError(0,"unexpected commit response"); }
		return self.api("PATCH","/git/refs/heads/" + self.branch.split("/").map(encodeURIComponent).join("/"),{sha: c.sha, force: false},undefined,undefined,"update ref").then(function() { return {commit: c.sha}; });
	});
};
exports.Client = Client; exports.GitHubError = GitHubError; exports.PATH_RE = PATH_RE; exports.PUB_PATH_RE = PUB_PATH_RE; exports.request = request; exports.readBody = readBody;
})();
