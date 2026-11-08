/*\
title: $:/plugins/tw-enc-sync/publish.js
type: application/javascript
module-type: library

Publish selected tiddlers as PLAINTEXT Markdown blog posts into the same repository (a Hugo site: content/blog/<slug>/index[.de].md).
Pure functions + an injectable GitHub client, so everything runs in Node tests and in the browser.

Safety model (deliberate disclosure, see docs/THREAT-MODEL.md "Publishing"):
 * opt-in per tiddler (tag publish:blog) AND an explicit confirm on a preview of the exact bytes; never from timers or Publish-to-GitHub-now;
 * a separate path allowlist (PUB_PATH_RE) - the ciphertext PATH_RE is never widened, the two are never mixed in one commit;
 * refuses anything that could pull in other (private) tiddlers or run code: transclusions, macros, widgets, raw HTML, filtered transclusion;
 * links to unpublished tiddlers become plain text; vault tags are never copied (only the field publish-tags);
 * refuses invisible / bidi-control Unicode (prompt-injection and "trojan source" hygiene);
 * front matter values are JSON-encoded strings (valid YAML, no injection through titles).
\*/
(function(){
/*jslint node: true, browser: true */
"use strict";

var TAG = "publish:blog";
var F_SLUG = "publish-slug", F_LANG = "publish-lang", F_TAGS = "publish-tags", F_MEDIA = "publish-media", F_SUMMARY = "summary",
	F_SHA = "publish-sha", F_DATE = "publish-date";
var SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/;
var MEDIA_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/;
var PUB_PATH_RE = /^content\/blog\/[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\/(?:index(?:\.de)?\.md|[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\.(?:webp|png|jpe?g))$/;
var LANGS = {en: 1, de: 1};
var MEDIA_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/webp": "webp"};
var MD_TYPES = {"text/x-markdown": 1, "text/markdown": 1};
var WIKI_TYPES = {"": 1, "text/vnd.tiddlywiki": 1};
var MAX_TEXT = 512 * 1024, MAX_MEDIA = 8 * 1048576, MAX_MEDIA_COUNT = 20;
/* tag chars U+E0000-E007F (surrogates DB40 DC00-DC7F), zero-width, BOM, bidi controls */
var INVISIBLE_RE = /\uDB40[\uDC00-\uDC7F]|[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]/;

function PublishError(msg,code,extra) { this.name = "PublishError"; this.message = msg; this.code = code || "refused"; if(extra) { this.extra = extra; } }
PublishError.prototype = Object.create(Error.prototype);
function refuse(msg,code,extra) { throw new PublishError(msg,code,extra); }

function tagList(v) {
	if(Array.isArray(v)) { return v.map(String); }
	if(typeof v !== "string") { return []; }
	var out = [], re = /\[\[(.*?)\]\]|(\S+)/g, m;
	while((m = re.exec(v))) { out.push(m[1] !== undefined ? m[1] : m[2]); }
	return out;
}
function hasTag(fields) { return tagList(fields && fields.tags).indexOf(TAG) !== -1; }

/* ASCII slug from a title (German umlauts transliterated). */
function slugify(title) {
	var s = String(title || "").toLowerCase()
		.replace(/ä/g,"ae").replace(/ö/g,"oe").replace(/ü/g,"ue").replace(/ß/g,"ss")
		.normalize("NFKD").replace(/[̀-ͯ]/g,"")
		.replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"").substr(0,80).replace(/-+$/,"");
	return s;
}

function invisibleAt(s) {
	var m = INVISIBLE_RE.exec(s);
	return m ? {index: m.index, code: "U+" + (m[0].length === 2 ? (((m[0].charCodeAt(0) - 0xD800) << 10) + (m[0].charCodeAt(1) - 0xDC00) + 0x10000) : m[0].charCodeAt(0)).toString(16).toUpperCase()} : null;
}

/* Remove fenced code blocks and inline code before scanning for constructs (code may legitimately show <html> or {{x}}). */
function stripCode(md) {
	return md.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[ \t]*$/gm,"").replace(/`+[^`\n]*`+/g,"");
}

/* Constructs that can pull in other tiddlers, run code or inject markup. */
var FORBIDDEN = [
	[/\{\{/, "transclusion {{…}}"],
	[/<<|>>/, "macro call <<…>>"],
	[/<\$/, "widget <$…>"],
	[/<(?!https?:\/\/[^\s>]+>)\/?[A-Za-z!?][^>]*>/, "raw HTML"],
	[/\{\{\{/, "filtered transclusion {{{…}}}"],
	[/^\\(?:define|import|rules|whitespace|procedure|function|widget|parameters)\b/m, "pragma \\define/\\import/…"],
	[/\[img[\s\[]/i, "malformed TiddlyWiki image syntax [img[…]]"],
	[/\[ext\[/i, "TiddlyWiki external link syntax [ext[…]]"]
];
function forbidden(md) {
	var s = stripCode(md), found = [];
	FORBIDDEN.forEach(function(r) { if(r[0].test(s)) { found.push(r[1]); } });
	return found;
}

/* Outside code spans/blocks only: [img[Title]] / [img[alt|Title]] / [img width=.. [Title]] -> ![alt](#Title). */
function convertImgSyntax(md) {
	var parts = md.split(/(^(?:```|~~~)[^\n]*\n[\s\S]*?^(?:```|~~~)[ \t]*$|`+[^`\n]*`+)/m), out = "";
	for(var i = 0; i < parts.length; i++) {
		if(i % 2 === 1) { out += parts[i]; continue; }
		out += parts[i].replace(/\[img(?:\s+[^\[\]]*)?\[([^\]|]*?)(?:\|([^\]]*?))?\]\]/g,function(all,a,b) {
			var alt = b === undefined ? "" : a, target = b === undefined ? a : b;
			return "![" + alt.replace(/[\[\]]/g,"") + "](#" + target.replace(/[()]/g,"") + ")";
		});
	}
	return out;
}
/* Image references ![alt](target) outside code. */
function imageRefs(md) {
	var refs = [], re = /!\[[^\]]*\]\(\s*([^)\s]+(?:\s+[^)"]+)*?)\s*(?:"[^"]*")?\)/g, m, body = stripCode(md);
	while((m = re.exec(body))) { refs.push(m[1]); }
	return refs;
}

/* [[Title]] / [[text|Title]] -> link to a published post (resolver returns a URL) or plain text. */
function resolveLinks(md,resolve) {
	var parts = md.split(/(^(?:```|~~~)[^\n]*\n[\s\S]*?^(?:```|~~~)[ \t]*$|`+[^`\n]*`+)/m), out = "";
	for(var i = 0; i < parts.length; i++) {
		if(i % 2 === 1) { out += parts[i]; continue; }     // code: untouched
		out += parts[i].replace(/\[\[([^\]|]*?)(?:\|([^\]]*?))?\]\]/g,function(all,a,b) {
			var text = a, target = b === undefined ? a : b;
			var url = resolve ? resolve(target) : null;
			text = text.replace(/[\[\]]/g,"");
			return url ? "[" + text + "](" + url + ")" : text;
		});
	}
	return out;
}

function yamlStr(s) { return JSON.stringify(String(s)); }   // JSON strings are valid YAML scalars
function tw2iso(v) {
	// TiddlyWiki date string YYYYMMDDHHMMSSmmm (UTC) -> ISO 8601
	var m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(String(v || ""));
	return m ? m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + "Z" : null;
}

/*
 buildPost(fields, opts) -> {slug, lang, path, dir, markdown, media: [{name, title, type, ext, path}], title, warnings}
 opts: {convert(text,fields) -> markdown|null  (WikiText -> Markdown; null = not convertible),
        resolve(title) -> url|null             (other published posts),
        mediaFields(title) -> fields|null      (image tiddlers listed in publish-media),
        now: ISO string}
*/
function buildPost(fields,opts) {
	opts = opts || {};
	if(!fields || typeof fields.title !== "string") { refuse("no tiddler"); }
	var title = fields.title, warnings = [];
	if(title.indexOf("$:/") === 0) { refuse("system tiddlers are never published"); }
	if(!hasTag(fields)) { refuse("tiddler is not tagged " + TAG); }
	if(fields._is_skinny !== undefined || typeof fields.text !== "string") { refuse("the tiddler is not loaded yet; open it and try again","not-loaded"); }
	if(fields["draft.of"]) { refuse("drafts are never published; save the tiddler first"); }
	var inv = invisibleAt(title) || invisibleAt(fields.text) || invisibleAt(String(fields[F_SUMMARY] || "")) || invisibleAt(String(fields[F_TAGS] || ""));
	if(inv) { refuse("invisible or bidi-control character " + inv.code + " found (position " + inv.index + "); remove it before publishing","invisible"); }
	var lang = String(fields[F_LANG] || "en").trim().toLowerCase();
	if(!LANGS[lang]) { refuse("publish-lang must be en or de"); }
	var slug = String(fields[F_SLUG] || "").trim() || slugify(title);
	if(!SLUG_RE.test(slug)) { refuse("cannot derive a valid slug; set the field publish-slug (a-z, 0-9, dashes)"); }
	if(fields.text.length > MAX_TEXT) { refuse("text too large to publish"); }
	var type = fields.type || "", md;
	if(MD_TYPES[type]) { md = fields.text; }
	else if(WIKI_TYPES[type]) {
		md = opts.convert ? opts.convert(fields.text,fields) : null;
		if(typeof md !== "string") { refuse("this WikiText cannot be converted to Markdown without guessing; convert it in the editor first (Control Panel > Markdown lists the reasons)","not-convertible"); }
	} else { refuse("only Markdown or WikiText tiddlers can be published (type " + type + ")"); }
	md = convertImgSyntax(md.replace(/\r\n?/g,"\n"));
	var bad = forbidden(md);
	if(bad.length) { refuse("refusing to publish: " + bad.join(", ") + ". These could pull in private tiddlers or run code.","forbidden",bad); }
	md = resolveLinks(md,opts.resolve);
	// media
	var media = [], names = {}, wanted = tagList(fields[F_MEDIA]);
	imageRefs(md).forEach(function(ref) {
		var t = ref.replace(/^#/,"");
		try { t = decodeURIComponent(t); } catch(e) {}
		if(/^[a-z][a-z0-9+.-]*:|^\/\//i.test(ref)) { refuse("external image " + ref.substr(0,80) + ": the website only shows its own images (Content-Security-Policy). Import it as an image tiddler and use ![alt](#Title).","media"); }
		if(wanted.indexOf(t) === -1) { wanted.push(t); }
	});
	wanted.forEach(function(mt) {
		if(media.length >= MAX_MEDIA_COUNT) { refuse("too many media tiddlers"); }
		var mf = opts.mediaFields ? opts.mediaFields(mt) : null;
		if(!mf) { refuse("image not found: \"" + mt + "\" (use the exact title of an image tiddler)","media"); }
		var ext = MEDIA_TYPES[mf.type || ""];
		if(!ext) { refuse("media must be PNG, JPEG or WebP: " + mt,"media"); }
		if(typeof mf.text !== "string" || mf._is_skinny !== undefined) { refuse("media tiddler not loaded yet: " + mt,"not-loaded"); }
		if(mf.text.length > MAX_MEDIA * 4 / 3 + 4) { refuse("media too large: " + mt,"media"); }
		var base = slugify(mt.replace(/\.(png|jpe?g|webp)$/i,"")) || "image";
		if(!MEDIA_NAME_RE.test(base)) { refuse("cannot derive a file name for " + mt,"media"); }
		var name = base, n = 2;
		while(names[name]) { name = base + "-" + (n++); }
		names[name] = 1;
		var p = "content/blog/" + slug + "/" + name + "." + ext;
		if(!PUB_PATH_RE.test(p)) { refuse("refusing unexpected media path","path"); }
		media.push({title: mt, name: name, ext: ext, type: mf.type, path: p, base64: mf.text});
		// rewrite Markdown image references to the media tiddler title: ![alt](Title) / ![alt](#Title)
		md = md.replace(/!\[([^\]]*)\]\(\s*#?([^)]+?)\s*\)/g,function(all,alt,target) {
			return (target === mt || decodeURIComponent(target) === mt) ? "![" + alt + "](" + name + "." + ext + ")" : all;
		});
	});
	// front matter
	var date = tw2iso(fields.created) || opts.now || null, lastmod = tw2iso(fields.modified);
	var tags = tagList(fields[F_TAGS]).filter(function(t) { return t && t.length <= 40; }).slice(0,12);
	var fm = ["---", "title: " + yamlStr(title)];
	if(slug !== slugify(title) || lang !== "en") { fm.push("slug: " + yamlStr(slug)); }
	if(date) { fm.push("date: " + yamlStr(date)); }
	if(lastmod) { fm.push("lastmod: " + yamlStr(lastmod)); }
	var desc = fields[F_SUMMARY] ? String(fields[F_SUMMARY]).replace(/\s+/g," ").trim() : autoDescription(md);
	if(desc) { fm.push("description: " + yamlStr(desc)); }
	if(tags.length) { fm.push("tags: [" + tags.map(yamlStr).join(", ") + "]"); }
	fm.push("translationKey: " + yamlStr(slug));
	fm.push("source: \"vault\"");
	fm.push("---");
	var markdown = fm.join("\n") + "\n\n" + md.replace(/\s+$/,"") + "\n";
	var dir = "content/blog/" + slug, path = dir + "/" + (lang === "de" ? "index.de.md" : "index.md");
	if(!PUB_PATH_RE.test(path)) { refuse("refusing unexpected post path","path"); }
	var inv2 = invisibleAt(markdown);
	if(inv2) { refuse("invisible character in generated Markdown","invisible"); }
	return {slug: slug, lang: lang, dir: dir, path: path, markdown: markdown, media: media, title: title, warnings: warnings};
}

/* A plain-text description from the first real paragraph (no headings, lists, code, links or emphasis), <= 160 chars. */
function autoDescription(md) {
	var paras = md.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[ \t]*$/gm,"").split(/\n\s*\n/);
	for(var i = 0; i < paras.length; i++) {
		var p = paras[i].trim();
		if(!p || /^(#|>|[-*+] |\d+\. |\||!\[|<)/.test(p)) { continue; }
		p = p.replace(/!\[[^\]]*\]\([^)]*\)/g,"").replace(/\[([^\]]*)\]\([^)]*\)/g,"$1").replace(/[*_`~]+/g,"").replace(/\s+/g," ").trim();
		if(p.length < 20) { continue; }
		if(p.length <= 160) { return p; }
		var cut = p.substr(0,157), sp = cut.lastIndexOf(" ");
		return (sp > 80 ? cut.substr(0,sp) : cut).replace(/[,;:.]$/,"") + "…";
	}
	return "";
}

/* git blob id of bytes (what GitHub reports as "sha" for a file): sha1("blob <len>\0" + bytes) */
function gitBlobSha(bytes,subtle) {
	var head = new TextEncoder().encode("blob " + bytes.length + "\0"), buf = new Uint8Array(head.length + bytes.length);
	buf.set(head,0); buf.set(bytes,head.length);
	return (subtle || globalThis.crypto.subtle).digest("SHA-1",buf).then(function(d) {
		return Array.prototype.map.call(new Uint8Array(d),function(b) { return ("0" + b.toString(16)).slice(-2); }).join("");
	});
}
function b64bytes(s) { var bin = atob(s), u = new Uint8Array(bin.length); for(var i = 0; i < bin.length; i++) { u[i] = bin.charCodeAt(i); } return u; }

/*
 publish(client, post, opts) -> Promise<{commit, sha, unchanged}>
 client: {getHead(), getContentSha(path, ref) -> sha|null, createBlob(bytes) -> sha, commitPlain(head, entries, message)}
 opts: {lastSha: the publish-sha field (sha of the post file at the last publish), force: overwrite a remote edit}
 Conflict: if the post file exists remotely with a sha other than lastSha (or exists but we never published it), refuse unless force.
*/
function publish(client,post,opts) {
	opts = opts || {};
	var enc = new TextEncoder(), mdBytes = enc.encode(post.markdown), head, files = [{path: post.path, bytes: mdBytes}];
	post.media.forEach(function(m) { files.push({path: m.path, bytes: b64bytes(m.base64)}); });
	for(var i = 0; i < files.length; i++) { if(!PUB_PATH_RE.test(files[i].path)) { return Promise.reject(new PublishError("refusing unexpected path","path")); } }
	var localSha;
	return gitBlobSha(mdBytes).then(function(s) {
		localSha = s;
		return client.getHead();
	}).then(function(h) {
		head = h;
		return client.getContentSha(post.path,head.commit);
	}).then(function(remoteSha) {
		if(remoteSha && remoteSha === localSha) { return {unchanged: true}; }
		if(remoteSha && remoteSha !== opts.lastSha && !opts.force) {
			throw new PublishError("the published post was changed outside the vault (e.g. edited on GitHub) since your last publish; review it and choose \"Publish anyway\" to overwrite","conflict",{remoteSha: remoteSha});
		}
		return Promise.all(files.map(function(f) {
			return gitBlobSha(f.bytes).then(function(fs) {
				return f.path === post.path ? client.createBlob(f.bytes) : client.getContentSha(f.path,head.commit).then(function(rs) { return rs === fs ? fs : client.createBlob(f.bytes); });
			}).then(function(sha) { return {path: f.path, sha: sha}; });
		})).then(function(entries) {
			return client.commitPlain(head,entries,"Publish: " + post.slug + (post.lang === "de" ? " (de)" : ""));
		});
	}).then(function(r) {
		return {commit: r && r.commit, sha: localSha, unchanged: !!(r && r.unchanged)};
	});
}

/* unpublish(client, slug, lang) -> removes the post file for that language; when no other language file remains, the whole folder. */
function unpublish(client,slug,lang) {
	if(!SLUG_RE.test(String(slug || ""))) { return Promise.reject(new PublishError("invalid slug")); }
	var dir = "content/blog/" + slug, mine = dir + "/" + (lang === "de" ? "index.de.md" : "index.md"), head;
	return client.getHead().then(function(h) {
		head = h;
		return client.listDir(dir,head.commit);
	}).then(function(paths) {
		paths = (paths || []).filter(function(p) { return PUB_PATH_RE.test(p); });
		if(paths.indexOf(mine) === -1) { return {commit: null, removed: []}; }
		var others = paths.filter(function(p) { return /\/index(\.de)?\.md$/.test(p) && p !== mine; });
		var remove = others.length ? [mine] : paths;   // other language still published: keep its media
		return client.commitPlain(head,remove.map(function(p) { return {path: p, sha: null}; }),"Unpublish: " + slug + (lang === "de" ? " (de)" : "")).then(function(r) { return {commit: r && r.commit, removed: remove}; });
	});
}

exports.TAG = TAG; exports.PUB_PATH_RE = PUB_PATH_RE; exports.SLUG_RE = SLUG_RE;
exports.FIELDS = {slug: F_SLUG, lang: F_LANG, tags: F_TAGS, media: F_MEDIA, summary: F_SUMMARY, sha: F_SHA, date: F_DATE};
exports.PublishError = PublishError;
exports.slugify = slugify; exports.hasTag = hasTag; exports.forbidden = forbidden; exports.resolveLinks = resolveLinks;
exports.invisibleAt = invisibleAt; exports.autoDescription = autoDescription; exports.convertImgSyntax = convertImgSyntax; exports.imageRefs = imageRefs; exports.buildPost = buildPost; exports.gitBlobSha = gitBlobSha;
exports.publish = publish; exports.unpublish = unpublish;
})();
