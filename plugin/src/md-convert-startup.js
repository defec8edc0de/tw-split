/*\
title: $:/plugins/tw-enc-sync/md-convert-startup.js
type: application/javascript
module-type: startup

WikiText to Markdown converter, runtime part. Registers the messages tm-md-scan, tm-md-convert-all, tm-md-revert-all, tm-md-convert,
tm-md-revert and tm-md-drop-backups, publishes reports under the temp/ext/md/ tiddlers and exposes $tw.mdConvert for scripts and tests.

It also installs a small fix for the markdown parser of anstosa/tw5-markdown (only when a self-test shows the defect). That parser hands every
text node of the rendered HTML back to the WikiText parser as a block, which drops the space after an inline element and re-interprets text such
as a leading colon or asterisk as list syntax. The fix parses those text nodes as inline WikiText instead. Switch it off with the config tiddler
ParserFix under config/ext/md (text no).

Conversion keeps the original in the field wikitext-backup, so every conversion can be reverted.

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

exports.name = "md-convert";
exports.platforms = ["browser"];
exports.after = ["rootwidget"];
exports.before = ["story","render"];
exports.synchronous = true;

var MD_TYPE = "text/x-markdown", WIKI_TYPE = "text/vnd.tiddlywiki";
var T_STATUS = "$:/temp/ext/md/status", T_REASONS = "$:/temp/ext/md/reasons", T_LIST = "$:/temp/ext/md/list/";
var CFG_FIX = "$:/config/ext/md/ParserFix", CFG_EXT = "$:/config/ext/md/ExternalLinks";
var F_BACKUP = "wikitext-backup", F_BTYPE = "wikitext-backup-type", F_HASH = "md-converted-hash";
var LISTS = ["convertible","review","markdown","unloaded","converted","modified"];

function lib() { return require("$:/plugins/tw-enc-sync/md-convert.js"); }
function cfg(title) {
	var t = $tw.wiki.getTiddler(title);
	return t && typeof t.fields.text === "string" ? t.fields.text.trim().toLowerCase() : "";
}
function plain(s) { return String(s === undefined ? "" : s).replace(/[^\x20-\x7e -￿]/g," ").substr(0,400); }

/* ------------------------------------------------------------------ markdown parser fix */
function flatText(nodes) {
	var s = "";
	(nodes || []).forEach(function(n) { if(!n) { return; } if(n.type === "text") { s += n.text; } else if(n.children) { s += flatText(n.children); } });
	return s;
}
function parserNeedsFix(Cls) {
	try { return flatText(new Cls(MD_TYPE,"**a** b: c",{}).tree).trim() !== "a b: c"; } catch(e) { return false; }
}
var parserState = {state: "n/a", original: null, installed: false};
/* The defect only shows once the wikitext parser is fully initialised (the markdown plugin silently falls back to plain text for a parse that
   throws), so the self-test runs on demand (refreshParserState), not at startup. The fix is installed unconditionally; it only swaps the
   WikiText parser used for text nodes while a markdown tiddler is being parsed. */
function refreshParserState() {
	var P = $tw.Wiki && $tw.Wiki.parsers, cur = P && P[MD_TYPE];
	if(!cur || !parserState.original) { parserState.state = "n/a"; return parserState.state; }
	var needs = parserNeedsFix(cur);
	parserState.state = parserState.installed ? (needs ? "failed" : "active") : (needs ? "disabled" : "not needed");
	return parserState.state;
}
function installParserFix() {
	var P = $tw.Wiki && $tw.Wiki.parsers, Orig = P && P[MD_TYPE], Wiki = P && P[WIKI_TYPE];
	if(!Orig || !Wiki) { parserState.state = "n/a"; return; }
	parserState.original = Orig;
	if(cfg(CFG_FIX) === "no") { return; }
	function Fixed(type,text,options) {
		var saved = P[WIKI_TYPE];
		P[WIKI_TYPE] = function(t,txt,opts) {
			var o = {}, k, tree;
			for(k in (opts || {})) { if(Object.prototype.hasOwnProperty.call(opts,k)) { o[k] = opts[k]; } }
			o.parseAsInline = true;
			// The core parser skips leading whitespace and runs pragmas (define, rules) at the start of its input. A sentinel in front
			// keeps both away from the text node; it is removed again from the tree.
			tree = new Wiki(t,"\u200b" + txt,o).tree;
			if(tree.length && tree[0].type === "text" && tree[0].text.charAt(0) === "\u200b") {
				tree[0].text = tree[0].text.slice(1);
				if(tree[0].text === "") { tree.shift(); }
			}
			return {tree: [{type: "element", tag: "p", children: tree}]};
		};
		try { return new Orig(type,text,options); } finally { P[WIKI_TYPE] = saved; }
	}
	Fixed.prototype = Orig.prototype;
	P[MD_TYPE] = Fixed;
	parserState.installed = true;
	parserState.state = "active";
}

/* ------------------------------------------------------------------ rendering check */
function renderSignature(type,text) {
	var doc = (typeof document !== "undefined" && document) || $tw.fakeDocument,
		parser = $tw.wiki.parseText(type,text,{}),
		widget = $tw.wiki.makeWidget(parser,{document: doc, parentWidget: $tw.rootWidget}),
		box = doc.createElement("div");
	widget.render(box,null);
	var sig = lib().signature(box);
	try { widget.removeChildDomNodes(); } catch(e) {}
	return sig;
}
function verify(original,md,hints) {
	try {
		var a = renderSignature(WIKI_TYPE,original), b = renderSignature(MD_TYPE,md);
		return lib().compareSignatures(a,b,hints);
	} catch(e) { return {ok: false, diffs: ["render check failed: " + plain(e && e.message)]}; }
}

/* ------------------------------------------------------------------ helpers */
function opts() { return {externalLinks: cfg(CFG_EXT) === "tw" ? "tw" : "md"}; }
function loaded(t) { return !!t && t.fields._is_skinny === undefined && typeof t.fields.text === "string"; }
function userTitles() { return $tw.wiki.allTitles().filter(function(t) { return t.indexOf("$:/") !== 0; }); }
function hasBackup(t) { return !!t && Object.prototype.hasOwnProperty.call(t.fields,F_BACKUP) && t.fields.type === MD_TYPE; }
function fieldsWithoutSkinny(t) { var f = {}, k; for(k in t.fields) { if(k !== "_is_skinny" && k !== "text") { f[k] = t.fields[k]; } } return f; }

function setTiddler(title,fields) { $tw.wiki.addTiddler(new $tw.Tiddler({title: title},fields)); }
function setList(name,titles) {
	var ok = titles.filter(function(t) { return t.indexOf("]]") === -1 && /^[^\n]*$/.test(t); });
	setTiddler(T_LIST + name,{list: $tw.utils.stringifyList(ok), count: String(titles.length), unlistable: String(titles.length - ok.length)});
}
var busy = false;
function status(fields) {
	var t = $tw.wiki.getTiddler(T_STATUS), f = {};
	if(t) { for(var k in t.fields) { f[k] = t.fields[k]; } }
	for(var k2 in fields) { f[k2] = fields[k2]; }
	f.title = T_STATUS; f.type = "text/plain";
	$tw.wiki.addTiddler(new $tw.Tiddler(f));
}

/* Ask the syncer to lazily load skinny tiddlers and wait (poll) until their text is there or the time is up. */
function ensureLoaded(titles,timeout) {
	return new Promise(function(resolve) {
		var start = Date.now();
		function pending() { return titles.filter(function(t) { return !loaded($tw.wiki.getTiddler(t)); }); }
		function kick(list) { list.forEach(function(t) { try { $tw.wiki.getTiddlerText(t); } catch(e) {} }); }
		var p = pending();
		if(!p.length) { return resolve([]); }
		kick(p);
		(function poll() {
			p = pending();
			if(!p.length || Date.now() - start > timeout) { return resolve(p); }
			setTimeout(function() { if(Date.now() - start > 2000) { kick(p); } poll(); },200);
		})();
	});
}

/* ------------------------------------------------------------------ scan */
var lastScan = null;
function scan(options) {
	options = options || {};
	refreshParserState();
	if(busy) { return Promise.resolve(null); }
	busy = true;
	status({state: "loading", message: "Loading tiddler texts..."});
	var titles = userTitles(), L = lib(), toLoad = [];
	titles.forEach(function(title) {
		var t = $tw.wiki.getTiddler(title);
		if(!t || loaded(t)) { return; }
		var st = L.classify("x",fieldsWithoutSkinny(t),opts()).status;
		if(st === "convertible" || st === "review" || hasBackup(t)) { toLoad.push(title); }
	});
	return ensureLoaded(toLoad,options.loadTimeout === undefined ? (parseInt(cfg("$:/config/ext/md/LoadTimeout"),10) || 20000) : options.loadTimeout).then(function(stillSkinny) {
		status({state: "scanning", message: "Analysing..."});
		var res = {convertible: [], review: [], markdown: [], unloaded: stillSkinny.slice(), converted: [], modified: [], skipped: 0, reasons: {}, md: {}, hints: {}, warnings: {}};
		var skinnySet = {}; stillSkinny.forEach(function(t) { skinnySet[t] = 1; });
		titles.forEach(function(title) {
			var t = $tw.wiki.getTiddler(title);
			if(!t) { return; }
			if(skinnySet[title]) { return; }
			if(hasBackup(t)) {
				res.converted.push(title);
				if(typeof t.fields.text === "string" && L.hash(t.fields.text) !== t.fields[F_HASH]) { res.modified.push(title); }
				return;
			}
			var f = {}, k; for(k in t.fields) { f[k] = t.fields[k]; }
			var c = L.classify(loaded(t) ? t.fields.text : undefined,f,opts());
			if(c.status === "skip") { res.skipped++; return; }
			if(c.status === "already-markdown") { res.markdown.push(title); return; }
			if(c.status === "review") { res.review.push(title); res.reasons[title] = c.reasons.join("; "); return; }
			// convertible: prove it with the real renderers
			var md = L.convert(t.fields.text,opts());
			var v = options.verify === false ? {ok: true, diffs: []} : verify(t.fields.text,md,c.hints);
			if(v.ok) { res.convertible.push(title); res.md[title] = md; res.hints[title] = c.hints; res.warnings[title] = c.warnings; }
			else { res.review.push(title); res.reasons[title] = "render check: " + v.diffs.join("; "); }
		});
		LISTS.forEach(function(n) { setList(n,res[n]); });
		var rj = {}; Object.keys(res.reasons).forEach(function(k) { rj[k] = plain(res.reasons[k]); });
		setTiddler(T_REASONS,{type: "application/json", text: JSON.stringify(rj)});
		status({state: "idle", scanned: $tw.utils.stringifyDate(new Date()), "n-convertible": String(res.convertible.length), "n-review": String(res.review.length),
			"n-markdown": String(res.markdown.length), "n-unloaded": String(res.unloaded.length), "n-converted": String(res.converted.length),
			"n-modified": String(res.modified.length), "n-skipped": String(res.skipped), "parser-fix": parserState.state,
			message: res.unloaded.length ? res.unloaded.length + " tiddler(s) are not loaded yet. Wait a few seconds and scan again." : "Scan finished."});
		lastScan = res;
		busy = false;
		return res;
	}).then(null,function(e) { busy = false; status({state: "idle", message: "Scan failed: " + plain(e && e.message)}); return null; });
}

/* ------------------------------------------------------------------ convert / revert */
function parserOk() {
	refreshParserState(); return parserState.state === "active" || parserState.state === "not needed" || parserState.state === "n/a"; }
function convertTiddler(title,md,noBackup) {
	var t = $tw.wiki.getTiddler(title);
	if(!loaded(t) || hasBackup(t)) { return false; }
	var extra = {type: MD_TYPE, text: md};
	if(!noBackup) {
		extra[F_BACKUP] = t.fields.text;
		extra[F_HASH] = lib().hash(md);
		if(t.fields.type !== undefined) { extra[F_BTYPE] = t.fields.type; }
	}
	$tw.wiki.addTiddler(new $tw.Tiddler(t,extra));
	return true;
}
/* force: revert even when the Markdown was edited after the conversion */
function revertTiddler(title,force) {
	var t = $tw.wiki.getTiddler(title);
	if(!hasBackup(t) || !loaded(t)) { return "skipped"; }
	if(!force && lib().hash(t.fields.text) !== t.fields[F_HASH]) { return "modified"; }
	var o = {text: t.fields[F_BACKUP], type: Object.prototype.hasOwnProperty.call(t.fields,F_BTYPE) ? t.fields[F_BTYPE] : undefined};
	o[F_BACKUP] = undefined; o[F_BTYPE] = undefined; o[F_HASH] = undefined;
	$tw.wiki.addTiddler(new $tw.Tiddler(t,o));
	return "reverted";
}
function convertAll() {
	if(!parserOk()) { status({message: "Markdown parser fix is not active (" + parserState.state + "): conversion refused, the converted notes would lose spaces."}); return Promise.resolve(null); }
	return scan({}).then(function(res) {
		if(!res) { return null; }
		var n = 0;
		res.convertible.forEach(function(title) { if(convertTiddler(title,res.md[title])) { n++; } });
		return scan({verify: false, loadTimeout: 0}).then(function() {
			status({message: "Converted " + n + " tiddler(s). " + res.review.length + " need review, " + res.unloaded.length + " not loaded."});
			res.convertedNow = n;
			return res;
		});
	});
}
function revertAll() {
	var n = 0, skipped = [];
	userTitles().forEach(function(title) {
		var r = revertTiddler(title,false);
		if(r === "reverted") { n++; } else if(r === "modified") { skipped.push(title); }
	});
	return scan({verify: false, loadTimeout: 0}).then(function() {
		status({message: "Reverted " + n + " tiddler(s). " + skipped.length + " edited since conversion were left alone (see list)."});
		return {reverted: n, modified: skipped};
	});
}
function dropBackups() {
	var n = 0;
	userTitles().forEach(function(title) {
		var t = $tw.wiki.getTiddler(title);
		if(hasBackup(t) && loaded(t)) { var o = {}; o[F_BACKUP] = undefined; o[F_BTYPE] = undefined; o[F_HASH] = undefined; $tw.wiki.addTiddler(new $tw.Tiddler(t,o)); n++; }
	});
	return scan({verify: false, loadTimeout: 0}).then(function() { status({message: "Deleted " + n + " backup(s). Those conversions can no longer be reverted."}); return n; });
}
/* single tiddler (view toolbar button) */
function convertOne(title) {
	var t = $tw.wiki.getTiddler(title), L = lib(), res = {ok: false, message: ""};
	if(!t) { res.message = "No such tiddler."; return res; }
	if(!loaded(t)) { $tw.wiki.getTiddlerText(title); res.message = "Not loaded yet, try again in a few seconds."; return res; }
	if(!parserOk()) { res.message = "Markdown parser fix is not active."; return res; }
	var f = {}, k; for(k in t.fields) { f[k] = t.fields[k]; }
	var c = L.classify(t.fields.text,f,opts());
	if(c.status !== "convertible") { res.message = c.status === "review" ? "Needs review: " + c.reasons.join("; ") : "Not convertible (" + c.status + ")."; return res; }
	var md = L.convert(t.fields.text,opts()), v = verify(t.fields.text,md,c.hints);
	if(!v.ok) { res.message = "Render check failed: " + v.diffs.join("; "); return res; }
	res.ok = convertTiddler(title,md); res.message = res.ok ? "Converted." : "Could not convert.";
	return res;
}

/* One-time automatic conversion (no backups, no buttons): every note whose WikiText is fully understood AND whose Markdown renders identically
   is converted when the wiki is first opened with this version; everything else stays untouched and is listed in Control Panel > Markdown. */
var AUTO_MARK = "$:/config/ext/md/AutoConverted";
function autoConvert(attempt) {
	if(cfg("$:/config/ext/md/AutoConvert") === "no" || $tw.wiki.getTiddler(AUTO_MARK)) { return Promise.resolve(null); }
	if(!parserOk()) { return Promise.resolve(null); }
	return scan({}).then(function(res) {
		if(!res) { return null; }
		var n = 0;
		res.convertible.forEach(function(title) { if(convertTiddler(title,res.md[title],true)) { n++; } });
		if(res.unloaded.length && attempt < 3) { setTimeout(function() { autoConvert(attempt + 1); },10000); }   // stubs that were not loaded yet: try again later
		else { $tw.wiki.addTiddler(new $tw.Tiddler({title: AUTO_MARK, type: "text/plain", text: "yes, " + n + " converted, " + res.review.length + " left as WikiText"})); }
		return scan({verify: false, loadTimeout: 0}).then(function() { status({message: "Converted " + n + " note(s) to Markdown. " + res.review.length + " need manual review."}); return res; });
	});
}
function notify(msg) { status({message: plain(msg)}); try { if($tw.notifier) { $tw.wiki.addTiddler(new $tw.Tiddler({title: "$:/temp/ext/md/notification", type: "text/plain", text: plain(msg)})); $tw.notifier.display("$:/temp/ext/md/notification"); } } catch(e) {} }

function ask(msg) { try { return typeof window.confirm === "function" ? !!window.confirm(msg) : false; } catch(e) { return false; } }

exports.startup = function() {
	installParserFix();
	var api = $tw.mdConvert = {
		autoConvert: function() { return autoConvert(0); },
		scan: scan, convertAll: convertAll, revertAll: revertAll, dropBackups: dropBackups, convertOne: convertOne,
		revertOne: function(title,force) { return revertTiddler(title,!!force); },
		parser: parserState, lastScan: function() { return lastScan; }, verify: verify, renderSignature: renderSignature
	};
	setTimeout(function() { autoConvert(0); },6000);
	var rw = $tw.rootWidget;
	if(!rw || typeof rw.addEventListener !== "function") { return; }
	rw.addEventListener("tm-md-scan",function() { scan({}); return false; });
	rw.addEventListener("tm-md-convert-all",function() {
		scan({}).then(function(res) {
			if(!res) { return; }
			if(!parserOk()) { status({message: "Markdown parser fix is not active (" + parserState.state + "): conversion refused."}); return; }
			if(!res.convertible.length) { status({message: "Nothing to convert."}); return; }
			if(!ask("Convert " + res.convertible.length + " tiddler(s) from WikiText to Markdown?\n\nEach original text is kept in the field " + F_BACKUP + " and can be reverted. " + res.review.length + " tiddler(s) needing review are not touched.")) { status({message: "Cancelled."}); return; }
			var n = 0;
			res.convertible.forEach(function(title) { if(convertTiddler(title,res.md[title])) { n++; } });
			scan({verify: false, loadTimeout: 0}).then(function() { status({message: "Converted " + n + " tiddler(s)."}); });
		});
		return false;
	});
	rw.addEventListener("tm-md-revert-all",function() {
		var n = userTitles().filter(function(t) { return hasBackup($tw.wiki.getTiddler(t)); }).length;
		if(!n) { status({message: "Nothing to revert."}); return false; }
		if(!ask("Revert " + n + " converted tiddler(s) to their original WikiText? Tiddlers edited after the conversion are left alone.")) { status({message: "Cancelled."}); return false; }
		revertAll();
		return false;
	});
	rw.addEventListener("tm-md-convert",function(event) {
		var title = event && (event.param || (event.paramObject && event.paramObject.title));
		if(typeof title === "string" && title.indexOf("$:/") !== 0) { notify(convertOne(title).message); }
		return false;
	});
	rw.addEventListener("tm-md-revert",function(event) {
		var title = event && (event.param || (event.paramObject && event.paramObject.title));
		if(typeof title !== "string" || title.indexOf("$:/") === 0) { return false; }
		var r = revertTiddler(title,false);
		if(r === "modified") {
			if(ask("This tiddler was edited after the conversion. Revert to the original WikiText anyway? The edits are lost.")) { r = revertTiddler(title,true); } else { r = "cancelled"; }
		}
		notify(r === "reverted" ? "Reverted to WikiText." : r === "cancelled" ? "Cancelled." : "Nothing to revert.");
		return false;
	});
	rw.addEventListener("tm-md-drop-backups",function() {
		var n = userTitles().filter(function(t) { return hasBackup($tw.wiki.getTiddler(t)); }).length;
		if(!n) { status({message: "No backups."}); return false; }
		if(!ask("Permanently delete the WikiText backups of " + n + " tiddler(s)? This cannot be undone and those conversions can no longer be reverted.")) { status({message: "Cancelled."}); return false; }
		dropBackups();
		return false;
	});
};
})();
