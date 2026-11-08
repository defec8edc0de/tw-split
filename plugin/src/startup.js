/*\
title: $:/plugins/tw-enc-sync/startup.js
type: application/javascript
module-type: startup

Before the first render: pull the (authenticated) manifest into the wiki as skinny tiddlers and
prefetch the boot-critical system tiddlers (theme, palette, stylesheets...) so the UI does not flash.
After render: background-prefetch small text tiddlers so full-text search works.

Browser hardening installed here (all through public TiddlyWiki hooks, all feature-detected, see docs/THREAT-MODEL.md):
 - the core "message" listener (browser-messaging.js) takes tiddlers from ANY window that can postMessage to this page;
   only the plugin-library iframes the core itself created may talk to it
 - raw-HTML that can run script in this origin (srcdoc, javascript: URLs, base/meta/link elements) is neutered
   (opt out: tiddler $:/config/ext/enc/AllowActiveHtml = yes)
 - the GitHub token is not kept in localStorage (shared by every page of the same *.github.io origin); default sessionStorage
   (tiddler $:/config/ext/enc/TokenStorage = memory | session | local)
 - sync alerts are rendered as plain text (core renders them as wikitext) and the syncer no longer logs titles to the console

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

exports.name = "enc-sync-load";
exports.platforms = ["browser"];
exports.after = ["startup"];
exports.before = ["story","rootwidget","render","browser-messaging"];
exports.synchronous = false;

var BLOCKING = "[prefix[$:/]!is[image]]", BACKGROUND = "[!is[system]!is[image]]", MAX_TEXT = 262144, PARALLEL = 6;
var CFG_TOKEN = "$:/config/ext/enc/TokenStorage", CFG_HTML = "$:/config/ext/enc/AllowActiveHtml", CFG_LOG = "$:/config/ext/enc/ConsoleLog";
var TOKEN_KEY = "tw5-password-github";
/* Raw HTML in wikitext: core 5.1.21 neuters only <script> elements and on* attributes. */
var ACTIVE_HTML = ["base","meta","link","applet","frame","frameset"];
var JS_URL = /^[\u0000-\u0020]*j[\t\n\r]*a[\t\n\r]*v[\t\n\r]*a[\t\n\r]*s[\t\n\r]*c[\t\n\r]*r[\t\n\r]*i[\t\n\r]*p[\t\n\r]*t[\t\n\r]*:/i;

function pool(titles,fn,n) {
	var i = 0, errors = 0;
	function next() {
		if(i >= titles.length) { return Promise.resolve(); }
		var t = titles[i++];
		return fn(t).catch(function() { errors++; }).then(next);
	}
	var w = []; for(var k=0; k<Math.min(n,titles.length); k++) { w.push(next()); }
	return Promise.all(w).then(function() { return errors; });
}

/* Current text of a (possibly still skinny) config tiddler WITHOUT triggering a lazy load. */
function cfgText(title) {
	var t = $tw.wiki.getTiddler(title);
	return t && typeof t.fields.text === "string" ? t.fields.text.trim().toLowerCase() : "";
}

/* Error text is shown to the user: keep it short, printable, and never interpreted as wikitext (type text/plain). */
function plain(s) { return String(s === undefined ? "" : s).replace(/[^\x20-\x7e -￿]/g," ").substr(0,300); }
function showError(msg) {
	$tw.wiki.addTiddler(new $tw.Tiddler({title: "$:/temp/ext/enc/error", type: "text/plain", text: plain(msg)}));
}

/* --- 1. cross-window messages ------------------------------------------------------------------------------------------------ */
/* Core: window.addEventListener("message") with no origin/source check; a GET-RESPONSE/save-tiddler message from any page that holds
   a reference to this window (opener, parent frame, window.open) does wiki.addTiddler(JSON.parse(body)) - an arbitrary tiddler,
   which this plugin would then encrypt and commit as if the user wrote it. Our listener is registered first (before: browser-messaging)
   and swallows every message that does not come from a library iframe created by the core for that iframe's own origin. */
function fromLibraryIframe(ev) {
	var map = $tw.browserMessaging && $tw.browserMessaging.iframeInfoMap, u, info;
	if(!map || !ev.source) { return false; }
	for(u in map) {
		info = map[u];
		if(info && info.domNode && info.domNode.contentWindow === ev.source) {
			try { return new URL(u,window.location.href).origin === ev.origin; } catch(e) { return false; }
		}
	}
	return false;
}
function installMessageGuard() {
	window.addEventListener("message",function(ev) {
		if(!fromLibraryIframe(ev)) { ev.stopImmediatePropagation(); }
	},true);
}

/* --- 2. active raw HTML ------------------------------------------------------------------------------------------------------- */
/* Hostile or imported tiddler text such as <iframe srcdoc="<script>...">, <a href="javascript:...">, <embed src=javascript:...> would run
   script in THIS origin (token, engine, every note). So: (a) base/meta/link/applet/frame/frameset are rendered as inert safe-* elements via
   the documented $tw.config.htmlUnsafeElements list; (b) attributes that carry script (srcdoc, any value starting with "javascript:") are
   dropped before they reach the DOM. iframe/embed/object themselves stay usable: the core's own text/html (sandboxed iframe) and PDF
   (embed) renderers need them. */
function hardenHtml() {
	if(cfgText(CFG_HTML) === "yes") { return; }
	var list = $tw.config && $tw.config.htmlUnsafeElements;
	if(Array.isArray(list)) { ACTIVE_HTML.forEach(function(tag) { if(list.indexOf(tag) === -1) { list.push(tag); } }); }
	var W;
	try { W = require("$:/core/modules/widgets/widget.js").widget; } catch(e) { return; }
	if(!W || typeof W.prototype.assignAttributes !== "function" || W.prototype.assignAttributes.encSyncWrapped) { return; }
	var orig = W.prototype.assignAttributes;
	W.prototype.assignAttributes = function(domNode,options) {
		var saved = this.attributes, clean = Object.create(null), k, changed = false;
		if(saved && typeof saved === "object") {
			for(k in saved) {
				if(String(k).toLowerCase() === "srcdoc" || (typeof saved[k] === "string" && JS_URL.test(saved[k]))) { changed = true; } else { clean[k] = saved[k]; }
			}
		}
		if(!changed) { return orig.apply(this,arguments); }
		this.attributes = clean;
		try { return orig.apply(this,arguments); } finally { this.attributes = saved; }
	};
	W.prototype.assignAttributes.encSyncWrapped = true;
}

/* --- 3. token storage --------------------------------------------------------------------------------------------------------- */
function tokenMode() { var m = cfgText(CFG_TOKEN); return m === "local" || m === "memory" ? m : "session"; }
function installTokenPolicy() {
	var U = $tw.utils, origGet = U.getPassword, origSave = U.savePassword, mem = "";
	if(typeof origGet !== "function" || typeof origSave !== "function") { return; }
	function store(kind) { try { return window[kind + "Storage"]; } catch(e) { return null; } }
	U.savePassword = function(name,password) {
		var mode = tokenMode(), s;
		if(name !== "github" || mode === "local") { return origSave.apply(this,arguments); }
		mem = String(password || "");
		try { store("local").removeItem(TOKEN_KEY); } catch(e) {}
		if($tw.savedPasswords) { delete $tw.savedPasswords.github; }
		s = store("session");
		try { if(s) { if(mem && mode === "session") { s.setItem(TOKEN_KEY,mem); } else { s.removeItem(TOKEN_KEY); } } } catch(e) {}
	};
	U.getPassword = function(name) {
		var mode = tokenMode(), v = "";
		if(name !== "github" || mode === "local") { return origGet.apply(this,arguments); }
		if(mem) { return mem; }
		if(mode === "session") { try { v = store("session").getItem(TOKEN_KEY) || ""; } catch(e) {} }
		return v;
	};
	/* a token an earlier session (or stock TiddlyWiki) left in localStorage is moved out of it, once the mode is known */
	return function adopt() {
		if(tokenMode() === "local") { return; }
		try {
			var old = store("local").getItem(TOKEN_KEY);
			if(old) { store("local").removeItem(TOKEN_KEY); U.savePassword("github",old); }
		} catch(e) {}
	};
}

/* --- 4. syncer alerts / console ----------------------------------------------------------------------------------------------- */
function hardenSyncer(syncer) {
	var logger = syncer.logger;
	if(!logger || typeof logger.log !== "function" || typeof logger.alert !== "function") { return; }
	var origLog = logger.log, origAlert = logger.alert;
	// "Dispatching 'save' task: <tiddler title>" and friends: titles are private data; keep them out of the console unless asked
	logger.log = function() { if(cfgText(CFG_LOG) === "yes") { return origLog.apply(this,arguments); } };
	// The core renders alert text as WIKITEXT ({{||$:/core/ui/AlertTemplate}} -> <$transclude/>) and the syncer puts the tiddler title and
	// adaptor error text into it. Quote it so that titles/error messages are only ever displayed.
	logger.alert = function() {
		var text = Array.prototype.join.call(arguments," ").replace(/"/g,"”");
		return origAlert.call(this,"<$text text=\"" + text + "\"/>");
	};
}

exports.startup = function(callback) {
	var engine = $tw.encSync, syncer = $tw.syncer;
	if(!engine || !syncer) { return callback(); }
	installMessageGuard();
	var adoptToken = installTokenPolicy();
	hardenSyncer(syncer);
	function ready() { hardenHtml(); if(adoptToken) { adoptToken(); } }
	function loadFat(title) {
		return engine.load(title).then(function(fields) { syncer.storeTiddler(fields,true); });
	}
	engine.ready.then(function() {
		engine.skinny().forEach(function(f) { syncer.storeTiddler(f,false); });
		var cfgBlocking = $tw.wiki.getTiddlerText("$:/config/ext/enc/PrefetchBlocking") || BLOCKING;
		var titles = $tw.wiki.filterTiddlers(cfgBlocking).filter(function(t) { return engine.entries[t] && engine.entrySize(t) < MAX_TEXT; });
		return pool(titles,loadFat,PARALLEL);
	}).then(function() {
		ready();
		callback();
		var mode = $tw.wiki.getTiddlerText("$:/config/ext/enc/Prefetch","text");
		if(mode === "text") {
			var bg = $tw.wiki.filterTiddlers(BACKGROUND).filter(function(t) {
				var tid = $tw.wiki.getTiddler(t);
				return engine.entries[t] && tid && tid.fields.text === undefined && engine.entrySize(t) < MAX_TEXT;
			});
			setTimeout(function() { pool(bg,loadFat,3); },500);
		}
	},function(e) {
		showError("Encrypted storage could not be loaded: " + (e && e.message));
		console.error("enc-sync:",plain(e && e.message));
		ready();
		callback();
	});
};
})();
