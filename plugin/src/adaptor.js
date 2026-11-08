/*\
title: $:/plugins/tw-enc-sync/adaptor.js
type: application/javascript
module-type: syncadaptor

Syncadaptor: every tiddler lives in its own AES-GCM encrypted file in the GitHub Pages repo.
Uses only public TiddlyWiki APIs (syncadaptor, startup, saver modules; $tw.utils.getPassword).

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

if(!$tw.browser) { return; }

var CFG = "$:/ext/enc/config", DEK = "$:/ext/enc/dek", STATUS = "$:/temp/ext/enc/status", TARGET_CFG = "$:/config/ext/enc/SaveTarget";
var IGNORE_RE = /^\$:\/(?:ext\/enc\/|temp\/|state\/|status\/|StoryList$|HistoryList$|isEncrypted$|Import)/;

/* The boot kernel keeps every decrypted tiddler's field object in $tw.preloadTiddlers for the life of the page, so
   deleting the key tiddler from the wiki store alone leaves it reachable (and readable) from that global array. */
function scrubPreload(title) {
	var a = $tw.preloadTiddlers, i;
	if(!a || typeof a.length !== "number") { return; }
	for(i=a.length-1; i>=0; i--) {
		if(a[i] && a[i].title === title) { try { a[i].text = ""; } catch(e) {} a.splice(i,1); }
	}
}

/* TiddlyWiki keeps the (stage-1) password in a closure and uses it to re-encrypt a whole-wiki save, and anybody who can
   run script in the page could call $tw.crypto.decrypt() on the still-present encrypted bootstrap blob to recover the key.
   After unlock the password has no further job here, so drop it and make it impossible to set again. */
function lockCrypto(logger) {
	var c = $tw.crypto;
	if(!c || typeof c.setPassword !== "function") { return; }
	try { c.setPassword(null); } catch(e) {}
	c.setPassword = function(pw) {
		if(pw) { try { window.alert("Password changes are not supported inside the split wiki: the password protects the stage-1 file, which this page never rewrites. Use tools/twmigrate.py rotate."); } catch(e) {} }
		if(c.updateCryptoStateTiddler) { c.updateCryptoStateTiddler(); }
	};
}

/* Messages end up in alerts/tiddlers: short, printable. (The syncer's alerts are additionally quoted, see startup.js.) */
function plain(s) { return String(s === undefined ? "" : s).replace(/[^\x20-\x7e\u00a0-\uffff]/g," ").substr(0,300); }
function fixed(obj,name,value) {   // a property other scripts cannot replace/delete (they can still use it: the page is one trust domain)
	try { Object.defineProperty(obj,name,{value: value, writable: false, configurable: false, enumerable: false}); }
	catch(e) { try { obj[name] = value; } catch(e2) {} }
}

function EncAdaptor(options) {
	var self = this, wiki = options.wiki;
	this.wiki = wiki;
	this.logger = new $tw.utils.Logger("enc-sync");
	this.engine = null; this.sinks = null; this.ctx = null; this.Targets = null;
	var cfgText = wiki.getTiddlerText(CFG), dekText = wiki.getTiddlerText(DEK);
	// Remove the key from the store (and from the boot kernel's preload list) FIRST, before anything that can throw.
	if(wiki.tiddlerExists(DEK)) { wiki.deleteTiddler(DEK); }
	scrubPreload(DEK);
	if(!cfgText || !dekText) {
		if(cfgText || dekText) { fixed($tw,"encSyncGuard",true); }   // half-present bootstrap: fail closed (no whole-wiki saving)
		this.logger.log("bootstrap tiddlers missing; adaptor inactive");
		dekText = null; return;
	}
	fixed($tw,"encSyncGuard",true);   // from here on the stage-1 file must never be re-saved by a stock saver (see saver-guard.js)
	var cfg, dek;
	try {
		var Engine = require("$:/plugins/tw-enc-sync/engine.js").Engine, F = require("$:/plugins/tw-enc-sync/encfmt.js");
		var LS = require("$:/plugins/tw-enc-sync/localsink.js"), Targets = require("$:/plugins/tw-enc-sync/targets.js");
		cfg = JSON.parse(cfgText); dek = F.b64decode(dekText.trim()); dekText = null;
		// The key lives only in the engine's closure/CryptoKeys from now on.
		this.engine = new Engine({
			cfg: cfg, dek: dek, fetch: window.fetch.bind(window), baseUrl: window.location.href,   // not document.baseURI: a <base> element must not be able to redirect the encrypted-file fetches
			getToken: function() { return $tw.utils.getPassword("github") || undefined; },
			storage: (function() { try { return window.localStorage; } catch(e) { return null; } })(),
			isBase64Type: function(type) { var i = type && $tw.config.contentTypeInfo[type]; return !!(i && i.encoding === "base64"); },
			categoryOrder: function() { return (wiki.getTiddlerText("$:/config/ext/enc/CategoryOrder","") || "").split(",").map(function(s) { return s.trim(); }).filter(Boolean); },
			getTargets: function() { return self.targets(); },
			autoSave: function() { return Targets.autoSave(self.ctx); },   // debounce timer: github if configured, silent folder write if already permitted, never zip, never a prompt
			onStatus: function(st) {
				wiki.addTiddler(new $tw.Tiddler({title: STATUS, text: JSON.stringify(st), type: "application/json",
					unpublished: String(st.pending || 0), "unsaved-local": String(st.localDirty || 0), targets: self.targets().join(", ")}));
			}
		});
		this.sinks = {zip: new LS.ZipSink(), folder: LS.FolderSink.supported(window) ? new LS.FolderSink({window: window}) : null};
		this.ctx = {engine: this.engine, getTargets: function() { return self.targets(); }, sinks: this.sinks, get syncer() { return $tw.syncer; }, setTimeout: function(f,ms) { return window.setTimeout(f,ms); }};
		this.Targets = Targets;
	} catch(e) {
		if(dek) { try { dek.fill(0); } catch(e2) {} }
		this.engine = null;
		this.logger.alert("<$text text=\"enc-sync: could not start (" + plain(e && e.message).replace(/"/g,"\u201d") + "). Saving is disabled.\"/>");
		return;
	}
	lockCrypto(this.logger);
	fixed($tw,"encSync",this.engine);
	fixed($tw,"encTargets",this.ctx);
	$tw.addUnloadTask(function(event) {
		var msg = self.Targets.unloadWarning(self.engine,self.targets());   // only for ENABLED targets
		if(msg) { event.returnValue = msg; return msg; }
	});
}
/* Save targets: $:/config/ext/enc/SaveTarget (comma list of github, folder, zip; read through the wiki so it can be changed in the app).
   Default: file: -> folder (zip when the File System Access API is missing), http(s) -> github. */
EncAdaptor.prototype.targets = function() {
	if(!this.Targets) { return ["github"]; }
	var t = this.wiki.getTiddler(TARGET_CFG), text;
	if(t && t.fields._is_skinny === undefined && typeof t.fields.text === "string") { text = t.fields.text; }   // never triggers a lazy load
	return this.Targets.resolveTargets(text,{protocol: window.location.protocol, fsa: !!(this.sinks && this.sinks.folder)});
};
EncAdaptor.prototype.name = "enc-github";
EncAdaptor.prototype.supportsLazyLoading = true;
EncAdaptor.prototype.isReady = function() { return !!this.engine && this.engine.status.state !== "init"; };
EncAdaptor.prototype.getTiddlerInfo = function(tiddler) { return {}; };
EncAdaptor.prototype.getTiddlerRevision = function(title) { var e = this.engine && this.engine.entries[title]; return e ? String(e.r) : undefined; };

EncAdaptor.prototype.getSkinnyTiddlers = function(callback) {
	if(!this.engine) { return callback(null,[]); }
	var engine = this.engine;
	engine.ready.then(function() { callback(null,engine.skinny()); },function(e) { callback(new Error(plain(e && e.message))); });
};
/* True when the wiki holds a fully loaded copy of the tiddler that has changed since the syncer last stored/saved it (unsaved local change). */
EncAdaptor.prototype.hasUnsavedChange = function(title) {
	var wiki = this.wiki, cur = wiki && wiki.getTiddler(title), info = typeof $tw !== "undefined" && $tw.syncer && $tw.syncer.tiddlerInfo && $tw.syncer.tiddlerInfo[title];
	if(!cur || !info || cur.fields._is_skinny !== undefined || typeof cur.fields.text !== "string" || typeof wiki.getChangeCount !== "function") { return false; }
	return info.changeCount !== wiki.getChangeCount(title);
};
EncAdaptor.prototype.loadTiddler = function(title,callback) {
	if(!this.engine) { return callback(null,null); }
	var self = this;
	this.engine.load(title).then(function(f) {
		// A "load" task can sit in the syncer queue from the time the tiddler was still a stub (lazy load on first read, or a poll that saw a
		// different revision). When it finally runs, the stored copy must not replace a change made in between (e.g. the palette switched
		// at startup, or a note edited right after opening): that change is queued for saving and wins. Returning null stores nothing.
		callback(null,self.hasUnsavedChange(title) ? null : f);
	},function(e) { callback(new Error("load failed: " + plain(e && e.message))); });
};
EncAdaptor.prototype.saveTiddler = function(tiddler,callback,options) {
	var title = tiddler.fields.title, engine = this.engine;
	if(!engine || IGNORE_RE.test(title)) { return callback(null,{},undefined); }
	if(tiddler.fields["plugin-type"] && title.indexOf("$:/") === 0) { return callback(new Error("Plugins/themes live in the stage-1 HTML and are not synced per tiddler (use the migration tool's add-plugin).")); }
	function done(p) { p.then(function(rev) { callback(null,{},rev); },function(e) { callback(new Error(plain(e && e.message))); }); }
	// A still-skinny tiddler carries a placeholder text (""), not its content. Core does not stop the syncer from saving such a tiddler when
	// any other field changes (tag/list/rename side effects, plugins that stamp ids on every tiddler, ...): committing it as is would
	// overwrite the real note with an empty one. Fetch the real text first and save metadata + real text.
	if(tiddler.fields._is_skinny !== undefined) {
		return done(engine.load(title).then(function(full) {
			var fields = tiddler.getFieldStrings();
			fields.text = full.text;
			return engine.save(title,fields);
		}));
	}
	done(engine.save(title,tiddler.getFieldStrings()));
};
EncAdaptor.prototype.deleteTiddler = function(title,callback,options) {
	if(!this.engine || IGNORE_RE.test(title)) { return callback(null); }
	this.engine.remove(title).then(function() { callback(null); },function(e) { callback(new Error(plain(e && e.message))); });
};
exports.adaptorClass = EncAdaptor;
})();
