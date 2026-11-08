/*\
title: $:/plugins/tw-enc-sync/saver-guard.js
type: application/javascript
module-type: saver

The stage-1 HTML must never be re-saved from the browser (it would drop the key, embed whatever happens to be loaded
and, with a stock saver such as the GitHub one, overwrite the live wiki with a broken file).
"Save" therefore means: write all pending encrypted changes to every configured save target now (GitHub commit, local folder, zip download;
see $:/config/ext/enc/SaveTarget and targets.js). Whole-wiki "download" is refused (partial, and in
plaintext once the password is gone); other downloads (single-tiddler / JSON / CSV exports) are passed on untouched.

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";

var WHOLE_WIKI_RE = /<(?:div id="storeArea"|pre id="encryptedStoreArea")/;

function Guard(wiki) { this.wiki = wiki; }
Guard.prototype.save = function(text,method,callback) {
	var engine = $tw.encSync;
	if(method === "download") {
		if(typeof text !== "string" || !WHOLE_WIKI_RE.test(text)) { return false; }   // an ordinary export: let the download saver have it
		callback(new Error("Downloading the whole wiki is disabled: it would contain only the tiddlers loaded so far, decrypted. Use the export buttons for selected tiddlers, or tools/twmigrate.py inline for a full backup."));
		return true;
	}
	if(!engine) {   // bootstrap present but the engine failed to start: fail closed instead of letting a stock saver overwrite tw.html
		callback(new Error("Encrypted storage is not active, so nothing can be saved (the stage-1 file is never re-saved)."));
		return true;
	}
	// Ctrl+S / Save button: every configured target (github, then folder / zip) once the syncer has handed over its queue.
	// "autosave" is the unattended variant: no prompts, no zip (same rules as the debounce timer).
	var ctx = $tw.encTargets, T = $tw.encSync && ctx && require("$:/plugins/tw-enc-sync/targets.js");
	if(!ctx || !T) { engine.flush().then(function() { callback(null); },function(e) { callback(e); }); return true; }
	if(method === "autosave") { T.waitIdle(ctx).then(function() { return T.autoSave(ctx); }).then(function() { callback(null); },function(e) { callback(e); }); return true; }
	T.saveAll(ctx,{interactive: true}).then(function() { callback(null); },function(e) { callback(e); });
	return true;
};
Guard.prototype.info = {name: "enc-sync-guard", priority: 100000, capabilities: ["save","autosave","download"]};
exports.canSave = function(handler) { return !!($tw.browser && ($tw.encSync || $tw.encSyncGuard)); };
exports.create = function(wiki) { return new Guard(wiki); };
})();
