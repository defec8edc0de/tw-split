/*\
title: $:/plugins/tw-enc-sync/startup-ui.js
type: application/javascript
module-type: startup

Registers the "save now" (tm-enc-flush) and "publish to GitHub now" (tm-enc-publish) messages once the root widget exists, and refuses script-URL activation from tiddler content.

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";
exports.name = "enc-sync-ui";
exports.platforms = ["browser"];
exports.after = ["rootwidget"];
exports.before = ["story","render"];
exports.synchronous = true;

/* Browsers drop tabs/newlines anywhere in a URL and leading C0 controls/spaces before parsing the scheme. */
var JS_URL = /^[\u0000- ]*j[\t\n\r]*a[\t\n\r]*v[\t\n\r]*a[\t\n\r]*s[\t\n\r]*c[\t\n\r]*r[\t\n\r]*i[\t\n\r]*p[\t\n\r]*t[\t\n\r]*:/i;
function isScriptUrl(v) { return typeof v === "string" && JS_URL.test(v); }
function attr(n,names) {
	for(var i=0; i<names.length; i++) { if(isScriptUrl(n.getAttribute(names[i]))) { return true; } }
	return false;
}
/* Wikitext allows raw <a href="javascript:...">, <form action=...>, <button formaction=...> (core 5.1.21 only strips on* attributes).
   Such a link would run in this origin (token, engine). Capturing listeners on the document cancel the activation. */
function blockScriptUrls() {
	function stop(ev) { ev.preventDefault(); ev.stopImmediatePropagation(); }
	function onClick(ev) {
		for(var n = ev.target; n && n.nodeType === 1; n = n.parentNode) {
			if(attr(n,["href","xlink:href","formaction"])) { return stop(ev); }
		}
	}
	function onSubmit(ev) {
		var f = ev.target, s = ev.submitter;
		if((f && f.getAttribute && attr(f,["action"])) || (s && s.getAttribute && attr(s,["formaction"]))) { stop(ev); }
	}
	document.addEventListener("click",onClick,true);
	document.addEventListener("auxclick",onClick,true);
	document.addEventListener("submit",onSubmit,true);
}

exports.startup = function() {
	if(!$tw.encSync) { return; }
	blockScriptUrls();
	var busy = false;
	function fail(e) {
		$tw.wiki.addTiddler(new $tw.Tiddler({title: "$:/temp/ext/enc/error", type: "text/plain", text: String(e && e.message || "save failed").replace(/[^\x20-\x7e\u00a0-\uffff]/g," ").substr(0,700)}));
	}
	function ok() { $tw.wiki.deleteTiddler("$:/temp/ext/enc/error"); }
	// Any tiddler content can send these messages (<$button message="tm-enc-flush"/>, <$action-sendmessage/>): ignore their parameters
	// and run at most one wait-and-save cycle at a time so that a hostile/looping tiddler cannot pile up timers or API calls.
	function once(fn) {
		return function() {
			if(busy || !$tw.encTargets) { return; }
			busy = true;
			var ctx = $tw.encTargets, T = require("$:/plugins/tw-enc-sync/targets.js");
			fn(T,ctx).then(function() { busy = false; ok(); },function(e) { busy = false; fail(e); });   // the click is still a user gesture here (folder picker / permission)
		};
	}
	// cloud button: all configured targets (like Ctrl+S)
	$tw.rootWidget.addEventListener("tm-enc-flush",once(function(T,ctx) { return T.saveAll(ctx,{interactive: true}); }));
	// "Publish to GitHub now": whole local state -> GitHub whatever SaveTarget says (seeds an empty repository)
	$tw.rootWidget.addEventListener("tm-enc-publish",once(function(T,ctx) { return T.publish(ctx); }));
};
})();
