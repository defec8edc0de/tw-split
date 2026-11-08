/*\
title: $:/plugins/tw-enc-sync/startup-newtype.js
type: application/javascript
module-type: startup

New tiddlers start as Markdown: when a brand-new, still empty draft is created (new-tiddler / journal buttons) and it has no type yet,
the type from $:/config/ext/DefaultNewType (default text/x-markdown) is preselected. Set that tiddler's text to empty to switch it off.
Only runs when the Markdown plugin is installed. Existing tiddlers and imports are never touched.

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";
exports.name = "enc-sync-newtype";
exports.platforms = ["browser"];
exports.after = ["startup"];
exports.synchronous = true;
exports.startup = function() {
	var wiki = $tw.wiki;
	wiki.addEventListener("change",function(changes) {
		var type = wiki.getTiddlerText("$:/config/ext/DefaultNewType","text/x-markdown");
		type = type && type.trim();
		if(!type || !wiki.getTiddler("$:/plugins/anstosa/tw5-markdown")) { return; }
		$tw.utils.each(changes,function(change,title) {
			if(change.deleted) { return; }
			var tiddler = wiki.getTiddler(title), f = tiddler && tiddler.fields;
			if(!f || f["draft.of"] === undefined || f.type !== undefined || f.text) { return; }
			if(wiki.tiddlerExists(f["draft.of"])) { return; }   // editing an existing tiddler, not creating one
			wiki.addTiddler(new $tw.Tiddler(tiddler,{type: type}));
		});
	});
};
})();
