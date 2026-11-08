/*\
title: $:/plugins/tw-enc-sync/startup-sidebar.js
type: application/javascript
module-type: startup

Mirrors the sidebar show/hide state ($:/state/sidebar) as a class on <html> (tw-sb-hidden) so the theme CSS can let the story use the full width
when the sidebar is hidden.

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";
exports.name = "enc-sync-sidebar";
exports.platforms = ["browser"];
exports.after = ["startup"];
exports.synchronous = true;
exports.startup = function() {
	var wiki = $tw.wiki, root = document.documentElement;
	function sync() { root.classList.toggle("tw-sb-hidden",(wiki.getTiddlerText("$:/state/sidebar","yes") || "yes").trim() === "no"); }
	sync();
	wiki.addEventListener("change",function(changes) { if(changes["$:/state/sidebar"]) { sync(); } });
};
})();
