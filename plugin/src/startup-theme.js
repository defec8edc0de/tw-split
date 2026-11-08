/*\
title: $:/plugins/tw-enc-sync/startup-theme.js
type: application/javascript
module-type: startup

One-time default: switch the palette to "Cyber" the first time this plugin runs, then never touch it again (marker tiddler
$:/config/ext/theme/Applied). Change the palette any time in Control Panel > Appearance; switch the overlay stylesheet off by creating
$:/config/ext/theme/CyberMedia with the text "not all".

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";
exports.name = "enc-sync-theme";
exports.platforms = ["browser"];
exports.after = ["enc-sync-load"];
exports.before = ["story","rootwidget","render"];
exports.synchronous = true;
exports.startup = function() {
	var wiki = $tw.wiki;
	if(!$tw.encSync) { return; }
	// 1. palette (one time)
	if(wiki.getTiddler("$:/palettes/tw-split/Cyber") && !wiki.getTiddler("$:/config/ext/theme/Applied")) {
		wiki.addTiddler(new $tw.Tiddler({title: "$:/config/ext/theme/Applied", text: "yes"}));
		wiki.addTiddler(new $tw.Tiddler({title: "$:/palette", text: "$:/palettes/tw-split/Cyber"}));
	}
	// 1b. (one time) show the theme "about" icon in the sidebar icon block (the top bar no longer carries it); the settings gear is already there
	var ABOUT = "$:/themes/telmiger/navigator/ui/Buttons/about";
	if(wiki.getTiddler(ABOUT) && !wiki.getTiddler("$:/config/ext/theme/SidebarIcons")) {
		wiki.addTiddler(new $tw.Tiddler({title: "$:/config/ext/theme/SidebarIcons", text: "yes"}));
		wiki.addTiddler(new $tw.Tiddler({title: "$:/config/PageControlButtons/Visibility/" + ABOUT, text: "show"}));
	}
	// 2. TiddlyMap (one time): readable node colours, the Map tab follows the current note, plus an "Everything" view
	var TM = "$:/plugins/felixhayashi/tiddlymap/";
	if(!wiki.getTiddler(TM.slice(0,-1)) || wiki.getTiddler("$:/config/ext/theme/MapSeeded")) { return; }
	function styleIfStock(title,stock,style) {
		var t = wiki.getTiddler(TM + "graph/nodeTypes/" + title);
		if(t && t.fields.style === stock) { wiki.addTiddler(new $tw.Tiddler(t,{style: style})); }
	}
	styleIfStock("tmap:central-topic",'{"font":{"size":22,"color":"rgba(0,0,0,1)"},"shape":"star"}','{"font":{"size":18,"color":"#fec503"},"shape":"star","color":{"background":"#3a2d05","border":"#fec503","highlight":{"background":"#4d3b06","border":"#fec503"},"hover":{"background":"#4d3b06","border":"#fec503"}}}');
	styleIfStock("tmap:neighbour",'{"color":"#565656"}','{"color":{"background":"#10202e","border":"#3a5a75","highlight":{"background":"#1b3a4d","border":"#fec503"},"hover":{"background":"#1b3a4d","border":"#a3d900"}},"font":{"color":"#a9bfca"}}');
	var holder = wiki.getTiddler(TM + "misc/defaultViewHolder");
	if(holder && holder.fields.text === "Default") { wiki.addTiddler(new $tw.Tiddler(holder,{text: "Live View"})); }
	var V = TM + "graph/views/Everything";
	if(!wiki.getTiddler(V)) {
		wiki.addTiddler(new $tw.Tiddler({title: V, isview: "true", "config.physics_mode": "true", "config.neighbourhood_scope": "0",
			"config.vis": '{"physics":{"forceAtlas2Based":{"gravitationalConstant":-70,"springLength":70,"springConstant":0.05,"damping":0.5}}}'}));
		wiki.addTiddler(new $tw.Tiddler({title: V + "/filter/nodes", filter: "[!is[system]!is[image]]"}));
		wiki.addTiddler(new $tw.Tiddler({title: V + "/filter/edges", filter: "[prefix[" + TM + "graph/edgeTypes]]"}));
	}
	wiki.addTiddler(new $tw.Tiddler({title: "$:/config/ext/theme/MapSeeded", text: "yes"}));
};
})();
