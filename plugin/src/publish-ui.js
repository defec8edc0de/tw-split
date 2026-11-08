/*\
title: $:/plugins/tw-enc-sync/publish-ui.js
type: application/javascript
module-type: startup

Publish tiddlers tagged "publish:blog" as plaintext Markdown posts (see publish.js and docs/THREAT-MODEL.md "Publishing").
Flow: view-toolbar button -> tm-enc-post-preview (builds the post, shows the exact bytes in a modal)
      -> modal button tm-enc-post-confirm -> rebuilt from the live tiddler, must equal the preview -> NATIVE window.confirm -> one commit.
Wikitext can send these messages too; the native confirm (which wikitext cannot fake or auto-accept) is the real consent gate.
Never runs from timers, autosave, Save or "Publish to GitHub now".

\*/
(function(){
/*jslint node: true, browser: true */
/*global $tw: false */
"use strict";
exports.name = "enc-sync-publish";
exports.platforms = ["browser"];
exports.after = ["rootwidget","enc-sync-ui"];
exports.before = ["story","render"];
exports.synchronous = true;

var PREVIEW = "$:/temp/ext/pub/preview", STATUS = "$:/temp/ext/pub/status", MODAL = "$:/plugins/tw-enc-sync/ui/publish-modal";

function plain(s) { return String(s === undefined || s === null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g," ").substr(0,2000); }
function setStatus(msg,state) {
	$tw.wiki.addTiddler(new $tw.Tiddler({title: STATUS, type: "text/plain", text: plain(msg), state: state || "info"}));
	try { if($tw.notifier) { $tw.notifier.display(STATUS); } } catch(e) {}
}
function ask(msg) { try { return typeof window.confirm === "function" ? !!window.confirm(msg) : false; } catch(e) { return false; } }

exports.startup = function() {
	if(!$tw.encSync || !$tw.rootWidget) { return; }
	var P = require("$:/plugins/tw-enc-sync/publish.js"), G = require("$:/plugins/tw-enc-sync/github.js"), C = require("$:/plugins/tw-enc-sync/md-convert.js");
	var busy = false, previewed = null;   // {title, markdown, path} of the last preview (closure: content cannot forge it)

	function fieldsOf(title) { var t = $tw.wiki.getTiddler(title); return t ? t.fields : null; }
	function convert(text,fields) { var c = C.classify(text,fields); return c && c.status === "convertible" ? C.convert(text) : null; }
	function resolve(target) {
		var f = fieldsOf(target);
		if(!f || !P.hasTag(f) || !f[P.FIELDS.sha]) { return null; }   // only posts that are actually published become links
		var slug = String(f[P.FIELDS.slug] || "");
		if(!P.SLUG_RE.test(slug)) { return null; }
		return (String(f[P.FIELDS.lang] || "en") === "de" ? "/de" : "") + "/blog/" + slug + "/";
	}
	function build(title) {
		var f = fieldsOf(title);
		return P.buildPost(f,{convert: convert, resolve: resolve, mediaFields: fieldsOf, now: new Date().toISOString().replace(/\.\d+Z$/,"Z")});
	}
	function client() {
		var e = $tw.encSync, token = e.d && e.d.getToken && e.d.getToken();
		if(!token) { throw new Error("GitHub token missing: enter it in Control Panel > Saving > GitHub"); }
		return new G.Client({repo: e.cfg.repo, branch: e.cfg.branch, apiBase: e.cfg.apiBase, token: token, fetch: e.d.fetch, timeoutMs: e.d.requestTimeoutMs});
	}
	function titleOf(ev) {
		var t = ev && (typeof ev.param === "string" && ev.param ? ev.param : ev.tiddlerTitle);
		return typeof t === "string" ? t : "";
	}

	$tw.rootWidget.addEventListener("tm-enc-post-preview",function(ev) {
		var title = titleOf(ev), cur = $tw.wiki.getTiddler(title);
		// one-click start: an untagged note is turned into a blog post (tag publish:blog) after a native confirm
		if(cur && title.indexOf("$:/") !== 0 && !cur.fields["draft.of"] && !P.hasTag(cur.fields)) {
			if(!ask("Turn \"" + title + "\" into a blog post?\n\nThis adds the tag " + P.TAG + " and opens a preview. Nothing is published until you confirm the preview.")) { return false; }
			$tw.wiki.addTiddler(new $tw.Tiddler(cur.fields,{tags: (cur.fields.tags || []).concat([P.TAG])}));
		}
		try {
			var post = build(title);
			previewed = {title: title, markdown: post.markdown, path: post.path};
			var f = fieldsOf(title);
			$tw.wiki.addTiddler(new $tw.Tiddler({title: PREVIEW, type: "text/plain", text: post.markdown, "post-title": title, "post-path": post.path,
				"post-media": post.media.map(function(m) { return m.path; }).join(" "), "post-published": f[P.FIELDS.sha] ? "yes" : "no", "post-lang": post.lang}));
		} catch(e) { previewed = null; setStatus("Not published: " + (e && e.message || e),"error"); return false; }
		try { $tw.modal.display(MODAL,{event: ev || {}, variables: {rootwindow: "yes"}}); } catch(e) { setStatus("Preview ready in " + PREVIEW + " (the dialog could not be shown).","info"); }
		return false;
	});

	$tw.rootWidget.addEventListener("tm-enc-post-confirm",function() {
		if(busy) { return false; }
		var pv = previewed; previewed = null;
		if(!pv) { setStatus("Open the preview first (Publish post button).","error"); return false; }
		var post;
		try { post = build(pv.title); } catch(e) { setStatus("Not published: " + (e && e.message || e),"error"); return false; }
		if(post.markdown !== pv.markdown || post.path !== pv.path) { setStatus("The tiddler changed after the preview; open the preview again.","error"); return false; }
		var lines = post.markdown.split("\n").length, kb = Math.ceil(post.markdown.length / 1024);
		if(!ask("Publish \"" + pv.title + "\" as PUBLIC plaintext?\n\n" + post.path + " (" + lines + " lines, " + kb + " KB)" +
			(post.media.length ? "\n+ " + post.media.length + " image(s)" : "") + "\n\nAnyone can read it once the site rebuilds. Git history keeps it even after unpublishing.")) { setStatus("Publishing cancelled.","info"); return false; }
		var f = fieldsOf(pv.title), gh;
		try { gh = client(); } catch(e) { setStatus(e.message,"error"); return false; }
		busy = true; setStatus("Publishing " + post.path + " …","busy");
		var run = function(force) {
			return P.publish(gh,post,{lastSha: f[P.FIELDS.sha] || null, force: force});
		};
		run(false).catch(function(e) {
			if(e && e.code === "conflict" && ask("The published post was changed outside the vault since your last publish.\n\nOverwrite it with this version?")) { return run(true); }
			throw e;
		}).then(function(r) {
			busy = false;
			var cur = $tw.wiki.getTiddler(pv.title), upd = {};
			upd[P.FIELDS.slug] = post.slug; upd[P.FIELDS.sha] = r.sha; upd[P.FIELDS.date] = $tw.utils.stringifyDate(new Date());
			if(cur) { $tw.wiki.addTiddler(new $tw.Tiddler(cur.fields,upd)); }   // encrypted save happens through the normal sync (separate commit)
			setStatus(r.unchanged ? "Already up to date: " + post.path : "Published " + post.path + (r.commit ? " (commit " + r.commit.substr(0,7) + "). The site rebuilds in about a minute." : ""),"ok");
			$tw.wiki.deleteTiddler(PREVIEW);
		},function(e) { busy = false; setStatus("Not published: " + (e && e.message || e),"error"); });
		return false;
	});

	$tw.rootWidget.addEventListener("tm-enc-post-unpublish",function(ev) {
		if(busy) { return false; }
		var title = titleOf(ev) || (previewed ? previewed.title : ""), f = fieldsOf(title);
		if(!f || !P.hasTag(f) || !f[P.FIELDS.slug]) { setStatus("Nothing to unpublish for this tiddler.","error"); return false; }
		var slug = String(f[P.FIELDS.slug]), lang = String(f[P.FIELDS.lang] || "en") === "de" ? "de" : "en";
		if(!ask("Unpublish \"" + title + "\"?\n\nRemoves content/blog/" + slug + "/" + (lang === "de" ? "index.de.md" : "index.md") + " from the site. It stays in the git history.")) { return false; }
		var gh; try { gh = client(); } catch(e) { setStatus(e.message,"error"); return false; }
		busy = true; setStatus("Unpublishing " + slug + " …","busy");
		P.unpublish(gh,slug,lang).then(function(r) {
			busy = false;
			var cur = $tw.wiki.getTiddler(title);
			if(cur) { var upd = {}; upd[P.FIELDS.sha] = undefined; upd[P.FIELDS.date] = undefined; $tw.wiki.addTiddler(new $tw.Tiddler(cur.fields,upd)); }
			setStatus(r.removed.length ? "Unpublished " + slug + " (" + r.removed.length + " file(s) removed)." : "Not found on the site: " + slug,"ok");
		},function(e) { busy = false; setStatus("Not unpublished: " + (e && e.message || e),"error"); });
		return false;
	});
};
})();
