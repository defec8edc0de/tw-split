/*\
title: $:/plugins/tw-enc-sync/targets.js
type: application/javascript
module-type: library

Save-target selection and orchestration (no TiddlyWiki dependency; unit-testable in Node).
Targets: github (Git Data API commit), folder (File System Access API), zip (download of a store-only zip).

  explicit save (Ctrl+S, Save button, cloud button): ALL configured targets, in the order github -> folder -> zip, prompts allowed
  automatic debounce timer / autosave:               github only if configured; folder only if a stored handle is already writable
                                                     (silent); NEVER zip, NEVER a picker or permission prompt
  "Publish to GitHub now":                            engine.flush({force:true}) whatever SaveTarget says

\*/
(function(){
"use strict";

var ALL = ["github","folder","zip"];

/* "github, folder  zip" -> ["github","folder","zip"]; whitespace/comma tolerant, case-insensitive, unknown tokens ignored, duplicates dropped */
function parseTargets(text) {
	var out = [];
	String(text === undefined || text === null ? "" : text).toLowerCase().split(/[\s,;]+/).forEach(function(t) {
		if(ALL.indexOf(t) !== -1 && out.indexOf(t) === -1) { out.push(t); }
	});
	return out;
}
/* text: the SaveTarget config (undefined when absent). env: {protocol, fsa}. Blank / no valid token => default (a typo must not disable saving).
   A "folder" target in a browser without the File System Access API becomes "zip". Result is ordered github, folder, zip. */
function resolveTargets(text,env) {
	env = env || {};
	var list = parseTargets(text);
	if(!list.length) { list = [env.protocol === "file:" ? "folder" : "github"]; }
	if(list.indexOf("folder") !== -1 && !env.fsa) {
		list = list.filter(function(t) { return t !== "folder"; });
		if(list.indexOf("zip") === -1) { list.push("zip"); }
	}
	return ALL.filter(function(t) { return list.indexOf(t) !== -1; });
}
function isLocal(t) { return t === "folder" || t === "zip"; }

/* Message for the beforeunload dialog, or null. Only ENABLED targets count: no GitHub warning when github is not a target. */
function unloadWarning(engine,targets) {
	var gh = targets.indexOf("github") !== -1, local = targets.some(isLocal), msgs = [];
	if(gh && engine.pending.size > 0) { msgs.push("Unsaved changes are still being committed to GitHub."); }
	if(local && engine.localDirty && engine.localDirty.size > 0) { msgs.push("Changes have not been saved to the local " + (targets.indexOf("folder") !== -1 ? "folder" : "zip") + " yet."); }
	return msgs.length ? msgs.join(" ") : null;
}

/* Let the syncer hand over queued edits to the adaptor first (max ~10 s). ctx: {syncer, setTimeout} */
function waitIdle(ctx) {
	var tries = 0, st = ctx.setTimeout || setTimeout;
	return new Promise(function(resolve) {
		(function go() {
			var s = ctx.syncer;
			if(s && (s.numTasksInQueue() > 0 || s.numTasksInProgress() > 0) && tries++ < 100) { return st(go,100); }
			resolve();
		})();
	});
}

/*
ctx: {engine, getTargets(): string[], sinks: {folder, zip}, syncer, setTimeout}
Explicit save: every configured target in order. A failing target never stops the later ones (the local copy is the safety net for a
failed upload and vice versa); the first error is thrown at the end.
*/
function saveAll(ctx,opts) {
	var engine = ctx.engine, targets = ctx.getTargets(), firstErr = null, p;
	var interactive = !(opts && opts.interactive === false);
	// Ask for the folder/permission NOW, while the click that started the save is still a user gesture (a GitHub upload can take longer
	// than the browser's gesture window). The write itself happens below.
	var warm = Promise.resolve(), s0 = ctx.syncer;
	if(interactive && targets.indexOf("folder") !== -1 && ctx.sinks.folder && typeof ctx.sinks.folder.access === "function" &&
			(engine.localDirty.size || (s0 && (s0.numTasksInQueue() > 0 || s0.numTasksInProgress() > 0)))) {
		warm = engine.manifestFile().then(function(mf) { return ctx.sinks.folder.access(mf,true); }).then(null,function() {});   // errors resurface in the real write
	}
	p = warm.then(function() { return waitIdle(ctx); });
	function run(fn) { p = p.then(fn).then(null,function(e) { if(!firstErr) { firstErr = e; } }); }
	if(targets.indexOf("github") !== -1) { run(function() { return engine.flush(); }); }
	// all local targets get the same snapshot in ONE saveLocal (a second call would find nothing dirty any more)
	var locals = ["folder","zip"].filter(function(t) { return targets.indexOf(t) !== -1; });
	if(locals.length) {
		run(function() {
			var sinks = [], missing = null;
			locals.forEach(function(t) { if(ctx.sinks[t]) { sinks.push(ctx.sinks[t]); } else if(!missing) { missing = new Error("Save target '" + t + "' is not available in this browser."); } });
			var q = sinks.length ? engine.saveLocal(sinks,{interactive: interactive}) : Promise.resolve();
			return q.then(function() { if(missing) { throw missing; } },function(e) { throw e; });
		});
	}
	return p.then(function() { if(firstErr) { throw firstErr; } });
}

/* Debounce timer / autosave. Never rejects (errors land in engine.status), never prompts, never zips. */
function autoSave(ctx) {
	var engine = ctx.engine, targets = ctx.getTargets(), p = Promise.resolve();
	if(targets.indexOf("github") !== -1 && engine.pending.size) {
		p = p.then(function() { return engine.flush(); }).then(null,function() {});
	}
	if(targets.indexOf("folder") !== -1 && ctx.sinks.folder && engine.localDirty.size) {
		var sink = ctx.sinks.folder;
		p = p.then(function() { return sink.hasPermission(); }).then(function(ok) {
			if(ok) { return engine.saveLocal(sink,{interactive: false}); }
		}).then(null,function() {});
	}
	return p;
}

/* "Publish to GitHub now": whole local state -> GitHub (seeds an empty repository), independent of SaveTarget. */
function publish(ctx) {
	return waitIdle(ctx).then(function() { return ctx.engine.flush({force: true}); });
}

exports.ALL = ALL; exports.parseTargets = parseTargets; exports.resolveTargets = resolveTargets; exports.unloadWarning = unloadWarning;
exports.waitIdle = waitIdle; exports.saveAll = saveAll; exports.autoSave = autoSave; exports.publish = publish; exports.isLocal = isLocal;
})();
