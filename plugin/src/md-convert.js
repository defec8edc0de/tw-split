/*\
title: $:/plugins/tw-enc-sync/md-convert.js
type: application/javascript
module-type: library

Safe WikiText to Markdown converter (pure functions, no TiddlyWiki dependency, runs in Node and in the browser).

classify(text,fields) says whether a tiddler can be converted without guessing. convert(text) returns the Markdown, or the
UNCHANGED text if any construct is not understood. Every rule mirrors the parser of TiddlyWiki 5.1.21 (wikiparser rules) and the
behaviour of the anstosa/tw5-markdown 1.1.4 parser (markdown-it, html + linkify + typographer, then each text node re-parsed as wikitext).
Internal links stay in TiddlyWiki syntax because the markdown plugin hands text nodes back to the wikitext parser (link graph, backlinks and
TiddlyMap keep working). The fix module md-convert-startup.js makes those text nodes inline-only so that no space is lost after
inline elements and no block syntax is re-interpreted.

\*/
(function(){
/*jslint node: true, browser: true */
"use strict";

var MD_TYPES = {"text/x-markdown": 1, "text/markdown": 1};
var WIKI_TYPES = {"": 1, "text/vnd.tiddlywiki": 1};
var MAX_REASONS = 25;

/* TiddlyWiki 5.1.21 isLinkExternal / extlink */
var RE_EXTERNAL = /^(?:file|http|https|mailto|ftp|irc|news|data|skype):[^\s<>{}\[\]`|"\\^]+(?:\/|\b)/i;
var RE_EXTLINK = /^(~?)(?:file|http|https|mailto|ftp|irc|news|data|skype):[^\s<>{}\[\]`|"\\^]+(?:\/|\b)/;
var RE_PRETTYLINK = /^\[\[(.*?)(?:\|(.*?))?\]\]/;
var RE_ENTITY = /^&#?[a-zA-Z0-9]{2,8};/;
/* markdown-it typographer: replacements and smart quotes. In a link target or title they would silently change the target. */
var RE_TYPO = /['"`]|--|\.\.|\((?:c|r|p|tm)\)|\+-|!!|\?\?|,,/i;

function Ctx(opts) {
	this.opts = opts || {};
	this.reasons = [];
	this.warnings = [];
	this.hints = {headerRows: 0, headerCells: 0, fuzzy: 0};
	this.plain = [];
}
Ctx.prototype.review = function(msg) { if(this.reasons.indexOf(msg) === -1 && this.reasons.length < MAX_REASONS) { this.reasons.push(msg); } };
Ctx.prototype.warn = function(msg) { if(this.warnings.indexOf(msg) === -1) { this.warnings.push(msg); } };

/* ---- character classes (CommonMark flanking rules) ---- */
var RE_PUNCT = /[\p{P}\p{S}]/u;
function cls(ch) {
	if(ch === "" || ch === undefined || /\s/.test(ch)) { return "ws"; }
	return RE_PUNCT.test(ch) ? "p" : "w";
}
function leftFlanking(prev,next) { var n = cls(next), p = cls(prev); return n !== "ws" && !(n === "p" && p === "w"); }
function rightFlanking(prev,next) { var p = cls(prev), n = cls(next); return p !== "ws" && !(p === "p" && n === "w"); }
function isAlnum(ch) { return !!ch && /[\p{L}\p{N}]/u.test(ch); }

/* ---- hazards for text that is copied verbatim into Markdown ---- */
/* Raw TiddlyWiki fragments ([[Title]], [img[x]]) that stay as they are inside Markdown text. */
function rawProblem(str) {
	if(/[*\\`<>&~\[\]\n]/.test(str)) { return "contains a character Markdown would interpret"; }
	if(/(?:^|[^A-Za-z0-9])_|_(?:[^A-Za-z0-9]|$)/.test(str)) { return "contains an underscore at a word boundary"; }
	if(RE_TYPO.test(str)) { return "contains a quote, dash or ellipsis that the markdown typographer rewrites"; }
	return "";
}
/* Plain text -> Markdown text (visible characters stay identical). */
function escapeText(str,ctx,inCell) {
	var out = "", i, ch;
	for(i = 0; i < str.length; i++) {
		ch = str.charAt(i);
		if(ch === "\\") { out += "\\\\"; }
		else if(ch === "*" || ch === "[" || ch === "]" || ch === "`") { out += "\\" + ch; }
		else if(ch === "_") { out += (isAlnum(str.charAt(i - 1)) && isAlnum(str.charAt(i + 1))) ? "_" : "\\_"; }
		else if(ch === "|" && inCell) { out += "\\|"; }
		else { out += ch; }
	}
	return out;
}
/* A line that Markdown would read as block syntax at its start gets its first marker character escaped. */
function escapeLineStart(line) {
	var m;
	if((m = /^([-+])(?=\s|$)/.exec(line))) { return "\\" + line; }
	if((m = /^(\d{1,9})([.)])(?=\s|$)/.exec(line))) { return m[1] + "\\" + line.slice(m[1].length); }
	if(/^#{1,6}(?=\s|$)/.test(line)) { return "\\" + line; }
	if(/^>/.test(line)) { return "\\" + line; }
	if(/^(?:=+|-+)\s*$/.test(line)) { return "\\" + line; }
	if(/^(?:```|~~~)/.test(line)) { return "\\" + line; }
	if(/^\|/.test(line)) { return "\\" + line; }
	return line;
}
function urlText(url) {
	/* bare URL stays bare only when markdown-it linkify and the TiddlyWiki URL rule must agree about its extent */
	return url;
}
function urlSafeBare(url,next) {
	return /^(?:https?|ftp):\/\/[A-Za-z0-9\-.~%\/?#=+:@!$,;]*[A-Za-z0-9\/]$/.test(url) && /^$|^[\s.,;:!?)]/.test(next);
}
function isHttpUrl(u) { return /^https?:\/\/[^\s()<>\\"]+$/i.test(u); }

/* ---- the inline tokenizer (TiddlyWiki inline rules, left to right) ---- */
var EMPH = [
	{tok: "''", name: "bold", open: "**", close: "**", star: true},
	{tok: "//", name: "italic", open: "*", close: "*", star: true},
	{tok: "~~", name: "strikethrough", open: "~~", close: "~~", star: true},
	{tok: "__", name: "underline", open: "<u>", close: "</u>", star: false},
	{tok: "^^", name: "superscript", open: "<sup>", close: "</sup>", star: false},
	{tok: ",,", name: "subscript", open: "<sub>", close: "</sub>", star: false}
];
function lastChar(s) { return s.length ? s.charAt(s.length - 1) : ""; }
function runLength(s,p,ch) { var n = 0; while(s.charAt(p + n) === ch) { n++; } return n; }

/* mode.cell: the run is a table cell (pipes escaped); returns the Markdown string. */
function inline(ctx,s,mode) {
	mode = mode || {};
	var pos = 0;
	function parseRun(term) {
		var out = "";
		while(pos < s.length) {
			var rest = s.slice(pos), c = s.charAt(pos), m, e, i;
			if(term && rest.slice(0,term.length) === term) { return {out: out, closed: true}; }
			if(mode.cell && !term && /^ *\|/.test(rest)) { return {out: out, closed: false, cellEnd: true}; }
			// --- constructs that are not converted ---
			if(c === "<") {
				if(rest.slice(0,4) === "<!--") { ctx.review("HTML comment (the markdown plugin cannot render comments reliably)"); pos = s.length; return {out: out, closed: false}; }
				if(/^<[A-Za-z$\/!?<]/.test(rest)) { ctx.review("macro, widget or HTML tag"); pos = s.length; return {out: out, closed: false}; }
			}
			if(c === "{" && rest.slice(0,2) === "{{") { ctx.review("transclusion {{...}}"); pos = s.length; return {out: out, closed: false}; }
			if(c === "@" && rest.slice(0,2) === "@@") { ctx.review("styled text @@...@@"); pos = s.length; return {out: out, closed: false}; }
			if(c === "&" && RE_ENTITY.test(rest)) { ctx.review("HTML entity"); pos = s.length; return {out: out, closed: false}; }
			if(c === "$" && rest.slice(0,3) === "$:/") { ctx.review("system tiddler link in text"); pos = s.length; return {out: out, closed: false}; }
			if(c === "~") {
				if(RE_EXTLINK.test(rest) && rest.charAt(0) === "~" || rest.slice(0,3) === "~$:") { ctx.review("escaped link (~http, ~$:/)"); pos = s.length; return {out: out, closed: false}; }
			}
			// --- external URL (TiddlyWiki extlink) ---
			if((m = RE_EXTLINK.exec(rest)) && m[1] === "") {
				var url = m[0];
				if(!/^(?:https?|ftp):\/\//.test(url)) { ctx.review("link scheme other than http, https, ftp"); pos = s.length; return {out: out, closed: false}; }
				if(pos > 0 && isAlnum(s.charAt(pos - 1))) { ctx.review("URL glued to a word"); pos = s.length; return {out: out, closed: false}; }
				pos += url.length;
				out += urlSafeBare(url,s.slice(pos,pos + 1)) ? urlText(url) : "<" + url + ">";
				continue;
			}
			// --- inline code ---
			if(c === "`") {
				var open = rest.slice(0,2) === "``" ? "``" : "`";
				if(rest.slice(0,3) === "```") { ctx.review("triple backtick inside a line"); pos = s.length; return {out: out, closed: false}; }
				e = s.indexOf(open,pos + open.length);
				if(e === -1) { ctx.review("unterminated inline code"); pos = s.length; return {out: out, closed: false}; }
				var code = s.slice(pos + open.length,e);
				if(code === "" || /^\s|\s$/.test(code) || code.indexOf("`") !== -1 || (mode.cell && code.indexOf("|") !== -1)) {
					ctx.review("inline code with empty, padded or backtick/pipe content"); pos = s.length; return {out: out, closed: false};
				}
				out += "`" + code + "`"; pos = e + open.length;
				continue;
			}
			// --- [[links]], [img[...]], [ext[...]] ---
			if(c === "[") {
				if(rest.slice(0,2) === "[[") {
					m = RE_PRETTYLINK.exec(rest);
					if(!m) { ctx.review("unmatched [["); pos = s.length; return {out: out, closed: false}; }
					var res = link(m);
					if(res === null) { pos = s.length; return {out: out, closed: false}; }
					pos += m[0].length; out += res;
					var nx = s.charAt(pos);
					if(nx === "(" || nx === "[") { ctx.review("link directly followed by ( or ["); pos = s.length; return {out: out, closed: false}; }
					continue;
				}
				if(rest.slice(0,4) === "[ext") { ctx.review("[ext[...]] link"); pos = s.length; return {out: out, closed: false}; }
				if(rest.slice(0,4) === "[img") {
					m = /^\[img\[([^\[\]]*)\]\]/.exec(rest);
					if(!m) { ctx.review("unsupported [img ...] syntax"); pos = s.length; return {out: out, closed: false}; }
					var im = image(m[1]);
					if(im === null) { pos = s.length; return {out: out, closed: false}; }
					pos += m[0].length; out += im;
					continue;
				}
			}
			// --- emphasis family ---
			var emph = null;
			for(i = 0; i < EMPH.length; i++) { if(rest.slice(0,2) === EMPH[i].tok) { emph = EMPH[i]; break; } }
			if(emph) {
				if(runLength(s,pos,c) >= 3) { ctx.review("run of three or more " + c + " characters"); pos = s.length; return {out: out, closed: false}; }
				var before = lastChar(out), startPos = pos;
				pos += 2;
				var r = parseRun(emph.tok);
				if(!r.closed) { ctx.review("unterminated " + emph.name + " (" + emph.tok + ")"); pos = s.length; return {out: out, closed: false}; }
				pos += 2;
				var inner = r.out, lead = /^\s*/.exec(inner)[0], trail = /\s*$/.exec(inner)[0];
				var core = inner.slice(lead.length,inner.length - trail.length);
				if(core === "") { ctx.review("empty " + emph.name); pos = s.length; return {out: out, closed: false}; }
				if(emph.star) {
					var after = trail ? " " : s.charAt(pos), prevCh = lead ? " " : (before || (startPos === 0 ? "" : s.charAt(startPos - 1)));
					if(!leftFlanking(prevCh,core.charAt(0)) || !rightFlanking(core.charAt(core.length - 1),after)) {
						ctx.review("emphasis next to punctuation that Markdown would not recognise"); pos = s.length; return {out: out, closed: false};
					}
				}
				out += lead + emph.open + core + emph.close + trail;
				continue;
			}
			// --- dashes: runs of four or more are ambiguous between TiddlyWiki and the typographer ---
			if(c === "-" && runLength(s,pos,"-") >= 4) { ctx.review("run of four or more hyphens inside text"); pos = s.length; return {out: out, closed: false}; }
			// --- plain character ---
			ctx.plain.push(c);
			if(c === "\\") { out += "\\\\"; }
			else if(c === "*" || c === "[" || c === "]") { out += "\\" + c; }
			else if(c === "_") { out += (isAlnum(s.charAt(pos - 1)) && isAlnum(s.charAt(pos + 1))) ? "_" : "\\_"; }
			else if(c === "|" && mode.cell) { out += "\\|"; }
			else { out += c; }
			pos++;
		}
		return {out: out, closed: false};
	}
	function link(m) {
		var text = m[1], target = m[2] || text;
		if(m[2] !== undefined && m[2].indexOf("|") !== -1) { ctx.review("link with more than one |"); return null; }
		if(text === "" || /\n/.test(text)) { ctx.review("empty or multi-line link"); return null; }
		if(RE_EXTERNAL.test(target)) {
			var asMd = (ctx.opts.externalLinks || "md") === "md";
			if(asMd && isHttpUrl(target) && !/\)/.test(target)) {
				var bare = m[2] === undefined || text === target;
				if(bare) { return urlSafeBare(target,s.slice(pos + m[0].length,pos + m[0].length + 1)) ? target : "<" + target + ">"; }
				if(/[\[\]<>&]|\{\{|<<|\$:\//.test(text) || /^\s|\s$/.test(text)) { ctx.review("external link text with markup characters"); return null; }
				ctx.plain.push(text);
				return "[" + escapeText(text,ctx,mode.cell) + "](" + target + ")";
			}
			// kept as TiddlyWiki syntax
			var rp = rawProblem(text) || rawProblem(target);
			if(rp) { ctx.review("link " + rp); return null; }
			return "[[" + text + (m[2] !== undefined ? (mode.cell ? "\\|" : "|") + m[2] : "") + "]]";
		}
		var p = rawProblem(text) || rawProblem(target);
		if(p) { ctx.review("link text or target " + p); return null; }
		return "[[" + text + (m[2] !== undefined ? (mode.cell ? "\\|" : "|") + m[2] : "") + "]]";
	}
	function image(body) {
		var bar = body.indexOf("|"), tip = bar === -1 ? "" : body.slice(0,bar), src = bar === -1 ? body : body.slice(bar + 1);
		if(src === "") { ctx.review("image without source"); return null; }
		if(isHttpUrl(src) && !/\)/.test(src)) {
			if(/["\\\n]/.test(tip)) { ctx.review("image tooltip with quotes"); return null; }
			return "![](" + src + (tip ? " \"" + tip + "\"" : "") + ")";
		}
		var p = rawProblem(body);
		if(p) { ctx.review("image " + p); return null; }
		return "[img[" + (mode.cell ? body.replace(/\|/g,"\\|") : body) + "]]";
	}
	var top = parseRun(null);
	if(ctx.reasons.length) { return ""; }
	return top.out;
}

/* ---- block level ---- */
function leadWs(line) { return /^\s*/.exec(line)[0].length; }

function mdLines(ctx,str) {
	/* paragraph text: one Markdown line per source line, no blank lines (they would split the paragraph) */
	var lines = str.split("\n"), out = [], i, l;
	for(i = 0; i < lines.length; i++) {
		l = lines[i].replace(/^\s+|\s+$/g,"");
		if(l === "") { continue; }
		if(/^[\s|:\-]+$/.test(l) && l.indexOf("|") !== -1 && l.indexOf("-") !== -1) { ctx.review("line that looks like a table delimiter row"); }
		out.push(escapeLineStart(l));
	}
	return out;
}

function convertTable(ctx,rows) {
	var parsed = [], r, i, ncols = -1;
	for(r = 0; r < rows.length; r++) {
		var line = rows[r], mm = /^\|(.*)\|([fhck]?)$/.exec(line);
		if(!mm) { ctx.review("malformed table row"); return null; }
		if(mm[2]) { ctx.review("table row with f/h/c/k suffix (footer, header, caption, class)"); return null; }
		var body = line;      // "|a|b|" : a cell starts at each pipe that is not the last character
		var cells = [], p = 0;
		while(p < body.length - 1) {
			// body[p] is the opening "|"
			var seg = body.slice(p + 1), raw = /^[^|]*/.exec(seg)[0];
			if(raw === "~" || raw === ">" || raw === "<") { ctx.review("table with colspan/rowspan cells"); return null; }
			if(/^\^([^\^]|\^\^)/.test(seg) || /^,([^,]|,,)/.test(seg)) { ctx.review("table cell with vertical alignment"); return null; }
			var q = 0, spaceLeft = false;
			while(seg.charAt(q) === " ") { spaceLeft = true; q++; }
			var header = false;
			if(seg.charAt(q) === "!") { header = true; q++; }
			// the cell runs to the next top-level pipe: find it with the inline tokenizer's rules by scanning for code/link spans
			var end = cellEnd(seg,q);
			if(end < 0) { ctx.review("table cell with unbalanced markup"); return null; }
			var content = seg.slice(q,end), spaceRight = seg.charAt(end - 1) === " " && end - 1 >= q;
			var trimmed = content.replace(/ +$/,"");
			var md = inline(ctx,trimmed,{cell: true});
			if(ctx.reasons.length) { return null; }
			var align = spaceRight ? (spaceLeft ? "center" : "left") : (spaceLeft ? "right" : "");
			if(md.trim() === "") { align = ""; }
			cells.push({md: md.trim(), header: header, align: align});
			p = p + 1 + end;       // position of the closing pipe = start of the next cell
		}
		if(ncols === -1) { ncols = cells.length; }
		if(cells.length === 0 || cells.length !== ncols) { ctx.review("table rows with different cell counts"); return null; }
		parsed.push(cells);
	}
	// header row: all cells of the first row are "!" cells and no other row has any
	var firstAll = parsed[0].every(function(c) { return c.header; }), anyLater = false, anyFirst = parsed[0].some(function(c) { return c.header; });
	for(r = 1; r < parsed.length; r++) { if(parsed[r].some(function(c) { return c.header; })) { anyLater = true; } }
	if(anyLater || (anyFirst && !firstAll)) { ctx.review("table with header cells outside a header row"); return null; }
	var out = [], aligns = [];
	for(i = 0; i < ncols; i++) {
		var set = {}, n = 0;
		parsed.forEach(function(row) { var a = row[i].align; if(a && !set[a]) { set[a] = 1; n++; } });
		if(n > 1) { ctx.review("table column with mixed cell alignment"); return null; }
		aligns.push(n ? Object.keys(set)[0] : "");
	}
	var header = firstAll ? parsed[0] : null, body2 = firstAll ? parsed.slice(1) : parsed;
	function rowMd(cells) { return "| " + cells.map(function(c) { return c.md; }).join(" | ").replace(/ {2,}\|/g," |") + " |"; }
	out.push(header ? rowMd(header) : "| " + parsed[0].map(function() { return " "; }).join(" | ") + " |");
	if(!header) { ctx.hints.headerRows++; ctx.hints.headerCells += ncols; }
	out.push("| " + aligns.map(function(a) { return a === "center" ? ":---:" : a === "right" ? "---:" : a === "left" ? ":---" : "---"; }).join(" | ") + " |");
	body2.forEach(function(row) { out.push(rowMd(row)); });
	return out.join("\n");
}
/* Index (in seg) of the pipe that ends the cell starting at q: skips [[...]], [img[...]], and `code` spans like the wikitext parser. */
function cellEnd(seg,q) {
	var p = q, m, e;
	while(p < seg.length) {
		var rest = seg.slice(p), c = seg.charAt(p);
		if(c === "|") {
			// trailing spaces before the pipe belong to the alignment, not to the content
			var k = p; while(k > q && seg.charAt(k - 1) === " ") { k--; }
			return p;
		}
		if(c === "`") { var open = rest.slice(0,2) === "``" ? "``" : "`"; e = seg.indexOf(open,p + open.length); if(e === -1) { return -1; } p = e + open.length; continue; }
		if(rest.slice(0,2) === "[[" && (m = RE_PRETTYLINK.exec(rest))) { p += m[0].length; continue; }
		if(rest.slice(0,4) === "[img" && (m = /^\[img\[[^\[\]]*\]\]/.exec(rest))) { p += m[0].length; continue; }
		if((m = RE_EXTLINK.exec(rest))) { p += m[0].length; continue; }
		p++;
	}
	return -1;
}

function convertList(ctx,items,kind) {
	// items: [{markers, text}]; TiddlyWiki list rule: the parent chain of an item must be the previous item's chain
	var lines = [], prev = null, k, i;
	for(i = 0; i < items.length; i++) {
		var it = items[i], markers = it.markers, level = markers.length;
		if(kind === "quote") { continue; }
		if(!prev) { if(level !== 1) { ctx.review("list starting below the first level"); return null; } }
		else if(level > 1 && (prev.length < level - 1 || markers.slice(0,level - 1) !== prev.slice(0,level - 1))) { ctx.review("list nesting that jumps a level or changes the parent list type"); return null; }
		prev = markers;
		var text = inline(ctx,it.text,{});
		if(ctx.reasons.length) { return null; }
		var l = mdLines(ctx,text);
		if(l.length !== 1) { ctx.review("empty list item"); return null; }
		var indent = ""; for(k = 1; k < level; k++) { indent += "    "; }
		lines.push(indent + (markers.charAt(level - 1) === "#" ? "1. " : "- ") + l[0]);
	}
	return lines.join("\n");
}
function convertQuoteLines(ctx,items) {
	var out = [], prev = 0, i, k;
	function pre(n) { var s = ""; for(k = 0; k < n; k++) { s += "> "; } return s; }
	for(i = 0; i < items.length; i++) {
		var n = items[i].markers.length;
		if(n > prev + 1 && prev !== 0) { ctx.review("blockquote nesting that jumps a level"); return null; }
		var text = inline(ctx,items[i].text,{});
		if(ctx.reasons.length) { return null; }
		var l = mdLines(ctx,text);
		if(l.length !== 1) { ctx.review("empty blockquote line"); return null; }
		if(i > 0) { out.push(pre(Math.min(prev,n)).replace(/\s+$/,"")); }
		out.push(pre(n) + l[0]);
		prev = n;
	}
	return out.join("\n");
}

function blocks(ctx,lines,depth) {
	var out = [], i = 0, n = lines.length;
	if(depth > 8) { ctx.review("quote blocks nested too deeply"); return ""; }
	while(i < n) {
		var line = lines[i];
		if(/^\s*$/.test(line)) { i++; continue; }
		var L = line.replace(/^\s+/,""), indented = L.length !== line.length, m;
		// pragmas
		if(/^\\[a-zA-Z]/.test(L)) { ctx.review("pragma (\\define, \\rules, \\import, ...)"); return ""; }
		if(/^(?:@@|\$\$\$|""")/.test(L)) { ctx.review("styled block, typed block or poetry block"); return ""; }
		// fenced code block
		if(L.slice(0,3) === "```") {
			m = /^```([\w-]*)$/.exec(L);
			if(!m || indented) { ctx.review("unsupported code fence"); return ""; }
			var j = i + 1;
			while(j < n && lines[j] !== "```") { j++; }
			if(j >= n) { ctx.review("unterminated code block"); return ""; }
			var body = lines.slice(i + 1,j), bad = body.some(function(x) { return /^ {0,3}`{3,}\s*$/.test(x) || /^ {0,3}~{3,}/.test(x) && false; });
			if(bad) { ctx.review("code block containing a fence-like line"); return ""; }
			if(!body.length) { ctx.review("empty code block"); return ""; }
			out.push("```" + m[1] + "\n" + (body.length ? body.join("\n") + "\n" : "") + "```");
			i = j + 1;
			continue;
		}
		// <<< quote block
		if(L.slice(0,3) === "<<<") {
			if(L !== "<<<" || indented) { ctx.review("quote block with class, citation or deeper nesting"); return ""; }
			var c = i + 1;
			while(c < n && lines[c].replace(/^\s+/,"").slice(0,3) !== "<<<") { c++; }
			if(c >= n) { ctx.review("unterminated quote block"); return ""; }
			if(lines[c] !== "<<<") { ctx.review("quote block with citation"); return ""; }
			var inner = blocks(ctx,lines.slice(i + 1,c),depth + 1);
			if(ctx.reasons.length) { return ""; }
			if(inner === "") { ctx.review("empty quote block"); return ""; }
			out.push(inner.split("\n").map(function(x) { return x === "" ? ">" : "> " + x; }).join("\n"));
			i = c + 1;
			continue;
		}
		// horizontal rule
		if(/^-{3,}$/.test(L)) {
			if(indented) { ctx.review("indented horizontal rule"); return ""; }
			out.push("---"); i++; continue;
		}
		// heading
		if(L.charAt(0) === "!") {
			if(indented) { ctx.review("indented heading"); return ""; }
			var level = runLength(L,0,"!");
			if(level > 6) { ctx.review("heading deeper than level 6"); return ""; }
			var htext = L.slice(level);
			if(htext.charAt(0) === ".") { ctx.review("heading with CSS class"); return ""; }
			htext = htext.replace(/^\s+|\s+$/g,"");
			if(htext === "") { ctx.review("empty heading"); return ""; }
			var hm = inline(ctx,htext,{});
			if(ctx.reasons.length) { return ""; }
			hm = hm.replace(/(\s)(#+)$/,"$1\\$2");
			var hs = ""; for(var h = 0; h < level; h++) { hs += "#"; }
			out.push(hs + " " + hm); i++; continue;
		}
		// lists, definition lists, blockquote lines
		if((m = /^[*#;:>]+/.exec(L))) {
			if(indented) { ctx.review("indented list marker"); return ""; }
			var first = m[0].charAt(0), items = [], j2 = i, okGroup = true;
			while(j2 < n) {
				var ln = lines[j2];
				if(/^\s*$/.test(ln)) { j2++; continue; }
				var lt = ln.replace(/^\s+/,""), mk = /^[*#;:>]+/.exec(lt);
				if(!mk || mk[0].charAt(0) !== first) { break; }
				if(/[;:]/.test(mk[0])) { ctx.review("definition list (; and :)"); return ""; }
				if(first === ">" ? /[*#]/.test(mk[0]) : /[>]/.test(mk[0])) { ctx.review("mixed list and quote markers"); return ""; }
				var after = lt.slice(mk[0].length);
				if(after.charAt(0) === ".") { ctx.review("list item or quote line with CSS class"); return ""; }
				var itext = after.replace(/^\s+|\s+$/g,"");
				if(itext === "") { ctx.review("empty list item"); return ""; }
				items.push({markers: mk[0], text: itext});
				j2++;
			}
			var lm = first === ">" ? convertQuoteLines(ctx,items) : convertList(ctx,items,"list");
			if(ctx.reasons.length || lm === null) { return ""; }
			out.push(lm);
			i = j2; continue;
		}
		// table
		if(L.charAt(0) === "|" && /^\|.*\|[fhck]?$/.test(line)) {
			var rows = [], t = i;
			while(t < n && /^\|.*\|[fhck]?$/.test(lines[t])) { rows.push(lines[t]); t++; }
			var tm = convertTable(ctx,rows);
			if(ctx.reasons.length || tm === null) { return ""; }
			out.push(tm); i = t; continue;
		}
		if(L.charAt(0) === "|" && indented && /\|[fhck]?$/.test(L)) { ctx.review("indented table"); return ""; }
		// paragraph: runs to the first truly empty line (TiddlyWiki's terminator is exactly two newlines)
		var p2 = i, plines = [];
		while(p2 < n && lines[p2] !== "") { plines.push(lines[p2]); p2++; }
		var ptext = plines.join("\n");
		if(plines.some(function(x) { return /^\s*$/.test(x); })) { ctx.warn("whitespace-only line inside a paragraph (joined in WikiText)"); }
		var pm = inline(ctx,ptext,{});
		if(ctx.reasons.length) { return ""; }
		var pl = mdLines(ctx,pm);
		if(pl.length === 0) { i = p2; continue; }
		out.push(pl.join("\n"));
		i = p2;
	}
	return out.join("\n\n");
}

/* ---- public API ---- */
var RE_FUZZY = /(?:^|[^\w@.\/-])(?:www\.[\w-]+\.\w|[\w-]+(?:\.[\w-]+)*\.(?:com|net|org|edu|gov|io|me|dev|app|info|biz|co|ru|de|uk|fr|it|es|nl|ch|se|no|jp|cn)\b|[\w.+-]+@[\w-]+\.\w)/gi;

function analyze(text,opts) {
	var ctx = new Ctx(opts);
	if(typeof text !== "string") { ctx.review("tiddler text is not loaded"); return {md: null, reasons: ctx.reasons, warnings: ctx.warnings, hints: ctx.hints}; }
	var src = text.replace(/\r\n?/g,"\n"), lines = src.split("\n"), md = blocks(ctx,lines,0);
	if(!ctx.reasons.length) {
		if(src.charAt(src.length - 1) === "\n" && md !== "") { md += "\n"; }
		var plain = ctx.plain.join(""), fz = plain.match(RE_FUZZY);
		if(fz) { ctx.hints.fuzzy = fz.length; ctx.warn("text that looks like a domain or e-mail address becomes a link in Markdown (linkify)"); }
		if(/['"]|--|\.\.\.|\((?:c|r|tm)\)/i.test(plain)) { ctx.warn("typographer: quotes, dashes and ellipses are shown as curly/long characters"); }
	}
	return {md: ctx.reasons.length ? null : md, reasons: ctx.reasons, warnings: ctx.warnings, hints: ctx.hints};
}

/* Does the text look like Markdown? Only signals that WikiText does not use (line based, linear time). */
function looksLikeMarkdown(text) {
	var lines = String(text).split("\n"), md = false, wiki = false, i, l, prev, next;
	var mdWhole = /\]\([^)\n]+\)/.test(text) || /(?:^|\s)\*\*[^*\n]+\*\*/.test(text) || /(?:^|[\s(])\*[^\s*][^*\n]*\*(?=[\s.,;:!?)]|$)/.test(text) ||
		/<(?:u|sup|sub)>/.test(text) || /\\[*_\[\]`#>+.|\\-]/.test(text);
	var wikiWhole = /''/.test(text) || /\[\[.+?\]\]/.test(text) || /<<|<\$|\{\{/.test(text) || /\/\/\S[^\n]*\S\/\//.test(text.replace(/\w+:\/\/\S+/g,""));
	for(i = 0; i < lines.length; i++) {
		l = lines[i];
		if(/^[ \t]*[-+] \S/.test(l) || /^\d+\. \S/.test(l) || /^\|\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|\s*$/.test(l)) { md = true; }
		if(/^#{1,6} \S/.test(l)) {
			prev = i > 0 ? lines[i - 1] : ""; next = i + 1 < lines.length ? lines[i + 1] : "";
			if(prev.charAt(0) !== "#" && next.charAt(0) !== "#") { md = true; } else { wiki = true; }
		} else if(/^#+[ \t]?\S/.test(l)) { wiki = true; }
		if(/^!{1,6}(?!\[)[ \t]?\S/.test(l) || /^<<<$/.test(l)) { wiki = true; }
		if(/^\*+[ \t]?\S/.test(l) && !/^\*{1,2}[^\s*][^*]*\*{1,2}(?=\s|$|[.,;:!?)])/.test(l)) { wiki = true; }
	}
	return (md || mdWhole) && !(wiki || wikiWhole);
}

function typeOf(fields) { return fields && fields.type !== undefined ? String(fields.type).trim().toLowerCase() : ""; }

/* classify(text, fields) -> {status, reasons, warnings}. fields is optional; with it system tiddlers, plugins, binary types etc. are skipped. */
function classify(text,fields,opts) {
	var f = fields || null, ty;
	if(f) {
		ty = typeOf(f);
		var title = String(f.title === undefined ? "" : f.title), tags = f.tags;
		if(title.indexOf("$:/") === 0) { return {status: "skip", reasons: ["system tiddler"], warnings: []}; }
		if(f["plugin-type"] || f["module-type"]) { return {status: "skip", reasons: ["plugin, theme or module"], warnings: []}; }
		if(f["draft.of"]) { return {status: "skip", reasons: ["draft"], warnings: []}; }
		if(f._canonical_uri) { return {status: "skip", reasons: ["external (_canonical_uri) content"], warnings: []}; }
		if(typeof tags === "string" && /(?:^|\s|\[\[)\$:\//.test(tags)) { return {status: "skip", reasons: ["tagged with a system tag"], warnings: []}; }
		if(MD_TYPES[ty]) { return {status: "already-markdown", reasons: [], warnings: []}; }
		if(!WIKI_TYPES[ty]) { return {status: "skip", reasons: ["type " + ty + " is not WikiText"], warnings: []}; }
		if(f._is_skinny !== undefined && f._is_skinny !== null) { return {status: "skip", reasons: ["not loaded yet"], warnings: []}; }
	}
	if(typeof text !== "string") { return {status: "skip", reasons: ["not loaded yet"], warnings: []}; }
	if(/^\s*$/.test(text)) { return {status: "skip", reasons: ["empty"], warnings: []}; }
	if(looksLikeMarkdown(text)) {
		if(!f) { return {status: "already-markdown", reasons: [], warnings: []}; }
		return {status: "review", reasons: ["looks like Markdown but is typed as WikiText"], warnings: []};
	}
	var a = analyze(text,opts);
	return {status: a.reasons.length ? "review" : "convertible", reasons: a.reasons, warnings: a.warnings, hints: a.hints};
}

/* convert(text) -> Markdown, or the text unchanged when any construct is not understood (never guesses). */
function convert(text,opts) {
	if(typeof text === "string" && looksLikeMarkdown(text)) { return text; }   // already Markdown (or ambiguous): never touch
	var a = analyze(text,opts);
	return a.reasons.length || a.md === null ? text : a.md;
}

/* ---- rendering signature, shared by the tests and by the in-wiki verification (works on any DOM-like node) ---- */
var BLOCK = {p:1,div:1,li:1,ul:1,ol:1,dl:1,dt:1,dd:1,td:1,th:1,tr:1,table:1,thead:1,tbody:1,tfoot:1,caption:1,h1:1,h2:1,h3:1,h4:1,h5:1,h6:1,blockquote:1,pre:1,hr:1,br:1,cite:1};
var COUNTED = {h1:"h1",h2:"h2",h3:"h3",h4:"h4",h5:"h5",h6:"h6",li:"li",ul:"ul",ol:"ol",a:"a",pre:"pre",code:"code",table:"table",tr:"tr",td:"cell",th:"cell",img:"img",
	blockquote:"blockquote",hr:"hr",strong:"strong",b:"strong",em:"em",i:"em",u:"u",s:"s",del:"s",strike:"s",sup:"sup",sub:"sub"};
function normalizeText(t) {
	return String(t).replace(/[\u2018\u2019\u201a\u201b]/g,"'").replace(/[\u201c\u201d\u201e\u201f]/g,"\"").replace(/[\u2013\u2014]/g,"-").replace(/\u2026/g,"...")
		.replace(/\u00a9/g,"(c)").replace(/\u00ae/g,"(r)").replace(/\u2122/g,"(tm)").replace(/\u00b1/g,"+-").replace(/\u00a0/g," ");
}
function signature(root) {
	var text = "", counts = {};
	(function walk(n) {
		var i, tag;
		if(!n) { return; }
		if(n.nodeType === 3) { text += n.nodeValue; return; }
		if(n.nodeType !== 1 && n.nodeType !== 11 && n.nodeType !== 9) { return; }
		tag = n.nodeType === 1 ? String(n.tagName).toLowerCase() : "";
		if(tag === "script" || tag === "style") { return; }
		if(COUNTED[tag]) { counts[COUNTED[tag]] = (counts[COUNTED[tag]] || 0) + 1; }
		if(BLOCK[tag]) { text += " "; }
		for(i = 0; i < n.childNodes.length; i++) { walk(n.childNodes[i]); }
		if(BLOCK[tag]) { text += " "; }
	})(root);
	return {words: normalizeText(text).split(/\s+/).filter(Boolean), counts: counts};
}
/* compare(a, b, hints) where a = rendering of the WikiText, b = rendering of the Markdown. Returns {ok, diffs}. */
function compareSignatures(a,b,hints) {
	var diffs = [], k, keys = {}, h = hints || {}, i;
	for(k in a.counts) { keys[k] = 1; }
	for(k in b.counts) { keys[k] = 1; }
	for(k in keys) {
		var x = a.counts[k] || 0, y = b.counts[k] || 0, want = x;
		if(k === "cell") { want += h.headerCells || 0; }
		if(k === "tr") { want += h.headerRows || 0; }
		if(k === "a") { if(y >= x && y <= x + (h.fuzzy || 0)) { continue; } }
		if(y !== want) { diffs.push(k + ": WikiText renders " + x + ", Markdown renders " + y); }
	}
	if(a.words.length !== b.words.length || a.words.some(function(w,j) { return w !== b.words[j]; })) {
		for(i = 0; i < Math.max(a.words.length,b.words.length); i++) { if(a.words[i] !== b.words[i]) { break; } }
		diffs.push("text differs near word " + (i + 1) + " (\"" + String(a.words[i]).slice(0,30) + "\" vs \"" + String(b.words[i]).slice(0,30) + "\")");
	}
	return {ok: diffs.length === 0, diffs: diffs};
}

/* small stable hash (FNV-1a, 32 bit) used to notice edits made after a conversion */
function hash(str) {
	var h = 0x811c9dc5, i;
	for(i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0; }
	return ("00000000" + h.toString(16)).slice(-8);
}

exports.classify = classify;
exports.convert = convert;
exports.analyze = analyze;
exports.looksLikeMarkdown = looksLikeMarkdown;
exports.signature = signature;
exports.compareSignatures = compareSignatures;
exports.normalizeText = normalizeText;
exports.hash = hash;
exports.MD_TYPE = "text/x-markdown";
})();
