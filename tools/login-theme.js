(function(){
"use strict";
var root = document.documentElement, body = document.body;
if(!body || document.getElementById("tw-rain")) { return; }
root.classList.add("tw-login");
var cv = document.createElement("canvas"); cv.id = "tw-rain"; cv.setAttribute("aria-hidden","true");
body.insertBefore(cv,body.firstChild);
var ctx = cv.getContext && cv.getContext("2d");
var reduce = false; try { reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch(e) {}
var GLYPHS = "ｦｧｨｩｪｫｬｭｮｯｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEF<>/{}=+*".split("");
var FS = 16, cols = 0, drops = [], last = [], w = 0, h = 0, raf = 0, stopped = false, lastT = 0;
function rnd(a) { return a[Math.floor(Math.random() * a.length)]; }
function size() {
	w = cv.width = Math.max(1,window.innerWidth); h = cv.height = Math.max(1,window.innerHeight);
	cols = Math.ceil(w / FS); drops = []; last = [];
	for(var i=0; i<cols; i++) { drops[i] = -Math.floor(Math.random() * (h / FS)); last[i] = rnd(GLYPHS); }
	if(ctx) { ctx.fillStyle = "#06101a"; ctx.fillRect(0,0,w,h); }
}
function step() {
	ctx.fillStyle = "rgba(6,16,26,0.09)"; ctx.fillRect(0,0,w,h);
	ctx.font = FS + "px 'MS Gothic','Yu Gothic','Hiragino Kaku Gothic ProN',ui-monospace,Consolas,monospace";
	for(var i=0; i<cols; i++) {
		var y = drops[i];
		if(y > 0) { ctx.fillStyle = "#63A4B5"; ctx.fillText(last[i],i * FS,y * FS); }   // previous head becomes teal trail
		var c = rnd(GLYPHS); last[i] = c; y++; drops[i] = y;
		if(y > 0) { ctx.fillStyle = "#B4FF00"; ctx.fillText(c,i * FS,y * FS); }          // new head: lime from the site palette
		if(y * FS > h && Math.random() > 0.975) { drops[i] = -Math.floor(Math.random() * 20); }
	}
}
function loop(t) {
	if(stopped) { return; }
	raf = window.requestAnimationFrame(loop);
	if(t - lastT < 48) { return; }
	lastT = t; step();
}
if(ctx) {
	size();
	if(reduce) { for(var k=0; k<140; k++) { step(); } } else { raf = window.requestAnimationFrame(loop); }
	window.addEventListener("resize",size);
}
/* "DECRYPTING" feedback: key stretching blocks the main thread, so let the browser paint first, then run the real submit. */
function onSubmit(ev) {
	var f = ev.target;
	if(!f || !f.closest || !f.closest(".tc-password-wrapper")) { return; }
	if(f.__twGo) { return; }
	ev.stopImmediatePropagation(); ev.preventDefault();
	root.classList.remove("tw-deny"); root.classList.add("tw-working");
	setTimeout(function() {
		f.__twGo = true;
		try { f.dispatchEvent(new Event("submit",{bubbles: true, cancelable: true})); } finally { f.__twGo = false; root.classList.remove("tw-working"); }
		var wrap = document.querySelector(".tc-password-wrapper");
		if(wrap && wrap.style.display !== "none" && body.contains(f)) {
			void root.offsetWidth; root.classList.add("tw-deny");
			var pw = f.querySelector("input[type=password]"); if(pw) { pw.focus(); }
		}
	},90);
}
document.addEventListener("submit",onSubmit,true);
/* decoration + clean-up once the wiki itself has rendered */
function tick() {
	var h1 = document.querySelector(".tc-password-wrapper h1");
	if(h1 && !h1.hasAttribute("data-text")) { h1.setAttribute("data-text",h1.textContent); }
	if(document.querySelector(".tc-page-container, .tc-sidebar-scrollable, .tc-story-river")) { done(); }
}
var mo = window.MutationObserver ? new MutationObserver(tick) : null;
if(mo) { mo.observe(body,{childList: true, subtree: true}); }
function done() {
	if(stopped) { return; }
	stopped = true; if(mo) { mo.disconnect(); }
	document.removeEventListener("submit",onSubmit,true); window.removeEventListener("resize",size);
	if(raf) { window.cancelAnimationFrame(raf); }
	root.classList.remove("tw-working","tw-deny");
	cv.classList.add("tw-out");
	setTimeout(function() { root.classList.remove("tw-login"); if(cv.parentNode) { cv.parentNode.removeChild(cv); } },750);
}
tick();
})();
