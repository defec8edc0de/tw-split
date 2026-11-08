"""Dev check (needs TW_PASSWORD + system Chromium): the startup palette switch must never be reverted by a late sync "load" task.
Opens the wiki folder N times; after every start $:/palette must still be the Cyber palette and the writing area dark.
Before the adaptor fix (loadTiddler skips tiddlers with unsaved local changes) about one start in three ended on the stored light palette.
Usage: race_test.py <wiki-folder> [runs]"""
import functools, http.server, os, sys, threading, time
from playwright.sync_api import sync_playwright
folder = os.path.abspath(sys.argv[1]); runs = int(sys.argv[2]) if len(sys.argv) > 2 else 8
class Q(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Q, directory=folder)); threading.Thread(target=srv.serve_forever, daemon=True).start()
bad = 0
with sync_playwright() as p:
    b = p.chromium.launch(executable_path='/usr/bin/chromium', args=['--no-sandbox'])
    for i in range(runs):
        pg = b.new_page(viewport={'width': 1366, 'height': 820})
        pg.goto('http://127.0.0.1:%d/tw.html' % srv.server_address[1]); pg.wait_for_selector('input[type=password]')
        pg.fill('input[type=password]', os.environ['TW_PASSWORD']); pg.keyboard.press('Enter')
        pg.wait_for_function('window.$tw && $tw.encSync && $tw.encSync.status.state === "ready" && document.querySelector(".tc-page-container")', timeout=60000); time.sleep(4)
        pal = pg.evaluate('$tw.wiki.getTiddlerText("$:/palette")'); bg = pg.evaluate('getComputedStyle(document.body).backgroundColor')
        ok = pal == '$:/palettes/tw-split/Cyber' and bg == 'rgb(10, 20, 30)'; bad += 0 if ok else 1
        print('run %d: %s %s %s' % (i + 1, 'ok ' if ok else 'BAD', pal, bg)); pg.close()
    b.close()
print('ALL RACE RUNS OK' if not bad else 'FAILED: %d of %d starts lost the palette' % (bad, runs)); sys.exit(1 if bad else 0)
