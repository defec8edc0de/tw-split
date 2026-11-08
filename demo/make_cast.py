"""Build a deterministic asciinema v2 cast of the tw-split demo by running the real commands on the SYNTHETIC demo wiki.
Usage: TW_PASSWORD=demo-password-not-a-secret python demo/make_cast.py demo/work tools/twmigrate.py demo.cast demo-transcript.txt"""
import json, os, random, subprocess, sys

demo, tool, out_cast, out_txt = sys.argv[1:5]
py = sys.executable
random.seed(7)
events, t = [], 0.4
transcript = []
COLS, ROWS = 96, 26
PROMPT = "\x1b[33m~/notes\x1b[0m \x1b[36m$\x1b[0m "

def emit(s, dt=0.0):
    global t
    t += dt
    events.append([round(t, 3), "o", s])

def type_cmd(cmd, shown=None):
    emit(PROMPT, 0.5)
    for ch in (shown or cmd):
        emit(ch, random.uniform(0.025, 0.07))
    emit("\r\n", 0.35)
    transcript.append("$ " + (shown or cmd))

def run(cmd, shown=None, env=None, filt=None, pace=0.04):
    type_cmd(cmd, shown)
    r = subprocess.run(cmd, shell=True, cwd=demo, capture_output=True, text=True, env=env)
    text = (r.stdout + r.stderr).rstrip("\n")
    if filt:
        text = filt(text)
    first = True
    for line in text.split("\n"):
        emit(line + "\r\n", 0.25 if first else pace)
        first = False
        transcript.append(line)

env = dict(os.environ)
assert env.get("TW_PASSWORD"), "set TW_PASSWORD to the demo password"
subprocess.run(["rm", "-rf", os.path.join(demo, "out")], check=True)

emit("\x1b[90m# tw-split demo — a synthetic wiki, a throw-away password\x1b[0m\r\n", 0.2)
transcript.append("# tw-split demo — a synthetic wiki, a throw-away password")
run("ls -lh tw.html | awk '{print $5, $9}'", shown="ls -lh tw.html")
emit("\x1b[90m# one file, whole wiki encrypted: every open decrypts everything\x1b[0m\r\n", 0.6)
transcript.append("# one file, whole wiki encrypted: every open decrypts everything")
type_cmd("read -rs TW_PASSWORD && export TW_PASSWORD")
run(f"{py} -I {tool} migrate --src tw.html --out out --repo you/notes 2>&1 | grep -v '^NOTE'", shown="twmigrate migrate --src tw.html --out out --repo you/notes")
run(f"{py} -I {tool} verify --src tw.html --out out 2>&1 | grep -v WARNING", shown="twmigrate verify --src tw.html --out out")
run("cd out && find . -type f | sort | sed 's#^./##'", shown="find out -type f")
run("od -A x -t x1z -N 48 out/m/*.bin", shown="od -A x -t x1z -N 48 out/m/*.bin")
run("grep -rl 'Lorem ipsum' out/ --include='*.bin' || echo 'no plaintext in out/'", shown="grep -rl 'Lorem ipsum' out/ --include='*.bin'")
emit("\x1b[90m# push out/ to a GitHub Pages repo; the browser decrypts one note at a time\x1b[0m\r\n", 0.8)
transcript.append("# push out/ to a GitHub Pages repo; the browser decrypts one note at a time")
emit(PROMPT, 0.4)
emit("", 2.5)

header = {"version": 2, "width": COLS, "height": ROWS, "timestamp": 1762560000, "title": "tw-split demo (synthetic data)",
          "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
with open(out_cast, "w", encoding="utf-8") as f:
    f.write(json.dumps(header) + "\n")
    for e in events:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
with open(out_txt, "w", encoding="utf-8") as f:
    f.write("\n".join(transcript) + "\n")
print(f"{len(events)} events, {t:.1f}s")
