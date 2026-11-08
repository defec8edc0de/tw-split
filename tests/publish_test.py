"""Runs tests/node/publish.test.js (publish.js + plaintext methods of github.js). Needs node (.venv/bin/node or PATH)."""
import os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
node = os.path.join(HERE, '..', '.venv', 'bin', 'node')
node = node if os.path.exists(node) else shutil.which('node')
if not node: print('SKIP: node not found'); sys.exit(0)
sys.exit(subprocess.call([node, os.path.join(HERE, 'node', 'publish.test.js')]))
