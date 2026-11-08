# Contributing / development notes

## Ground rules
* Never commit a real wiki, a real password, a token, or anything decrypted. Tests use synthetic data only.
* Public TiddlyWiki APIs only, with feature detection. Never patch `$:/core` or the boot kernel.
* Any change to the file format needs matching changes in `tools/encfmt.py` **and** `plugin/src/encfmt.js`, regenerated vectors (`tests/gen_vectors.py`), and an update to `docs/FORMAT.md`.
* Any change that affects security properties updates `docs/THREAT-MODEL.md`.

## Setup
```bash
python3 -m venv .venv
.venv/bin/pip install pycryptodome playwright nodejs-wheel-binaries   # node ends up in .venv/bin/node
(cd tests/node && ../../.venv/bin/npm ci)                              # jsdom for the browser-level tests
demo/build-demo.sh                                                     # synthetic encrypted wiki in demo/work/
TW_PASSWORD=demo-password-not-a-secret .venv/bin/python -I tools/twmigrate.py migrate --repo you/notes \
    --src demo/work/tw.html --out demo/work/out --kdf-iter 10000
```

## Tests
| suite | needs |
|---|---|
| `tests/test_parity.py` | Python + node (py ⇄ js format parity, shared vectors) |
| `tests/test_migrate.py` | Python. The real-wiki cases need `TW_SOURCE=demo/work/tw.html TW_PASSWORD=demo-password-not-a-secret` |
| `tests/engine_test.py` | node: engine, sinks, targets and adaptor against `tests/mock_github.py` |
| `tests/xss_test.py` | node + jsdom + a migrated skeleton: `TW_SKELETON=demo/work/out/tw.html` |
| `tests/mdconvert_test.py` | as above; the rendering cases also need the third-party *tw5-markdown* plugin in the skeleton |
| `tests/login_theme_test.py` | `TW_SOURCE` |
| `tests/race_test.py` | dev check with system Chromium against a migrated wiki folder |

Run each one with `.venv/bin/python -I tests/<suite>.py`.
