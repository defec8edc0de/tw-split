# tw-split

**Encrypted per-note storage for a TiddlyWiki hosted on GitHub Pages.**

A password-protected TiddlyWiki is a great private notebook, until it grows. Its built-in encryption turns the *whole* wiki, including every image and plugin, into one ciphertext. Every visit downloads and decrypts all of it, and every save rewrites all of it.

tw-split turns that single file into:

* a small **stage-1 `tw.html`**: TiddlyWiki core, plugins, and a tiny bootstrap blob in TiddlyWiki's *stock* encrypted format, so the familiar password prompt keeps working; and
* **one AES-256-GCM encrypted file per tiddler** under opaque names (`<12 hex>/<32 hex>.bin`), plus one encrypted manifest (`m/<32 hex>.bin`).

In the browser, the bundled plugin **tw-enc-sync** (`$:/plugins/tw-enc-sync`, a standard TiddlyWiki *syncadaptor*, with no core patches) works like this:

* At startup it loads and decrypts the manifest.
* It decrypts a tiddler only when you open it; images are decrypted only when they are displayed.
* It writes your edits back to the configured save targets.

```
$ twmigrate migrate --src tw.html --out out --repo you/notes
external tiddlers: 7, plugins kept in stage-1: 3, dropped state/temp: 3
$ find out -type f
164707c1e3e9/5c35bcad6c6fa55f9e1ae14b4e8d81df.bin
6be8ad88bdd2/57514aa4c51d932910ad22ca738a780e.bin
…
m/16ecdb5654b3451b08417e0fa60c74b3.bin
tw.html
```

A recorded demo (synthetic data) is on the [project page](https://defec8edc0.de/projects/tw-split/).

> **Not a substitute for audited cryptography.** Read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) before trusting it with anything. Above all, the stage-1 file is public, so your password faces offline guessing. Use a long random passphrase.

## Features

* **One password, one data key.** The password unlocks a random 256-bit data key. HKDF derives domain-separated subkeys for file encryption, file names and the manifest. After unlock, the key tiddler is scrubbed from the store and from the boot kernel's preload array, and TiddlyWiki's in-memory password is dropped.
* **Opaque layout.** Folder and file names are keyed HMACs of category and title. Bodies are padded to size buckets, and titles, tags and categories never appear in the repository.
* **Authenticated and rollback-aware.** AES-GCM binds every file to its id and revision. The manifest lists each ciphertext hash and carries a monotonic counter, so a browser that has seen counter *n* refuses older states.
* **Save targets** (`$:/config/ext/enc/SaveTarget`):
  * `github`: one commit through the Git Data API, a few seconds after you stop editing or on *Save*. It builds on `base_tree` and writes only its own paths, so it can share a repository with a website.
  * `folder`: writes changed ciphertext straight into the wiki folder (File System Access API; the default for `file://`).
  * `zip`: downloads the changed files to unpack.
* **Publish to GitHub now** makes the repository match your local state, and seeds an empty repository.
* **Defensive UI.** The GitHub token stays in `sessionStorage` (configurable). Active HTML in notes is neutered. The whole-wiki plaintext "download" is refused. Error and status messages are rendered as plain text, never as wikitext.
* **Optional extras** that ship with the plugin: a dark *Cyber* palette and editor overlay, Markdown as the default type for new tiddlers, and a WikiText→Markdown converter (see below).

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install pycryptodome
read -rs TW_PASSWORD && export TW_PASSWORD             # the existing wiki's password; never stored by the tools
read -rs TW_NEW_PASSWORD && export TW_NEW_PASSWORD     # recommended: a fresh long passphrase for stage-1
.venv/bin/python tools/twmigrate.py migrate --src tw.html --out out --repo OWNER/REPO --branch main
.venv/bin/python tools/twmigrate.py verify  --src tw.html --out out
unset TW_PASSWORD TW_NEW_PASSWORD
```

Then follow [`docs/DEPLOY.md`](docs/DEPLOY.md): copy `out/tw.html` into your Pages repository yourself, open the wiki, and press *Publish to GitHub now* to upload the encrypted files. Use a **fine-grained token limited to that one repository** (Contents: read & write, Metadata: read).

Other commands:

* `inspect`: inventory of the encrypted wiki.
* `restage`: rebuild stage-1 after plugin updates.
* `rotate`: new key and new file names.
* `inline`: roll back to a classic single-file encrypted wiki.

`--kdf-iter` (default 300000) sets the PBKDF2 cost of the stage-1 blob.

### Try it on synthetic data

```bash
demo/build-demo.sh                 # stock TiddlyWiki 5.1.21 + lorem notes, encrypted with a throw-away password
TW_PASSWORD=demo-password-not-a-secret .venv/bin/python tools/twmigrate.py migrate --src demo/work/tw.html --out demo/work/out --repo you/notes
```

`demo/make_cast.py` regenerates the asciinema recording from that demo.

## Publishing notes to a Hugo blog (optional)

If the same repository also holds a [Hugo](https://gohugo.io) site, you can publish single notes as **public** Markdown posts. Everything else stays encrypted.

1. Open a note and press the **globe** button in its toolbar. On a note that isn't a blog post yet, you're asked once whether to add the tag `publish:blog`.
2. A preview shows the exact Markdown and the target path (`content/blog/<slug>/index.md`, or `index.de.md` for German). Press **Publish…** and confirm the browser dialog.
3. The post is committed (one commit, plaintext only, never mixed with ciphertext). Your site rebuilds as usual.
4. A status bar under the note shows the live link, **Update…** and **Unpublish…**.

These are filled in automatically:

| Field | From |
|---|---|
| title | the note's title |
| date | when the note was created |
| last update | when it was last modified |
| description | the first paragraph (or the *Summary* field) |
| URL | the title (frozen after the first publish) |

Optional settings live in the **Blog post** panel of the editor:

* *Summary*
* *Post tags*: vault tags are never copied
* *Language*: en/de
* *URL*
* *Images*: only needed for images that aren't referenced in the text

Images used in the text as `![alt](#Image title)` or `[img[Image title]]` are published next to the post. External image URLs are refused.

The publisher refuses anything that could pull in other notes or run code, outside of code blocks:

* transclusions
* macros
* widgets
* raw HTML
* invisible or bidi-control Unicode

Links to unpublished notes become plain text. Details and residual risks: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), section *Publishing*.

### Wiki in a sub-folder of the repository

If `tw.html` lives in a sub-folder of the Pages repository (for example `vault/` next to a website), set the folder once with `--repo-base vault/` (`migrate` or `restage`). Fetches stay relative to `tw.html`. Only the GitHub API paths get the prefix.

## Layout

| path | what |
|---|---|
| `tools/twmigrate.py` | CLI: `inspect`, `migrate`, `verify`, `restage`, `rotate`, `inline` |
| `tools/encfmt.py`, `tools/twlib.py` | Python reference implementation of the file format and of TiddlyWiki's SJCL store |
| `tools/login-theme.*` | optional styled password prompt for stage-1 (`--no-login-theme` to keep the stock one) |
| `plugin/src/` | the TiddlyWiki plugin, packed into stage-1 by `migrate`. Main modules: `engine.js` (manifest, queue, merge/retry commits), `github.js`, `localsink.js`, `targets.js`, `adaptor.js`, `startup*.js`, UI, theme, Markdown tools |
| `docs/` | [`FORMAT.md`](docs/FORMAT.md), [`THREAT-MODEL.md`](docs/THREAT-MODEL.md), [`DEPLOY.md`](docs/DEPLOY.md) |
| `tests/` | Python and Node suites, run against a mock GitHub API. See [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| `demo/` | synthetic demo wiki builder and cast generator |

## Compatibility

Only public extension points are used: `syncadaptor`, `startup`, `saver` and `library` modules, `$tw.utils.getPassword`, and the syncer's skinny/lazy-load protocol. Nothing in `$:/core` or the boot kernel is patched. It has been tested with TiddlyWiki 5.1.21; re-run the test suites after upgrading the core.

## Markdown tools (please read)

New tiddlers default to `text/x-markdown`. To turn that off, set `$:/config/ext/DefaultNewType` to empty.

The plugin also contains a WikiText→Markdown converter, and it **runs once automatically** the first time a wiki is opened with this plugin. It converts only notes whose WikiText it fully understands and whose Markdown renders identically, and it keeps **no backup**. Everything else is listed in *Control Panel → Markdown* for manual review.

**If you don't want this, create `$:/config/ext/md/AutoConvert` with the text `no` before the first open**, and keep a backup of your wiki in any case (`twmigrate.py inline`). The converter targets the third-party *tw5-markdown* plugin.

## Licence

[MIT](LICENSE). TiddlyWiki is © Jeremy Ruston and contributors, BSD-3-Clause, and is not included in this repository.
