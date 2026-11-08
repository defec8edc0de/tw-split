#!/usr/bin/env bash
# Build a SYNTHETIC, password-encrypted TiddlyWiki 5.1.21 for demos and tests (no real data anywhere).
#   demo/build-demo.sh [DIR]     -> DIR/tw.html   (default DIR=demo/work)
# Needs: node, curl, openssl. Downloads the official tiddlywiki@5.1.21 npm tarball and verifies its sha512.
set -euo pipefail
DIR="${1:-$(dirname "$0")/work}"
PW="demo-password-not-a-secret"            # throw-away demo password, printed on purpose
TGZ_URL="https://registry.npmjs.org/tiddlywiki/-/tiddlywiki-5.1.21.tgz"
TGZ_SHA512="sha512-VuBK9N2u9ttPcaHCh4NmRX3YYB2tMPoIKCHhfNaJ62VGQj8ozmVD+PkvP/w7R50g6HaZtaSsqUJj26gRTIBa6w=="
mkdir -p "$DIR" && cd "$DIR"
if [ ! -f tiddlywiki-5.1.21.tgz ]; then curl -fsSLO "$TGZ_URL"; fi
got="sha512-$(openssl dgst -sha512 -binary tiddlywiki-5.1.21.tgz | base64 -w0)"
[ "$got" = "$TGZ_SHA512" ] || { echo "integrity check failed for tiddlywiki-5.1.21.tgz" >&2; exit 1; }
rm -rf package wiki && tar xzf tiddlywiki-5.1.21.tgz
node package/tiddlywiki.js wiki --init empty >/dev/null
mk() { printf 'title: %s\ntags: %s\ntype: text/x-markdown\n\n%b\n' "$1" "$2" "$3" > "wiki/tiddlers/$4.tid"; }
mkdir -p wiki/tiddlers
mk "Lorem ipsum"   "notes"       "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer posuere erat a ante." lorem
mk "Reading list"  "notes books" "- *The Cuckoo's Egg*\\n- *Secrets and Lies*\\n- *Security Engineering*" reading
mk "Garden plan"   "garden"      "Tomatoes along the south fence; basil between them." garden
mk "Weekly review" "journal"     "What went well, what did not, what next." review
mk "Ideas"         "notes"       "A tiny encrypted notebook that lives on GitHub Pages." ideas
printf 'title: $:/SiteTitle\n\nDemo Wiki\n' > wiki/tiddlers/sitetitle.tid
printf 'title: $:/SiteSubtitle\n\nsynthetic demo data — not a real wiki\n' > wiki/tiddlers/sitesub.tid
node package/tiddlywiki.js wiki --password "$PW" --rendertiddler '$:/core/save/all' demo-encrypted.html text/plain
cp wiki/output/demo-encrypted.html tw.html
echo "demo wiki: $(pwd)/tw.html   (password: $PW)"
