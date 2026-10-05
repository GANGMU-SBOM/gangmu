#!/usr/bin/env bash
# The README's opening example, reproducible.
#
#   ./examples/disguise.sh /tmp/gangmu-disguise
#
# Takes a real GmSSL 3.0.0 release and does to it what vendor SDKs do: moves it
# to a directory with another name, deletes the version header, prefixes a
# third of the files' SM3/SM4 identifiers with a vendor tag, adds vendor
# functions and drops eight source files. Then asks gangmu what it is.
set -euo pipefail

WORK="${1:-/tmp/gangmu-disguise}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -rf "$WORK" && mkdir -p "$WORK/firmware/components"
git -c advice.detachedHead=false clone --quiet --depth 1 --branch v3.0.0 https://github.com/guanzhi/GmSSL "$WORK/GmSSL"
cp -r "$WORK/GmSSL" "$WORK/firmware/components/crypto_sm"
cd "$WORK/firmware/components/crypto_sm"
rm -rf .git include/gmssl/version.h

python3 - <<'PY'
import pathlib, random, re
random.seed(1)
files = sorted(pathlib.Path("src").glob("*.c"))
for f in random.sample(files, len(files) // 3):
    s = f.read_text(errors="replace")
    s = re.sub(r"\bsm3_", "vendor_sm3_", s)
    s = re.sub(r"\bsm4_", "vendor_sm4_", s)
    f.write_text(s + "\nint vendor_extra_hook(int x){return x*2+1;}\n")
for f in files[:8]:
    f.unlink()
PY

cd "$REPO"
gangmu scan "$WORK/firmware" --format table
gangmu scan "$WORK/firmware" --format json \
  | python3 -c "import json,sys; [print('  -', e['summary']) for f in json.load(sys.stdin)['findings'] for e in f['evidence']]"
