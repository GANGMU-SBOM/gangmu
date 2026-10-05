#!/usr/bin/env bash
# Reproduces the README's output from real upstream trees.
#
#   ./examples/demo.sh /tmp/gangmu-demo
#
# Clones upstream lwIP, Espressif's lwIP fork and cJSON, assembles a project
# laid out like an ESP-IDF one, synthesises the build artefacts a real build
# would leave behind, and scans it.
set -euo pipefail

WORK="${1:-/tmp/gangmu-demo}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$WORK"/{samples,project/components/{lwip,json,legacy},project/main,project/build}
cd "$WORK/samples"

clone() {  # repo, dir, ref
  [ -d "$2" ] && return 0
  git clone --quiet --depth 1 "https://github.com/$1" "$2"
  if [ -n "${3:-}" ]; then
    git -C "$2" fetch --quiet --depth 1 origin "$3"
    git -C "$2" checkout --quiet FETCH_HEAD
  fi
}
clone espressif/esp-lwip esp-lwip
clone DaveGamble/cJSON cJSON v1.7.19

cp -r esp-lwip "$WORK/project/components/lwip/lwip"
cp -r cJSON    "$WORK/project/components/json/cJSON"
cp -r cJSON    "$WORK/project/components/legacy/cJSON"
rm -rf "$WORK"/project/components/*/*/.git

cat > "$WORK/project/main/app_main.c" <<'EOF'
#include "lwip/init.h"
void app_main(void) { lwip_init(); }
EOF

python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1]) / "project"
build = root / "build"
entries, objs = [], {}
def add(src, archive):
    obj = build / "esp-idf" / archive / (src.name + ".obj")
    entries.append({"directory": str(build), "file": str(src), "output": str(obj),
                    "command": f"xtensa-esp32-elf-gcc -c {src} -o {obj}"})
    objs.setdefault(archive, []).append(obj)
for p in sorted((root/"components/lwip/lwip/src/core").glob("*.c"))[:12]:
    add(p, "lwip")
add(root/"components/json/cJSON/cJSON.c", "json")
add(root/"components/legacy/cJSON/cJSON.c", "legacy")
add(root/"components/legacy/cJSON/cJSON_Utils.c", "legacy")
(build/"compile_commands.json").write_text(json.dumps(entries, indent=1))

lines = ["Archive member included to satisfy reference by file (symbol)", ""]
for archive in ("lwip", "json"):
    for o in objs[archive]:
        lines += [f"esp-idf/{archive}/lib{archive}.a({o.name})",
                  "                              esp-idf/main/libmain.a(app_main.c.obj) (ref)"]
lines += ["", "Discarded input sections", ""]
for o in objs["legacy"]:
    lines.append(f" .text   0x0   0x2a esp-idf/legacy/liblegacy.a({o.name})")
lines += ["", "Memory Configuration", "", "Linker script and memory map", ""]
(build/"firmware.map").write_text("\n".join(lines) + "\n")
print(f"synthesised {len(entries)} compile entries and a linker map")
PY

export GANGMU_RULES="$REPO/rules"
cd "$WORK"
echo
echo "### source tree only -- the legacy copy looks shipped"
gangmu scan project --format table
echo
echo "### with the build -- the linker says otherwise"
gangmu scan project \
  --compile-db project/build/compile_commands.json \
  --link-map   project/build/firmware.map \
  --format table
echo
gangmu scan project \
  --compile-db project/build/compile_commands.json \
  --link-map   project/build/firmware.map \
  --format cyclonedx -o "$WORK/sbom.json"
echo "CycloneDX written to $WORK/sbom.json"

echo
echo "### the compliance path a team runs after it"
cd "$WORK"
[ -f gangmu.yaml ] || gangmu init . >/dev/null
gangmu vuln sbom.json --db "$REPO/tests/fixtures/advisories" \
  --format cyclonedx -o vex.json
gangmu vuln sbom.json --db "$REPO/tests/fixtures/advisories" --format table || true
echo
gangmu cra-check --sbom sbom.json --vex vex.json --no-fail | tail -20
echo
echo "The advisory fixtures above are SYNTHETIC (TEST-... identifiers)."
echo "Point --db at a real NVD or OSV mirror for real findings."
