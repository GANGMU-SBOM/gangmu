# The rule format

One rule is one directory's identity claim plus the evidence that lets a machine
re-check it. Everything a rule asserts must be falsifiable against a named
upstream release; that is why `upstream.source` is required rather than
documentary.

```yaml
id: espressif/esp-idf/lwip          # unique; also the path under rules/ in gangmu-rules by convention
vendor: espressif                   # optional, but raises the rule's specificity
sdk: esp-idf
sdk_versions: ">=5.0"               # free text today; used only to rank rules

component:
  path_globs:                       # where the component normally sits. A hint for
    - "components/lwip/lwip"        # ranking and discovery -- never a gate, because
  ships_as: lwip                    # a copied component is usually *not* where it belongs
  marker_files:                     # optional: files that, all present in one directory,
    - src/core/tcp.c                # mark a copy wherever it is and whatever the vendor
    - src/core/pbuf.c               # named it (generic/freertos-kernel uses tasks.c,
                                    # queue.c, list.c). Discovery only: matching still
                                    # decides identity.
  config_symbols:                   # optional: Kconfig options that switch this component on
    - MBEDTLS                       # (any one is enough). If an sdkconfig / .config says all
                                    # of them are off, the component is left out of the SBOM.
                                    # An option the file never mentions removes nothing.
                                    # Which option builds a component depends on the SDK it sits
                                    # in, so a generic rule can scope one to a path:
                                    #   - path: '**/modules/crypto/mbedtls'
                                    #     symbols: [MBEDTLS]

upstream:
  name: lwIP                        # the thing it actually is
  purl: "pkg:generic/lwip"          # version is spliced in at scan time
  cpe: "cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*"
  homepage: "https://savannah.nongnu.org/projects/lwip/"
  license: BSD-3-Clause
  advisory_scope: subsystem         # optional; OS/SDK trees whose advisories each name one subsystem
  support:                          # optional; omit unless you can cite a source
    status: maintained              # maintained | limited | no_longer_maintained | abandoned
    end_of_support: 2027-03-31      #   YYYY-MM-DD, only when the project states one
    source: https://example.org/BRANCHES.md   # where a reviewer checks it
    as_of: 2026-10-06               #   the day it was checked
  source:                           # REQUIRED -- what CI re-derives the evidence from
    kind: git
    url: https://github.com/espressif/esp-lwip
    ref: fc73c67e5c37c27a319725a0aee974c087dbf1a6
    subdir: null                    # optional; the component root inside the repo
  mirrors:                          # optional; more repositories to re-derive from, for
    - kind: git                     #   releases the primary lacks (verify checks each
      url: https://github.com/example/lwip   #   fetches; it does not compare evidence)
      ref: 0123456789abcdef0123456789abcdef01234567

vendor_fork:
  patched: true
  upstream_of_fork: https://github.com/lwip-tcpip/lwip
  note: "Espressif fork of lwIP 2.2.0 with ESP32 netif, PPP and SMP patches."

identity:
  include: ["src/**/*.c", "src/**/*.h"]   # relative to the matched directory
  exclude: ["**/test/**"]                 # defaults already drop test/doc/example
  anchors:                                # tier 1: exact, pins identity and version
    - path: src/include/lwip/init.h
      sha256:
        "2.2.0": "0696ee...365e"
  signature:                              # tier 2: identity only
    algo: winnow-bottomk
    k: 16
    window: 8
    size: 256                           # values kept (default 256)
    reference_version: "2.2.0"
    fileset_sha256: "8e01f1...9b9e"       # exact-copy test; see docs/CALIBRATION.md
    values: >-
      <2048 bytes of hex: 256 values of 8 bytes>
  thresholds: {exact: 0.98, strong: 0.85, weak: 0.60, floor: 0.35}   # optional
  binary_strings:                         # optional: recognise the component inside compiled images
    file: lwip.strings.fnsig              #   string-constant sidecar, built with
    sha256: "..."                         #   `gangmu rules functions <url> --tag ... --strings --out`
    count: 1200                           #   a rule may carry only this, with no source anchors
  binary_banners:                         # optional: text the library prints about itself, in compiled images
    - 'ThreadX [A-Za-z0-9/ +_-]{0,40}Version G?(\d+\.\d+\.\d+)'   # one capturing group: the release
                                          #   Checked when the rule loads, because the pattern runs over every byte
                                          #   of every binary in a tree: at most 160 characters, one capturing
                                          #   group, at least four literal characters, and no unbounded wildcard
                                          #   (`.*`, `\S+`, `[^x]+`) or nested repetition. Bound a gap as {0,40}.
                                          #   Gangmu's own banner list wins for a component it already knows. Needs
                                          #   gangmu 0.12.0: set `requires_gangmu` in the pack's rulebase.json.
  binary_functions:                       # optional: find the component's functions inside compiled images
    file: lwip.fnprint                    #   per-function fingerprints (strings and constants a function
    sha256: "..."                         #   uses), built with `gangmu rules binary-prints`; needs `disasm`
    count: 900                            #   (distinct fingerprinted functions)
    versions: ["2.1.3", "2.2.0"]
    calibration:                          # REQUIRED, copied from the command's output. The tool built the
      passed: true                        #   fingerprints, then tried them on builds they were not made
      releases: 2                         #   from: every release is supplied built at least twice (-Os and
      builds_per_release: 2               #   -O2), and each build is identified from the others as a
      fingerprintable: 900                #   stripped image. Needs >= 2 releases, >= 10 fingerprintable
      cross_build: {exact: 2, range: 2,   #   functions, no wrong release and no unrecognised image across
                    wrong: 0, none: 0}    #   builds, and no match on any --negative firmware. The loader
      same_build: {exact: 2, range: 2,    #   refuses a rule whose block is missing, says passed: false, or
                   wrong: 0, none: 0}     #   differs from the self-test stored in the sidecar (its digest
      negative_pairs: 6                   #   is pinned above, so the figures cannot be edited by hand).
      false_positives: 0                  #   Build for the SAME architecture as the firmware, linking only
      min_features: 2                     #   the library's own code (no libc): x86 references matched no
      tie_share: null                     #   Thumb image, and libc functions in a reference look like the
      version: 1                          #   library. The self-test shows the fingerprints work on builds
                                          #   the author made, not on a compiler or flags nobody tried.
                                          # One sidecar per architecture: `binary_functions` may be a
                                          #   list of these blocks instead of one. Each is built for its
                                          #   own CPU (a Thumb build and an AArch64 build are different
                                          #   evidence, because compilers derive different constants);
                                          #   an image is matched against the sidecar built for its CPU
                                          #   first, then the others by string literals only. Two
                                          #   sidecars for the same architecture fail `gangmu rules lint`.
  functions:                              # tier 2b: identity AND version, function level
    file: lwip.fnsig                      # binary sidecar beside the rule; built with
    sha256: "6aa531...554a"               #   `gangmu rules functions <url> --tag ... --out`
    count: 3022                           # distinct functions in the sidecar
    subset: true                          # optional: the component is routinely copied in part
                                          #   (an SDK package carries only the drivers its chip
                                          #   uses). If too little of a release is present for
                                          #   containment to reach the floor, accept the directory
                                          #   when >= 40 of its functions are the component's and
                                          #   >= 90% of its functions are; identity 0.75, version =
                                          #   the releases that hold every function found.
    family: gd32                          # optional: rules for sibling ports of one code base
                                          #   (one rule per chip family) name the same family;
                                          #   functions they share stay application code for
                                          #   each, instead of being dropped as borrowed code.
    derivative: true                      # optional: vendors ship trimmed, rewritten copies of
                                          #   this component. When >= 300 of a directory's functions
                                          #   are byte-identical to recorded releases and they are
                                          #   >= 30% of the directory, report a modified derivative:
                                          #   identity 0.5, no version, vendor_patched. Advisories
                                          #   for the product then surface only as in_triage.
    versions: ["2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1"]

version:
  probes:                                 # tier 3: version only
    - file: src/include/lwip/init.h
      patterns:
        major: 'LWIP_VERSION_MAJOR\s+(\d+)'
        minor: 'LWIP_VERSION_MINOR\s+(\d+)'
        revision: 'LWIP_VERSION_REVISION\s+(\d+)'
      template: "{major}.{minor}.{revision}"

confidence_ceiling: 0.95                  # no rule may claim certainty
review:
  added: "2026-10-03"
  by: ["@someone"]
```

## What is validated at load time

* `upstream.source` present and well formed;
* at least one anchor, signature, function signature (`functions`), `binary_strings`
  or `binary_functions` -- a rule with nothing checkable is refused outright;
* `cpe` is a 13-part CPE 2.3 name. A CPE with the wrong vendor matches no CVE at
  all, and the SBOM then looks clean, which is the most expensive way for a rule
  to be wrong. (`lwip:lwip` is wrong; NVD registers lwIP as `lwip_project:lwip`.)
* `cpe_evidence`, when present, lists CVE ids and requires a `cpe`. These are
  NVD records whose references point at the upstream's own repository or site
  and whose configuration names the CPE, so a reviewer can check the pair in a
  minute. `gangmu rules cpe-evidence --nvd DIR` finds them in a local NVD
  mirror and ranks every vendor:product it sees; a CPE is written into a rule
  only from that evidence, never guessed. When nothing turns up, `cpe_status`
  says so (`none-in-nvd: ...`) so the next contributor does not search again.
* `identity.functions.sha256` is 64 hex characters. Whether it matches the
  sidecar is checked by `gangmu rules verify`, which regenerates the `.fnsig`
  from the releases `versions` names, so it is verified rather than reviewed.
  The sidecar is what lets a vendor fork that mixes functions from several
  releases get a version interval instead of a guess (see
  [ALGORITHMS.md](ALGORITHMS.md));
* a rule with no `cpe` needs a `cpe_status` (`gangmu rules lint` fails
  otherwise). The reasons in use begin with a keyword: `none-in-nvd` (a full NVD
  mirror was searched), `none-found` (searched, nothing registered) or
  `unverified` (nobody could look, for instance with no network). `unverified`
  is the one a reviewer should chase; none of them is a guess;
* `upstream.advisory_scope: subsystem` marks an OS or SDK tree (Zephyr, ESP-IDF). `gangmu vuln` then reports
  a version-range match on it as `in_triage`, not `exploitable`, with a note: the advisory names one
  subsystem or driver and the version alone cannot say whether the firmware builds it.
* `upstream.support`, when present, has a `status` from the list above and
  `YYYY-MM-DD` dates. It is a claim about the upstream project at `as_of`, so it
  needs a `source` a reviewer can open; do not guess. A scan can override it with
  `--support FILE`, and components nobody names are written as `unknown`;
* `purl` starts with `pkg:`;
* every anchor digest is 64 hex characters;
* every probe pattern compiles;
* ids are unique across the whole base.

A malformed rule is reported and skipped, not fatal -- one bad contribution must
not take down everyone else's scan.

## Authoring a rule

```bash
git clone --depth 1 --branch v1.7.19 https://github.com/DaveGamble/cJSON
gangmu rules fingerprint cJSON --version 1.7.19 \
    --include 'cJSON.c' --include 'cJSON.h' --anchor cJSON.h
```

Paste the printed `identity:` block into the rule, fill in the metadata, and
open a pull request. CI clones the release your rule names and recomputes
everything; if it does not reproduce byte for byte, the pull request fails with
the diff spelled out.

### Draft rules from a list of upstream projects

When the projects to cover come from elsewhere -- for instance an index of the
public package registries that names the libraries their packages republish --
put them in a JSON file and let gangmu build the drafts:

```json
{"candidates": [
  {"name": "LwRB", "url": "https://github.com/MaJerle/lwrb", "license": "MIT",
   "note": "republished by 3 packages on PlatformIO and RT-Thread"}
]}
```

```bash
gangmu rules import candidates.json --manifest candidates --out rules/generic
gangmu rules lint --rules rules
gangmu rules verify --rules rules --rule generic/lwrb
```

Only `url` (and an optional `subdir`) is taken from the file. gangmu lists the
repository's release tags (pre-releases left out), fingerprints the latest
release, builds the `.fnsig` from the most recent `--limit` releases (12) and
pins `upstream.source.ref` to the latest tag, so `rules verify` reproduces the
rule like any other. The rule describes the whole repository, ports and demo
applications included, which vendors rarely copy whole, so it is marked
`functions.subset`. An entry flagged `bundles` -- much of its code is also in
other, unrelated packages, which it may bundle or which may bundle it -- is not:
a rule that accepts partial copies would claim those packages' code. No CPE is
guessed: the draft says `cpe_status: unverified ...` and `review.todo`; look one
up (`gangmu rules cpe-evidence`) before merging.

### A host that bundles another rule's library

A rule built from a whole repository records the libraries that project carries
a copy of (dropbear's libtomcrypt, picotool's littlefs). Segmentation keeps that
code the bundled library's when the copy is a small part of the host (at most
10% of its signature); above that it cannot tell a bundled copy from a fork or a
library split out of another, so the code is nobody's and the bundled library
can no longer be identified by its functions. `gangmu rules bundled` lists every
pair the signatures show:

```text
lost    generic/dropbear      bundles generic/libtomcrypt   1.18.2 979/994   33.9% of host
lineage generic/mbedtls       bundles generic/mbed-crypto    3.1.0 1251/1328 18.3% of host
kept    generic/clamav        bundles generic/zlib          1.2.11 182/194    0.3% of host
```

`lineage` (each holds a whole release of the other) is a fork or a split and is
right as it is. A `lost` copy is fixed in the host's rule: find where it keeps
the copy and exclude that directory, then rebuild the signature with the same
`--exclude`:

```bash
gangmu rules bundled --rule generic/dropbear --tree dropbear/   # a checkout of the host
gangmu rules functions https://github.com/mkj/dropbear --out dropbear.fnsig \
    --exclude 'libtomcrypt/**' --exclude 'libtommath/**' ...
```

## Conflict resolution

Several rules may legitimately fire on one directory -- a generic "vendored
lwIP" rule and a specific "ESP-IDF ships lwIP here" rule, for instance. They are
ranked by identity confidence, then by whether a version was resolved, then by
specificity (vendor, sdk, sdk_versions and path globs each add weight), then by
rule id so output is reproducible. The winner is reported; competitive
alternatives for a *different* upstream project are attached to it, because a
reviewer looking at a 0.6-confidence call wants to see what else it could have
been.
