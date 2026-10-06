# How identification works, and where it comes from

The first version of this tool matched at directory level: winnowed k-gram
fingerprints over a whole tree, compressed to a bottom-k sketch. That is a
reasonable thing to build and it is not good enough, for a reason the
measurements made plain:

| | whole-tree sketch | true Jaccard |
| --- | --- | --- |
| upstream lwIP 2.2.0 vs **Espressif's fork of it** | 0.949 | 0.949 |
| upstream lwIP 2.2.0 vs **upstream 2.1.3** | 0.887 | 0.867 |

A vendor fork and a neighbouring release are 0.06 apart. There is no threshold
that separates "forked" from "different version", so a tool built this way
cannot answer the question a CVE range match depends on.

## What the literature already settled

Three papers address exactly this, and this tool now follows them.

**CENTRIS** (Woo et al., ICSE 2021) matches at **function** granularity and
introduces two ideas this tool uses:

* *Code segmentation.* A component is identified by its **application code** —
  its own functions, with nested third-party code subtracted. Without this, if A
  vendors B, then every firmware containing B also appears to contain A.
* *Redundancy elimination.* Functions shared across many versions carry no
  version information; storing and weighting by version frequency is what makes
  the comparison both fast and discriminating.

**V1SCAN** (Woo et al., USENIX Security 2023) shows that version-based and
code-based evidence have to be combined for *partially* reused OSS, and reports
that mapping a single version onto a modified component produces a large
majority of the false positives in 1-day vulnerability detection.

**TIVER** (Korea University SSP, ICSE 2025) names the cause: a modified
component usually contains functions from **several upstream versions at once**.
Its answer is an *adaptive version* — a range, not a point — and it reports
removing 81.47% of the false positives that single-version mapping creates.

## What this tool took, and what it did not

| idea | taken | how it differs here |
| --- | --- | --- |
| function-level matching | yes | bodies hashed over a normalised **token stream**, not TLSH over text |
| containment of application code | yes | CENTRIS's Φ, with the version's own function set as the denominator |
| multi-version function bins | yes | a 64-bit version bitmap per function, stored in a binary sidecar |
| adaptive version range (TIVER) | yes | versions scored by **Jaccard over version-discriminating functions**, not raw coverage — coverage alone cannot separate a release from its successor, because the successor contains everything the release did |
| code segmentation (CENTRIS) | **simplified** | the direction of borrowing cannot be read off signatures alone, so a function appearing in more than one rule is application code for **none** of them. Weaker than CENTRIS, costs some recall, but it cannot invent a dependency that is not there |
| abstraction levels (VUDDY, MOVERY) | yes | two levels: exact bodies, and bodies with identifiers collapsed. An abstract-only match scores lower, because abstraction discards real evidence |
| binary analysis (BinCoFer, FIRE) | no | out of scope by choice; see the README |

## What it bought

Same trees, same include globs, function level instead of whole-tree:

| | whole-tree sketch | **function level** |
| --- | --- | --- |
| lwIP 2.2.0 vs Espressif's fork | 0.949 | **0.887** |
| lwIP 2.2.0 vs upstream 2.1.3 | 0.887 | **0.638** |
| **separation between the two** | **0.06** | **0.25** |

Four times the separation, which is the difference between a threshold that
works and one that does not. Version accuracy over six real trees including the
fork: **6/6 exact**. See [BENCHMARK.md](BENCHMARK.md).

## And it is faster

Function hashing is not a more expensive analysis bought with time. It is
cheaper, because the set it produces is two orders of magnitude smaller:

| | lwIP 2.2.0, 296 files |
| --- | --- |
| winnowed fingerprints | 105,405 values, 0.59 s |
| **function hashes** | **1,937 values, 0.28 s** |

Both come from the same token pass, so computing them together costs one
tokenise rather than two. The signature is small enough to store **whole** —
3,016 functions across 8 releases in 91 KB — so similarity is an exact set
operation with no sketching error at all. The sketch path remains as a fallback
for components where function extraction finds nothing (assembly, or code built
entirely inside macros).

## The extractor

Not a parser, deliberately. It walks the token stream for the shape
`name ( ... ) {` at brace depth zero and takes the balanced block. That accepts
attributes, `const`/`noexcept`, and K&R parameter declarations — still present in
the legacy embedded code this tool exists for — and rejects prototypes on the
one token that distinguishes them: a `;` immediately after the parameter list.

Getting that one token wrong made prototypes swallow everything up to the next
unrelated brace, and it cost two spurious "functions" in lwIP before it was
caught by a test.

## State of the art, 2025, and where this tool stands

Read in full: VULTURE and "Drop the Golden Apples". Read as abstracts or search
summaries only (treat the figures as theirs, not verified here): BinCoFer,
LibAM, BinaryAI, DeRed, Lares.

| work | what it adds | here |
| --- | --- | --- |
| **VULTURE** (NDSS 2025) | Two-segment database (component, vulnerability). TLSH fuzzy hashes of functions, so a *modified* function still matches. Disambiguates overlapping candidates with auxiliary evidence: the file path against the library name, then **birth time** (the earliest of a group sharing hashes is the parent). Decides vulnerable / patched by testing the vulnerable and patched function (and "chunks" of it) separately from the version, because developers patch in place without changing the version. | Path and name are a nudge (`resolve`); segmentation drops code shared between rules but has no birth-time tie-break. Version is never the only channel, but patch presence is **not** tested: `gangmu vuln` reasons from version ranges and (with `--source`) reachability. |
| **BinCoFer** (JSS 2025, binaries) | "Purifies" the feature repository in three stages: remove a library's internal functions, filter trivial functions, down-weight functions cloned across libraries. Reports 89.3% precision / 64.9% recall. | Segmentation (cross-rule) and the 6-token / 24-token floors are the same idea at source level. Not done: weighting by how many *libraries* share a function, rather than all-or-nothing removal. |
| **LibAM, DeRed** (binaries) | Match *areas* of the call graph, not isolated functions, so optimisation level and architecture matter less; DeRed adds a stage to discount deceptive reuse. | Out of scope: source and build first. A call-graph area would help the binary path. |
| **Drop the Golden Apples** (FSE 2025) | No database: LLM agents gather textual evidence (README, homepage, licence) and search the live web. Success about 58-59% on its two tasks; the authors say it does not compete with database tools on accuracy. | Not adopted. The rule base is the point, and a scan that must work air-gapped cannot browse. Worth noting: it is a source of *candidate* rules, never of a finding. |
| **Lares** (2025) | LLM-driven code-slice search for patch presence testing, to cut the false positives patch tests produce on unrelated functions. | See patch presence above. |

What the comparison says is worth doing next, in order of expected effect on
noise:

1. ~~**Patch presence, not just version.**~~ Done; see the next section.
2. ~~**Fuzzy function matching for edited functions.**~~ Done for patch presence
   (see Patch presence); measured and not worth it for identification.
3. **Weight by sharing, and break ties by age.** Replace "in more than one rule
   means none" with an inverse-frequency weight, and prefer the earliest-born
   project among rules that tie.

## Patch presence

A version range says which releases are affected. A vendor fork reports the
release it started from, so an advisory fixed in a later release matches it
whether or not the vendor already took the fix, and nothing in the version can
say. Before this, every such finding sat in `in_triage` for ever.

`gangmu patch-build` records, for one advisory, the functions its fix commit
touched: the hash of each body before the fix and after it (the same token-stream
hashes identification uses, so formatting and comments never matter), and the
identifier-abstracted hashes for renamed copies. `gangmu vuln --source ROOT
--patches FILE` then classifies each recorded function in the matched component's
directory:

| per function | meaning |
| --- | --- |
| `fixed` | the fixed body is present |
| `vulnerable` | the vulnerable body is present |
| `modified` | the function is defined, with neither body: the vendor edited it |
| `absent` | not defined anywhere in the directory |

and gives one verdict: `fixed` (a fixed body, no vulnerable one), `vulnerable`,
`partial` (both: an incomplete fix), `modified` or `absent`. `fixed` resolves the
finding, `vulnerable` and `partial` confirm it, and `modified` and `absent` leave
it in triage with the reason attached, because the code does not settle it.

Decisions that are easy to get wrong:

* **Exact before abstract, and abstract only where it can tell the two apart.**
  If a one-identifier fix leaves the abstract body unchanged, abstraction cannot
  separate vulnerable from fixed, so those hashes are not recorded.
* **A refactor is not a fix.** A commit that changes more than 40 functions is
  refused unless the functions are named: its hashes would call any tree that
  merely differs from it modified.
* **A merge commit is not a fix.** It has two parents, so "before" is undefined.
* **Only shipped code is read.** Tests, examples and docs of the component are
  excluded, as in identification; a fixed copy in `test/` does not resolve
  anything.
* **A verdict of `fixed` is "the fixed code is here".** It does not see a fix
  that lives in a macro, a struct or a build flag, a renamed function (which
  looks `absent`), or a fix split over commits that were not all recorded.

Checked on real code: CVE-2025-1866 (libwebsockets) was built from the OSV record
alone (repository and fix commit read from the advisory, fetched from GitHub),
giving one function, `lws_mux_mark_immortal`. The tree at the fix's parent and at
v4.3.3 tests `vulnerable`; the fix commit and v4.3.5 test `fixed`.

### Edited copies: near matching

A vendor who changes one line of a function defeats the exact hash, and the
function lands in `modified`. Comparing the whole body does not help: a copy with
a vendor log line is as close to the fixed body as to the vulnerable one. What
separates them is the fix itself. A record also stores, per function, the token
windows (4 consecutive tokens) the fix **added** and the ones it **removed**, plus
small bottom-k sketches of both bodies. An edited copy is then asked how much of
each it carries: the added code and none of the removed code is a variant of the
fix; the removed code and none of the added is a vulnerable variant; anything
between is left alone. Unrelated edits touch neither set, so they do not move the
answer. This is VULTURE's chunk comparison on token windows.

The verdicts are `likely_fixed` and `likely_vulnerable`. They are reported, with
the shares they rest on, but change the VEX state only under
`--patch-near-vex`: only a byte-identical body is allowed to do that by default.
Three details came from measuring rather than from design:

* **Seam windows are not evidence.** A fix that only inserts code "removes" the
  windows straddling the insertion point, and any vendor edit beside it destroys
  them, so a plainly vulnerable copy read as unclear. A removed set smaller than
  two window-widths is ignored.
* **The threshold sits away from a cliff.** On cJSON's history, claims are all
  right at 70% of the added windows and start to be wrong at 65%; the default is
  80%.
* **A rewrite is not an edit.** Below 50% similarity to the nearer body the
  function is reported as modified and nothing more.

Measured on cJSON: every commit that looks like a security fix (112 of them,
cosmetic ones excluded) against every release tag (49), with the truth taken from
git ancestry. Exact hashes make 1,166 claims, none wrong. Near matching adds 853
more, none wrong. With cosmetic commits (warning fixes, pragmas) included, exact
makes 9 wrong claims in 1,422 and near 16 in 1,026 (98.4%): a commit that
reorders or restores code older releases already had makes the "added" windows
present before the fix, and no threshold removes that. One repository, so the
thresholds may not transfer; the lwIP run was not completed.

**Measured and not built: near matching for identification.** On a real vendor
fork (RT-Thread's lwIP 2.1.2 against upstream 2.1.2) 98.9% of functions already
match exactly, and near matching would raise that to 99.5%. That does not pay for
a new signature format and a rebuild of every pack, so identification stays
exact-then-abstract.

## Measuring noise

Every change above that reduces noise was found by scanning *pristine*
upstream releases laid out as an SDK lays them out, and counting what the scan
says that is not true: a component that is not there, a copy labelled modified
that is not, a component in the wrong directory, an upstream project reported
twice. That corpus is cheap to rebuild (`git clone --depth 1 --branch TAG`) and
catches what a synthetic-mutation benchmark cannot, because the mistakes come
from real repositories' headers, examples and ports.

Two measured facts shaped the fixes and are worth keeping in mind when
touching the extractor:

* The shipped signatures *include* function-like `#define` macros (75 to 122
  recorded hashes in lwIP, libcoap and Mbed TLS). Skipping macros in the
  extractor looks like the obvious cure for phantom "vendor additions" and is
  wrong: it silently removes matches from every shipped signature. The phantom
  functions come from files the signature does not cover, so the fix is in the
  judgement of "modified", not in the hash.
* On pristine trees the number of recorded functions of the identified release
  that are *missing* is 0 in every case measured, while the number of functions
  the signature never saw ranges from 0 to 1,487. Missing or altered recorded
  code is the signal that separates an edit from a bigger tree.

## Citations

* Woo, Park, Choi, Lee, Oh. *CENTRIS: A Precise and Scalable Approach for
  Identifying Modified Open-Source Software Reuse.* ICSE 2021.
  [arXiv:2102.06182](https://arxiv.org/pdf/2102.06182)
* Woo, Lee, Oh. *V1SCAN: Discovering 1-day Vulnerabilities in Reused C/C++
  Open-source Software Components Using Code Classification Techniques.*
  USENIX Security 2023.
  [paper](https://www.usenix.org/system/files/usenixsecurity23-woo.pdf)
* *TIVER: Identifying Adaptive Versions of C/C++ Third-Party Open-Source
  Components.* ICSE 2025.
  [paper](https://ssp.korea.ac.kr/assets/papers/ICSE25.pdf)
* Schleimer, Wilkerson, Aiken. *Winnowing: Local Algorithms for Document
  Fingerprinting.* SIGMOD 2003. (the fallback path)
* Xu, Dong, Cai, Li, Shaghaghi, Sun, Ma. *Enhancing Security in Third-Party
  Library Reuse: Comprehensive Detection of 1-day Vulnerability through Code
  Patch Analysis* (VULTURE). NDSS 2025.
  [paper](https://www.ndss-symposium.org/wp-content/uploads/2025-576-paper.pdf)
* Zhang et al. *Drop the Golden Apples: Identifying Third-Party Reuse by
  DB-Less Software Composition Analysis.* FSE 2025.
  [arXiv:2503.22576](https://arxiv.org/pdf/2503.22576)
* *BinCoFer: Three-Stage Purification for Effective C/C++ Binary Third-Party
  Library Detection.* JSS 2025.
  [arXiv:2504.19551](https://arxiv.org/abs/2504.19551)
* *LibAM: An Area Matching Framework for Detecting Third-Party Libraries in
  Binaries.* [arXiv:2305.04026](https://arxiv.org/pdf/2305.04026)
* *Lares: LLM-driven Code Slice Semantic Search for Patch Presence Testing.*
  [arXiv:2511.01252](https://arxiv.org/pdf/2511.01252)
