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
