# Calibration

Every threshold in the matcher comes from a measurement, not a guess. These are
reproducible: clone the trees named below and run
`gangmu rules fingerprint` on each, or run the snippet at the end.

## Similarity between real trees

Winnowed k-grams over the token stream, `k=16`, `window=8`, bottom-k sketch of
`size=256`, include `src/**/*.c` and `src/**/*.h`.

"exact" is the true Jaccard of the full fingerprint sets, computed without any
sketch; the rest is what a sketch of that size estimates.

| left | right | exact | k=128 | **k=256** | k=512 |
| --- | --- | --- | --- | --- | --- |
| lwIP 2.2.0 | lwIP 2.2.2 | 0.985 | 0.992 | **0.992** | 0.990 |
| lwIP 2.2.0 | esp-lwip (Espressif's fork of 2.2.0) | 0.949 | 0.945 | **0.949** | 0.951 |
| lwIP 2.2.0 | lwIP 2.1.3 | 0.867 | 0.906 | **0.887** | 0.877 |
| lwIP 2.2.0 | cJSON 1.7.19 | 0.000 | 0.000 | **0.000** | 0.000 |

`size=256` is the default: at 128 the error reached 0.039 on the 2.1.3 pair,
which is too much next to a band edge at 0.85. 256 halves it for 2 KB more per
rule; 512 buys little beyond that.

Trees: `github.com/lwip-tcpip/lwip` at `STABLE-2_2_0_RELEASE`,
`STABLE-2_1_3_RELEASE` and `HEAD`; `github.com/espressif/esp-lwip` at
`fc73c67`; `github.com/DaveGamble/cJSON` at `v1.7.19`.

## What the numbers mean

**A vendor fork and a neighbouring upstream release are not separable by
similarity.** 0.945 (a fork of 2.2.0) sits between 0.984 (a later release of the
same line) and 0.836 (an earlier one). There is no threshold that puts forks on
one side and versions on the other, and any tool that reports a version derived
from a similarity score is guessing.

This is why the engine decides **identity** and **version** separately:

* identity comes from anchors and similarity;
* version comes from anchors, version probes and vendor manifests, never from
  a similarity band on its own;
* a finding whose version is unknown is reported at half its identity
  confidence rather than silently dropped or silently invented.

**Similarity is also the wrong instrument for "was this modified".** On a small
component a one-function vendor patch can still score 1.00, because MinHash
estimates a set overlap and 128 slots cannot resolve a 2% difference. The
exact-copy test is a hash over the reference release's `(path, sha256)` pairs,
recorded in the rule as `fileset_sha256`. It costs nothing -- the digests are
computed anyway -- and it answers exactly the question that similarity cannot.

## Bands

| similarity | identity confidence | band |
| --- | --- | --- |
| >= 0.98 | 0.95 | exact |
| >= 0.85 | 0.90 | strong |
| >= 0.60 | 0.75 | partial |
| >= 0.35 | 0.50 | weak, needs review |
| < 0.35 | -- | no match |

A rule may override any of these in `identity.thresholds` when its component
behaves differently -- a header-only library, for instance, has far fewer
fingerprints and needs a lower floor.

## Cost

Measured on the same trees, 2 cores, `gangmu bench`:

| tree | files | fingerprints | pass 1 | pass 2 | sketch |
| --- | --- | --- | --- | --- | --- |
| lwIP 2.2.0 | 296 | 105,405 | 0.050 s | 0.617 s | 0.013 s |
| esp-lwip | 299 | 108,446 | 0.045 s | 0.635 s | 0.010 s |
| cJSON 1.7.19 | 4 | 4,433 | 0.007 s | 0.036 s | 0.001 s |

**Pass 1** is the walk plus sha256 of every file, and it always runs. **Pass 2**
is tokenising and winnowing, and it runs only when the directory is *not*
byte-identical to the release a rule records — which, for vendored copies, is
the minority case. A whole scan of the demo project takes 1.1 s cold and 0.26 s
with a warm sketch cache.

Three changes got there from an earlier 9.7 s per tree:

* **bottom-k instead of 128-permutation MinHash.** 128 x 105,000 modular
  multiplications was 6.0 s of the 9.7 s. One pass replaces it.
* **rolling k-gram hashes.** Joining 16 tokens and running blake2b per position
  is O(k) work per k-gram; a polynomial rolling hash with a splitmix64 finaliser
  is O(1) after the first.
* **comments skipped by the tokenizer itself**, instead of a byte-at-a-time
  stripper that cost a third of the time on its own.

Plus two that avoid the work entirely: the lazy second pass above, and a disk
cache keyed by `fileset_sha256` — correct by construction, since a tree whose
files all hash the same cannot have a different sketch.

Since 0.6 a scan analyses each file once, whatever directories and rules ask
about it, and caches the result per file. Whole-scan numbers, the rule-count
curve and the CI regression check are in [PERFORMANCE.md](PERFORMANCE.md).

## Reproducing

```bash
gangmu bench lwip-2.2.0 esp-lwip lwip-2.1.3 \
    --include 'src/**/*.c' --include 'src/**/*.h'
```
