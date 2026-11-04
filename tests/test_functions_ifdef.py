"""Function extraction through #if/#else branches that each open the same block.

Counting every brace in every branch saw two `{` for one `}` in code like SQLite's
winRead, and lost every function after it in the file. The fix applies the change of
alternatives once; everything else must extract exactly as before.
"""

from gangmu.functions import _brace_levels, extract_functions
from gangmu.normalize import tokenize


def names(src: bytes):
    return [f.name for f in extract_functions(src, min_tokens=1)]


ALTERNATIVES = b"""
int first(int a) {
#if WINCE
  if (seek(a)) { return 1; }
  while (!read_a(a)) {
#else
  while (!read_b(a)) {
#endif
    a++;
  }
  return a;
}
int after(int b) { return b + 1; }
"""


def test_alternatives_that_each_open_a_block_count_once():
    assert names(ALTERNATIVES) == ["first", "after"]


SPLIT = b"""
int split(int n) {
#ifdef SE050
  n = 0;
#else
  for (int i = 0; i < n; i++) {
#endif
    n--;
#ifndef SE050
  }
#endif
  return n;
}
int next(int m) { return m; }
"""


def test_a_block_opened_in_one_conditional_and_closed_in_another_keeps_the_plain_count():
    # wolfSSL's test.c: summing the branches is right here, applying "once" would end
    # `split` at the `}` inside #ifndef.
    assert names(SPLIT) == ["split", "next"]


CLOSES = b"""
static int wait(int t) {
  do {
    t--;
#if RETRY
  } while (t && retry());
#else
  } while (t);
#endif
  return t;
}
static int other(void) { return 0; }
"""


def test_alternatives_that_each_close_a_block_count_once():
    # NXP's fsl_lpi2c.c and lwIP's sockets.c: the plain count ended `wait` early.
    found = extract_functions(CLOSES, min_tokens=1)
    assert [f.name for f in found] == ["wait", "other"]
    toks = tokenize(CLOSES)
    end = found[0].span[1]
    assert toks[end - 1] == b"}" and toks[end - 2] == b";" and toks[end - 3] == b"t"


BOTH_DEFINE = b"""
#ifdef _WIN32
int f(void) { return 1; }
#else
int f(void) { return 2; }
#endif
int g(void) { return 3; }
"""


def test_a_function_defined_in_each_branch_is_found_in_each():
    assert names(BOTH_DEFINE) == ["f", "f", "g"]


def test_code_without_unequal_branches_gets_the_plain_count():
    src = b"int a(void){ if (x) { y(); } return 0; }\n#if A\nint b(void){return 1;}\n#endif\n"
    toks = tokenize(src)
    plain, depth = [], 0
    for t in toks:
        plain.append(depth)
        depth += (t == b"{") - (t == b"}")
    plain.append(depth)
    assert _brace_levels(toks) == plain
