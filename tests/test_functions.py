"""Function extraction and multi-version signatures.

This is the part the research literature is about, so the tests are about the
properties the papers claim rather than about implementation details.
"""

import pytest

from gangmu.fnsig import FunctionSignature, infer_version
from gangmu.functions import extract_functions, function_hashes

SAMPLE = b"""
/* a header comment */
static int helper(int a, int b) { return a + b + a * b; }

int lwip_init(void)
{
    if (ready) { start(); }
    while (pending) { pump(); }
    return 0;
}

int declared_only(void);
struct thing { int x; };
typedef int (*callback)(void);
void with_attribute(void) __attribute__((weak));
int k_and_r(a, b) int a; int b; { return a - b + a * b; }
"""


def _names(data):
    return [f.name for f in extract_functions(data)]


def test_definitions_are_found_and_declarations_are_not():
    names = _names(SAMPLE)
    assert "helper" in names and "lwip_init" in names
    assert "declared_only" not in names
    assert "with_attribute" not in names


def test_control_statements_are_not_mistaken_for_functions():
    assert "if" not in _names(SAMPLE) and "while" not in _names(SAMPLE)


def test_kr_style_definitions_are_found():
    """Legacy embedded code still uses them, and missing them loses functions."""
    assert "k_and_r" in _names(SAMPLE)


def test_a_struct_definition_is_not_a_function():
    assert "thing" not in _names(SAMPLE)


def test_reformatting_does_not_change_a_function_hash():
    a = b"int f(int x) { int y = x + 1; while (y > 0) { y--; } return y; }"
    b = b"int f(int x)\n{\n\tint y = x + 1;\n\twhile (y > 0) {\n\t\ty--;\n\t}\n\treturn y;\n}"
    assert function_hashes(a) == function_hashes(b)


def test_renaming_breaks_the_exact_hash_but_not_the_abstract_one():
    """The whole point of the second abstraction level."""
    body = (b"int compute(const unsigned char *data, int length) { int total = 0; "
            b"int index; for (index = 0; index < length; index++) { "
            b"total += data[index]; if (total > 255) { total -= 255; } } "
            b"return total; }")
    renamed = body.replace(b"compute", b"vnd_compute").replace(b"total", b"acc")
    a = extract_functions(body)[0]
    b = extract_functions(renamed)[0]
    assert a.hash != b.hash
    assert a.abstract_hash is not None and a.abstract_hash == b.abstract_hash


def test_short_bodies_get_no_abstract_hash():
    """Abstraction destroys names, so a three-line function would collide."""
    tiny = extract_functions(b"int f(void) { return 1 + 2; }")[0]
    assert tiny.abstract_hash is None


def test_unrelated_functions_do_not_collide_when_abstracted():
    a = extract_functions(
        b"int f(int x) { int s = 0; for (int i = 0; i < x; i++) { s += i * 3; "
        b"if (s > 100) { s = 0; } } return s; }")[0]
    b = extract_functions(
        b"void g(char *p) { while (*p) { if (*p == 32) { *p = 95; } p++; } "
        b"flush(p); log_it(p); }")[0]
    assert a.abstract_hash != b.abstract_hash


# ------------------------------------------------------- signatures

def _sig():
    return FunctionSignature.build([
        ("1.0", {1, 2, 3, 10}, {901, 902}),
        ("1.1", {1, 2, 3, 20, 21}, {901, 903}),
        ("1.2", {1, 2, 3, 20, 21, 30}, {901, 903, 904}),
    ])


def test_a_signature_round_trips_through_bytes():
    sig = _sig()
    again = FunctionSignature.from_bytes(sig.to_bytes())
    assert again.hashes == sig.hashes
    assert again.bitmaps == sig.bitmaps
    assert again.abstract_hashes == sig.abstract_hashes


def test_functions_in_every_version_carry_no_version_information():
    assert _sig().discriminating() == {10, 20, 21, 30}


def test_a_pure_version_is_identified_exactly():
    verdict = infer_version(_sig(), {1, 2, 3, 20, 21})
    assert verdict.best == "1.1"


def test_a_tree_mixing_versions_is_flagged_as_such():
    """TIVER's observation: a fork carries functions from several releases."""
    verdict = infer_version(_sig(), {1, 2, 3, 10, 20, 21})
    assert verdict.multi_version is True
    assert "mixes releases" in verdict.detail


def test_functions_no_version_explains_are_counted():
    verdict = infer_version(_sig(), {1, 2, 3, 20, 21, 999})
    assert verdict.foreign == 1
    assert "match no recorded version" in verdict.detail


def test_only_common_code_cannot_narrow_the_version():
    verdict = infer_version(_sig(), {1, 2, 3})
    assert verdict.best is None
    assert "cannot be narrowed" in verdict.detail


def test_version_hashes_are_reconstructed_from_the_bitmaps():
    sig = _sig()
    assert sig.version_hashes(0) == {1, 2, 3, 10}
    assert sig.version_abstract_hashes(0) == {901, 902}


def test_segmentation_removes_borrowed_code_from_application_code():
    sig = _sig()
    before = len(sig.application_hashes)
    marked = sig.segment({1, 2})
    assert marked == 2
    assert len(sig.application_hashes) == before - 2
    assert 1 not in sig.application_hashes


def test_segmentation_also_holds_at_the_abstract_level():
    """Two rules for an upstream and its fork share bodies. Once identifiers
    are collapsed, the renaming fallback must not count the shared ones."""
    sig = FunctionSignature.build([("1.0", {1, 2, 3}, {10, 20, 30})])
    assert sig.version_abstract_hashes(0) == {10, 20, 30}
    sig.segment_abstract({20, 30, 99})
    assert sig.version_abstract_hashes(0) == {10}


def test_extern_c_wrapper_is_transparent():
    wrapped = b"""
#ifdef __cplusplus
extern "C" {
#endif
static int helper(int a, int b) { return a + b + a * b; }
int lib_init(void)
{
    if (ready) { start(); }
    return helper(1, 2);
}
#ifdef __cplusplus
}
#endif
"""
    names = {f.name for f in extract_functions(wrapped)}
    assert names == {"helper", "lib_init"}
