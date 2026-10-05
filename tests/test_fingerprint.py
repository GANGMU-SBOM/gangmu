import pytest

from gangmu.fingerprint import (Signature, fingerprint_bytes,
                                signature_from_fingerprints, winnow)

A = b"int add(int x, int y) { return x + y; }\nstatic void loop(void) { for (int i = 0; i < 10; i++) { work(i); } }\n" * 30
A_REFORMATTED = b"int add(int x,int y){\n// moved\nreturn x+y;\n}\nstatic void loop(void){for(int i=0;i<10;i++){work(i);}}\n" * 30
B = b"void elsewhere(void) { while (ready()) { flush_queue(); } }\n" * 30


def sig(data):
    return signature_from_fingerprints(fingerprint_bytes(data))


def test_reformatting_is_invisible():
    assert sig(A).similarity(sig(A_REFORMATTED)) == 1.0


def test_unrelated_code_does_not_match():
    assert sig(A).similarity(sig(B)) < 0.05


def test_partial_overlap_lands_in_between():
    mixed = A[: len(A) // 2] + B[: len(B) // 2]
    score = sig(A).similarity(sig(mixed))
    assert 0.1 < score < 0.95


def test_hex_roundtrip_is_exact():
    s = sig(A)
    assert Signature.from_hex(s.to_hex()).values == s.values


def test_signature_is_deterministic_across_runs():
    assert sig(A).values == sig(A).values


def test_mismatched_parameters_are_refused():
    s = sig(A)
    other = signature_from_fingerprints(fingerprint_bytes(A), k=8)
    with pytest.raises(ValueError):
        s.similarity(other)


def test_winnow_picks_at_least_one_per_window():
    hashes = list(range(100))
    selected = winnow(hashes, window=8)
    assert selected and selected <= set(hashes)


def test_empty_input_is_safe():
    assert fingerprint_bytes(b"") == set()
    assert signature_from_fingerprints([]).similarity(sig(A)) == 0.0
