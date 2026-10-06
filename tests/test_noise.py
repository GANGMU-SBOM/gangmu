"""Noise reduction: what must not be reported, and what still must.

Found by scanning pristine upstream releases (lwIP, Mbed TLS, nanopb, ...) laid
out the way an SDK lays them out: every one was flagged ``vendor-modified``, and
nanopb's own ``examples/`` produced two phantom components.
"""

from types import SimpleNamespace

from gangmu.fnsig import FunctionSignature, infer_version
from gangmu.match.engine import _is_patched
from gangmu.scan import _is_sample_of_component


def _sig():
    return FunctionSignature.build([
        ("1.0", {1, 2, 3, 10}, {901, 902}),
        ("1.1", {1, 2, 3, 20, 21}, {901, 903}),
        ("1.2", {1, 2, 3, 20, 21, 30}, {901, 903, 904}),
    ])


def _rule(**over):
    return SimpleNamespace(**{"patched": False, "signature": None, **over})


def test_functions_outside_the_signature_do_not_make_a_copy_modified():
    # Every recorded function of 1.1 is present; headers, ports and macros the
    # signature never covered add 500 more. That is a pristine copy.
    present = {1, 2, 3, 20, 21} | set(range(1000, 1500))
    verdict = infer_version(_sig(), present)
    assert verdict.best in ("1.1", "1.2") and verdict.low == "1.1"
    assert verdict.foreign == 500 and verdict.changed == 0
    assert _is_patched(_rule(), None, verdict.best, verdict) is False


def test_an_altered_recorded_function_does_make_it_modified():
    # Function 21 was edited: its old hash is gone and a new one appeared.
    verdict = infer_version(_sig(), {1, 2, 3, 20, 30, 777})
    assert verdict.changed >= 1
    assert _is_patched(_rule(), None, verdict.best, verdict) is True


def test_a_tree_holding_other_releases_functions_but_all_of_its_own_is_not_flagged():
    # 10 belongs to 1.0 only, yet every recorded function of 1.2 is here too.
    verdict = infer_version(_sig(), {1, 2, 3, 10, 20, 21, 30})
    assert verdict.multi_version is True and verdict.changed == 0
    assert _is_patched(_rule(), None, verdict.best, verdict) is False
    assert "not by itself evidence of modification" in verdict.detail


def _finding(directory):
    return SimpleNamespace(directory=directory)


def test_an_example_directory_inside_an_identified_component_is_not_a_component():
    found = [_finding("lib/pb")]
    assert _is_sample_of_component("lib/pb/examples/conan_dependency", found)
    assert _is_sample_of_component("lib/pb/tests/platformio", found)


def test_a_project_s_own_examples_directory_is_still_read():
    found = [_finding("lib/pb")]
    assert not _is_sample_of_component("examples/app", found)
    assert not _is_sample_of_component("lib/other/examples/app", found)
    assert not _is_sample_of_component("lib/pb", found)
    assert not _is_sample_of_component("lib/pb/src", found)


# ------------------------------------------------ one component, one location

from gangmu.scan import _drop_shadowing_ancestors     # noqa: E402


def _claim(directory, name, identity=0.95, version="1.0", version_conf=0.85):
    ver_conf = version_conf if version else 0.0
    return SimpleNamespace(
        directory=directory, upstream_name=name, identity_confidence=identity,
        version=version,
        confidence=round(min(identity, ver_conf), 3) if version
        else round(identity * 0.5, 3))


def test_a_component_found_in_a_subdirectory_does_not_claim_its_parent():
    # FatFs sits in os/dfs/elmfat. Function containment fires at os/ too; that
    # claim must not take os/ away from the kernel that owns it.
    outer = _claim("os", "FatFs", version="0.14b", version_conf=0.88)
    inner = _claim("os/dfs/elmfat", "FatFs", version="0.14b", version_conf=0.85)
    kept = _drop_shadowing_ancestors([outer, inner])
    assert kept == [inner]


def test_a_weaker_nested_match_never_displaces_the_real_root():
    root = _claim("sdk/mbedtls", "Mbed TLS", identity=0.95)
    nested = _claim("sdk/mbedtls/tf-psa-crypto", "Mbed TLS", identity=0.75)
    assert _drop_shadowing_ancestors([root, nested]) == [root, nested]


def test_an_exact_release_at_the_root_is_not_traded_for_an_inner_range():
    root = _claim("ui", "LVGL", version="8.3.11", version_conf=0.98)
    inner = _claim("ui/src", "LVGL", version="8.3.11~8.4.0", version_conf=0.88)
    assert _drop_shadowing_ancestors([root, inner]) == [root, inner]


def test_different_components_in_nested_directories_both_stay():
    a = _claim("os", "RT-Thread")
    b = _claim("os/dfs/elmfat", "FatFs")
    assert _drop_shadowing_ancestors([a, b]) == [a, b]
