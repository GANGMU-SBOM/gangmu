"""Every tree walker skips the same never-content directories and none skips
third-party code that is compiled in."""

import pytest

from gangmu import binaries, declared, declared_build, discover, licenses
from gangmu.core.walk import NOT_CONTENT_DIRS

WALKERS = {
    "discover": discover.SKIP_DIRS, "licenses": licenses.SKIP_DIRS,
    "binaries": binaries.SKIP_DIRS, "declared": declared._SKIP_DIRS,
    "declared_build": declared_build._SKIP,
}


@pytest.mark.parametrize("name", sorted(WALKERS))
def test_each_walker_skips_the_shared_never_content_dirs(name):
    assert NOT_CONTENT_DIRS <= set(WALKERS[name])


@pytest.mark.parametrize("name", sorted(WALKERS))
def test_no_walker_skips_esp_idf_managed_components(name):
    # The component manager puts compiled registry dependencies there.
    assert "managed_components" not in WALKERS[name]


def test_binaries_keep_build_outputs_in_view():
    # Firmware images are build outputs; skipping build/ would hide them.
    assert not {"build", "out"} & set(binaries.SKIP_DIRS)
