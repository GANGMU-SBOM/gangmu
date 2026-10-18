"""U-Boot legacy images (OpenWrt kernels, router firmware): the payload is read, LZMA included."""

import bz2
import gzip
import lzma
import os
import random
import struct

import pytest

from gangmu.binaries import collect_binaries
from gangmu.core.unpack import expand

BANNER = b" inflate 1.3.1 Copyright 1995-2024 Mark Adler "


def _payload():
    rng = random.Random(7)
    filler = bytes(rng.randrange(97, 123) for _ in range(3000))
    return filler + b"\0" + BANNER + b"\0" + filler[::-1]


def _uimage(body, comp, kind=2, size=None):
    head = struct.pack(">IIIIIIIBBBB32s", 0x27051956, 0, 0, len(body) if size is None else size,
                       0x80008000, 0x80008000, 0, 5, 2, kind, comp, b"Linux-5.15")
    return head + body


def _lzma_alone(raw):
    # U-Boot's encoder marks the uncompressed size as unknown (-1)
    out = bytearray(lzma.compress(raw, format=lzma.FORMAT_ALONE))
    out[5:13] = b"\xff" * 8
    return bytes(out)


CODECS = [
    (0, "none", lambda b: b),
    (1, "gzip", gzip.compress),
    (2, "bzip2", bz2.compress),
    (3, "lzma", _lzma_alone),
]


@pytest.mark.parametrize("comp,name,pack", CODECS)
def test_payload_of_each_supported_compression_is_a_layer(comp, name, pack):
    image = _uimage(pack(_payload()), comp)
    layers = expand(image, ".bin")
    assert any(BANNER in layer.data and layer.label for layer in layers), [l.label for l in layers]


def test_lzma_payload_is_found_without_a_magic_number():
    labels = [l.label for l in expand(_uimage(_lzma_alone(_payload()), 3), ".bin")]
    assert any(l.startswith("uimage-lzma@0x0") for l in labels)


def test_image_after_a_bootloader_is_found_at_its_offset():
    image = b"\xff" * 0x20000 + _uimage(_lzma_alone(_payload()), 3)
    labels = [l.label for l in expand(image, ".bin")]
    assert "uimage-lzma@0x20000" in labels


@pytest.mark.parametrize("comp,kind,size", [(9, 2, None), (3, 99, None), (3, 2, 10**6), (3, 2, 5)])
def test_inconsistent_headers_are_left_alone(comp, kind, size):
    image = _uimage(_lzma_alone(_payload()), comp, kind, size)
    assert [l.label for l in expand(image, ".bin")] == [""]


def test_a_corrupt_lzma_payload_is_not_an_error():
    body = _lzma_alone(_payload())
    image = _uimage(body[:200] + os.urandom(100) + body[300:], 3)
    assert expand(image, ".bin")[0].label == ""


def test_scan_reports_the_library_inside_a_compressed_kernel(tmp_path):
    (tmp_path / "uImage.bin").write_bytes(_uimage(_lzma_alone(_payload()), 3))
    (blob,) = collect_binaries(tmp_path)
    assert blob.layers > 1
    assert any(e.name == "zlib" and e.version == "1.3.1" for e in blob.embedded)
