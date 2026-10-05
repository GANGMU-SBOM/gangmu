"""Containers are unwrapped so banners inside them are read."""

import bz2
import gzip
import io
import lzma
import struct
import zipfile
import zlib

from gangmu.binaries import collect_binaries
from gangmu.unpack import expand, intel_hex, srec, uf2

PAYLOAD = b"\x00libopus 1.3-fixed\x00" + b"filler text " * 40 + b"\x00Xiph.Org libVorbis 1.3.7\x00"


def _ihex(image: bytes, base=0x08000000) -> bytes:
    def rec(addr, kind, body):
        raw = bytes([len(body), addr >> 8 & 0xFF, addr & 0xFF, kind]) + body
        return b":" + (raw + bytes([(-sum(raw)) & 0xFF])).hex().upper().encode()
    lines = [rec(0, 4, (base >> 16).to_bytes(2, "big"))]
    for i in range(0, len(image), 16):
        lines.append(rec(i, 0, image[i:i + 16]))
    lines.append(rec(0, 1, b""))
    return b"\n".join(lines) + b"\n"


def _srec(image: bytes) -> bytes:
    out = []
    for i in range(0, len(image), 16):
        body = image[i:i + 16]
        raw = bytes([len(body) + 5]) + (0x08000000 + i).to_bytes(4, "big") + body
        out.append(b"S3" + (raw + bytes([(~sum(raw)) & 0xFF])).hex().upper().encode())
    return b"\n".join(out) + b"\n"


def _uf2(image: bytes) -> bytes:
    blocks = [image[i:i + 256] for i in range(0, len(image), 256)]
    out = b""
    for n, body in enumerate(blocks):
        out += struct.pack("<8I", 0x0A324655, 0x9E5D5157, 0, 0x10000000 + n * 256,
                           len(body), n, len(blocks), 0xE48BFF56)
        out += body.ljust(476, b"\0") + struct.pack("<I", 0x0AB16F30)
    return out


def test_intel_hex_srec_and_uf2_give_back_the_flat_image():
    assert intel_hex(_ihex(PAYLOAD)) == PAYLOAD
    assert srec(_srec(PAYLOAD)) == PAYLOAD
    assert uf2(_uf2(PAYLOAD)) == PAYLOAD


def test_a_corrupt_checksum_is_refused_not_guessed():
    bad = _ihex(PAYLOAD).replace(b":10", b":11", 1)
    assert intel_hex(bad) is None and uf2(b"x" * 512) is None


def test_compressed_streams_inside_an_image_are_unwrapped():
    parts = [PAYLOAD + bytes([i]) * 300 for i in range(4)]    # distinct, or they are deduplicated
    blob = b"\x00" * 100 + gzip.compress(parts[0]) + b"\x00" * 50 + lzma.compress(parts[1]) \
        + bz2.compress(parts[2]) + zlib.compress(parts[3])
    layers = expand(blob, ".bin")
    assert [layer.label.split("@")[0] for layer in layers] == ["", "gzip", "xz", "bzip2", "zlib"]
    assert [layer.data for layer in layers[1:]] == parts


def test_nested_containers_are_followed_to_a_bounded_depth():
    import random
    noise = random.Random(1).randbytes(4000) + PAYLOAD      # does not shrink, so each layer stays big
    inner = gzip.compress(gzip.compress(gzip.compress(gzip.compress(noise))))
    layers = expand(inner, ".bin")
    assert max(layer.label.count(">") for layer in layers) == 2   # MAX_DEPTH (3) unwraps, no more
    assert len({layer.data for layer in layers}) == len(layers)   # same bytes never scanned twice


def test_a_decompression_bomb_is_cut_off():
    bomb = gzip.compress(b"\0" * (80 * 1024 * 1024))          # 80 MiB out of ~80 KiB in
    layers = expand(bomb, ".bin")
    assert max(len(layer.data) for layer in layers) <= 64 * 1024 * 1024


def test_zip_members_are_read():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("app.bin", PAYLOAD)
    assert any(layer.label == "zip:app.bin" for layer in expand(buf.getvalue(), ".bin"))


def test_banners_inside_compressed_and_hex_images_are_found(tmp_path):
    (tmp_path / "fw").mkdir()
    (tmp_path / "fw" / "ota.bin").write_bytes(b"\x00" * 64 + gzip.compress(PAYLOAD))
    (tmp_path / "fw" / "app.hex").write_bytes(_ihex(PAYLOAD))
    (tmp_path / "fw" / "app.uf2").write_bytes(_uf2(PAYLOAD))
    blobs = {b.path: b for b in collect_binaries(tmp_path)}
    assert set(blobs) == {"fw/ota.bin", "fw/app.hex", "fw/app.uf2"}
    for blob in blobs.values():
        assert {(e.name, e.version) for e in blob.embedded} == {("opus", "1.3"),
                                                                ("libvorbis", "1.3.7")}
    assert blobs["fw/ota.bin"].layers == 2
    assert "[inside gzip@0x40]" in blobs["fw/ota.bin"].embedded[0].banner
    assert blobs["fw/app.hex"].linked is None
