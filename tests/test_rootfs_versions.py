"""Versions of the programs and libraries on an embedded Linux root file system: release
strings beside a program's own version format, file names of sstripped libraries, U-Boot."""

import struct
from pathlib import Path

from gangmu.binaries import Embedded, _anchored_versions, _banners, _file_name_release
from gangmu.elf import parse_elf, soname


def _anchored(data: bytes):
    return [(e.name, e.version) for e in _anchored_versions(data, _banners(data))]


def test_a_release_beside_the_programs_version_format_names_it():
    dnsmasq = b"\0Dnsmasq version %s  %s\0" + b"x" * 40 + b"\0002.90\0" + b"\0--version\0"
    assert _anchored(dnsmasq) == [("dnsmasq", "2.90")]


def test_another_identifying_string_will_do():
    # an older dropbear build has "Dropbear SSH" but not the "SSH-2.0-dropbear" ident
    dropbear = b"\x8f\xbf\x00\x1c' 2022.82\0Dropbear SSH multi-purpose\0"
    assert _anchored(dropbear) == [("dropbear", "2022.82")]


def test_the_release_in_a_path_counts():
    pppd = b"\0pppd version %s\0/usr/lib/pppd/2.4.8\0Couldn't load plugin\0"
    assert _anchored(pppd) == [("ppp", "2.4.8")]


def test_a_git_suffix_is_cut_and_other_numbers_are_not_versions():
    iw = b"\0iw version %s\0" + b"\0000.8\0\0001.6\0\0003.2\0" + b"\x00\x40$\x895.9-8fab0c9e\0"
    assert _anchored(iw) == [("iw", "5.9")]


def test_a_development_snapshot_is_the_range_after_the_previous_release():
    wpad = b"\0hostapd v%s\0wpa_supplicant v%s\0\0002.11-devel\0"
    assert sorted(_anchored(wpad)) == [("hostapd", "2.10~2.11"), ("wpa_supplicant", "2.10~2.11")]


def test_two_candidates_name_nothing():
    assert _anchored(b"\0Dnsmasq version %s\0\0002.89\0\0002.90\0") == []


def test_a_release_string_without_its_program_names_nothing():
    assert _anchored(b"\0\0002.90\0\0001.2.4\0\0002022.82\0") == []


def test_a_version_already_known_is_not_read_again():
    data = b"\0musl libc (x86_64)\0\0001.2.4\0"
    assert [(e.name, e.version) for e in _anchored_versions(data, [])] == [("musl", "1.2.4")]
    known = [Embedded("musl", "musl", "1.2.5", "banner")]
    assert _anchored_versions(data, known) == []


def test_u_boot_is_named_by_its_banner_and_by_its_tools():
    found = _banners(b"\0U-Boot 2021.01-OpenWrt-r16 (Jan 11 2021 - 18:11:43 +0000)\0")
    assert [(e.name, e.version) for e in found if e.name == "u-boot"] == [("u-boot", "2021.01")]
    found = _banners(b"\0Compiled with U-Boot 2024.07\n\0")
    assert [(e.name, e.version) for e in found if e.name == "u-boot"] == [("u-boot", "2024.07")]
    assert not [e for e in _banners(b"\0U-Boot %s\0") if e.name == "u-boot"]


# ------------------------------------------------------------ sstripped ELF

def _sstripped(soname_text: bytes, interp: bool = False) -> bytes:
    """A 32-bit little-endian shared object with program headers and no section table,
    as OpenWrt's sstrip leaves every library: PT_LOAD, PT_DYNAMIC, optionally PT_INTERP."""
    base = 0x10000
    phnum = 3 if interp else 2
    ph_at = 52
    dyn_at = ph_at + 32 * phnum
    strtab = b"\0" + soname_text + b"\0/lib/ld-musl-mipsel-sf.so.1\0"
    dyn = struct.pack("<8I", 5, 0, 10, len(strtab), 14, 1, 0, 0)      # STRTAB, STRSZ, SONAME
    str_at = dyn_at + len(dyn)
    dyn = struct.pack("<8I", 5, base + str_at, 10, len(strtab), 14, 1, 0, 0)
    size = str_at + len(strtab)
    header = (b"\x7fELF\x01\x01\x01" + bytes(9)
              + struct.pack("<HHIIIIIHHHHHH", 3, 8, 1, 0, ph_at, 0, 0, 52, 32, phnum, 40, 0, 0))
    phdrs = struct.pack("<8I", 1, 0, base, base, size, size, 5, 0x1000)
    phdrs += struct.pack("<8I", 2, dyn_at, base + dyn_at, base + dyn_at, len(dyn), len(dyn), 6, 4)
    if interp:
        at = str_at + 2 + len(soname_text)
        phdrs += struct.pack("<8I", 3, at, base + at, base + at, 27, 27, 4, 1)
    return header + phdrs + dyn + strtab


def test_the_soname_of_a_library_without_sections_is_read_through_its_segments():
    data = _sstripped(b"libmbedtls.so.21")
    info = parse_elf(data)
    assert info is not None and not info.sections[0].name.startswith(".dyn")
    assert soname(data, info) == "libmbedtls.so.21"
    assert not info.is_executable


def test_a_program_without_sections_is_still_a_program():
    info = parse_elf(_sstripped(b"x", interp=True))
    assert info is not None and info.is_executable


def test_mbed_tls_is_named_by_the_file_name_its_soname_agrees_with():
    data = _sstripped(b"libmbedtls.so.21")
    found = _file_name_release(Path("libmbedtls.so.3.6.5"), data, parse_elf(data), [])
    assert [(e.name, e.version) for e in found] == [("mbedtls", "3.6.5")]
    other = _sstripped(b"libother.so.1")
    assert _file_name_release(Path("libmbedtls.so.3.6.5"), other, parse_elf(other), []) == []
