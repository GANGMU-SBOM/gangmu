"""What kind of ARM image this is, and where a raw Cortex-M image starts and is linked.

Real firmware, built with clang and lld at three load addresses (tests/thumb_images.py), plus
hand-built ELF sections for what a real toolchain would not emit.
"""

import os
import random
import struct

import pytest

import thumb_images as fw
from pebuild import elf_with_sections

from gangmu import disasm
from gangmu.cli import main
from gangmu.elf import SHT_ARM_ATTRIBUTES, arm_attributes, parse_elf

pytestmark = pytest.mark.skipif(not disasm.available(), reason="capstone not installed")

MCUBOOT_MAGIC = 0x96F3B83D


def _attributes(cpu_arch, profile, arm_isa, thumb_isa, cpu_name=b"7-M"):
    """A .ARM.attributes section as GNU ld and LLVM write it (ARM IHI 0045)."""
    body = b"\x05" + cpu_name + b"\0" + bytes([6, cpu_arch, 7, ord(profile), 8, arm_isa,
                                               9, thumb_isa, 18, 4])   # 18: ABI_PCS_wchar_t
    scope = b"\x01" + struct.pack("<I", 5 + len(body)) + body
    vendor = b"aeabi\0"
    return b"A" + struct.pack("<I", 4 + len(vendor) + len(scope)) + vendor + scope


def _elf(attrs, entry):
    sections = [(".text", 1, b"\0" * 8)]
    if attrs is not None:
        sections.append((".ARM.attributes", SHT_ARM_ATTRIBUTES, attrs))
    return elf_with_sections(sections, entry=entry)


# ------------------------------------------------------------ ARM or Thumb

def test_build_attributes_are_read_as_the_toolchain_wrote_them():
    section = _attributes(10, "M", 0, 2)
    assert arm_attributes(section) == {6: 10, 7: ord("M"), 8: 0, 9: 2}
    assert parse_elf(_elf(section, 0)).arm_attributes == {6: 10, 7: 77, 8: 0, 9: 2}


@pytest.mark.parametrize("junk", [b"", b"B", b"A", b"A\0\0\0\0", b"A" + b"\xff" * 40,
                                  _attributes(10, "M", 0, 2)[:-9]])
def test_malformed_build_attributes_give_nothing_instead_of_an_error(junk):
    assert isinstance(arm_attributes(junk), dict)
    assert parse_elf(_elf(junk, 0)) is not None


@pytest.mark.parametrize("attrs, entry, expected", [
    (_attributes(10, "M", 0, 2), 0x0, "thumb"),            # Cortex-M3, no ENTRY in the script
    (_attributes(13, "M", 0, 2), 0x08000100, "thumb"),     # v7E-M, entry's mode bit missing
    (_attributes(16, "M", 0, 2), 0x0, "thumb"),            # v8-M baseline
    (_attributes(11, "M", 0, 1), 0x0, "thumb"),            # v6-M
    (_attributes(10, "A", 0, 2), 0x8000, "thumb"),         # no ARM instruction used at all
    (_attributes(10, "A", 1, 2), 0x8000, "arm"),           # ARM and Thumb code, ARM entry
    (_attributes(10, "A", 1, 2), 0x8001, "thumb"),         # the entry's mode bit still decides
    (None, 0x8000, "arm"),                                 # nothing to go on: as before
    (None, 0x8001, "thumb"),
])
def test_the_mode_of_an_arm_elf_comes_from_what_it_was_built_for(attrs, entry, expected):
    info = parse_elf(_elf(attrs, entry))
    assert disasm.arch_of_elf(info) == expected


def test_a_stripped_firmware_linked_without_entry_is_decoded_as_thumb():
    # e_entry is 0 here, which used to read as "ARM state" and decode nonsense
    info = parse_elf(fw.NOENTRY_ELF)
    assert info.entry == 0 and info.arm_attributes[7] == ord("M")
    rec = disasm.recover_elf(fw.NOENTRY_ELF, info)
    assert rec.arch == "thumb"
    found = {f.address & ~1 for f in rec.functions}
    assert set(fw.FLASH_FUNCTIONS) <= found


# ------------------------------------------------------------ raw images

@pytest.mark.parametrize("image, base, functions", [
    (fw.FLASH_BIN, fw.FLASH_BASE, fw.FLASH_FUNCTIONS),
    (fw.APP_BIN, fw.APP_BASE, fw.APP_FUNCTIONS),            # an application after a bootloader
    (fw.SLOT_BIN, fw.SLOT_BASE, fw.SLOT_FUNCTIONS),
])
def test_an_image_is_based_from_its_vector_table_and_its_strings(image, base, functions):
    layout = disasm.cortex_m_layout(image)
    assert (layout.offset, layout.base) == (0, base)
    assert disasm.cortex_m_base(image) == base
    rec = disasm.recover_raw(image)
    assert rec.arch == "thumb"
    assert set(functions) <= {f.address & ~1 for f in rec.functions}


def test_the_application_image_used_to_be_called_unknown():
    # linked at 0x08008000, the handlers lie in no 1 MB window the image reaches
    rec = disasm.recover_raw(fw.APP_BIN)
    assert rec.functions and rec.functions[0].address >= fw.APP_BASE


def _mcuboot(payload, load_addr=0, header=0x200, trailer=b"\xff" * 80):
    head = struct.pack("<IIHHI", MCUBOOT_MAGIC, load_addr, header, 0, len(payload))
    return head + b"\xff" * (header - len(head)) + payload + trailer


def test_an_mcuboot_header_is_skipped_and_its_trailer_left_out():
    image = _mcuboot(fw.SLOT_BIN)
    layout = disasm.cortex_m_layout(image)
    assert (layout.offset, layout.base, layout.length) == (0x200, fw.SLOT_BASE, len(fw.SLOT_BIN))
    rec = disasm.recover_raw(image)
    assert "MCUboot" in rec.note
    found = {f.address & ~1 for f in rec.functions}
    assert set(fw.SLOT_FUNCTIONS) <= found
    assert max(found) < fw.SLOT_BASE + len(fw.SLOT_BIN)          # nothing from the trailer


def test_an_mcuboot_load_address_is_the_base_when_it_gives_one():
    image = _mcuboot(fw.FLASH_BIN, load_addr=fw.FLASH_BASE)
    assert disasm.cortex_m_layout(image).base == fw.FLASH_BASE


@pytest.mark.parametrize("prefix", [0x200, 0x400, 0x1000, 0x2000])
def test_a_vector_table_after_an_unknown_wrapper_is_found_at_an_aligned_offset(prefix):
    image = b"\xff" * prefix + fw.SLOT_BIN
    layout = disasm.cortex_m_layout(image)
    assert (layout.offset, layout.base) == (prefix, fw.SLOT_BASE)
    assert "vector table at file offset" in layout.how


def test_an_offset_the_search_does_not_try_is_given_by_the_user():
    image = b"\xff" * 0x4F0 + fw.SLOT_BIN
    assert disasm.cortex_m_layout(image) is None
    assert disasm.recover_raw(image).functions == []
    rec = disasm.recover_raw(image, offset=0x4F0)
    assert set(fw.SLOT_FUNCTIONS) <= {f.address & ~1 for f in rec.functions}


def test_an_image_with_no_strings_to_place_it_by_is_left_unknown_not_guessed():
    # a vector table and nothing else: the base cannot be told from the handlers alone
    table = struct.pack("<16I", 0x20010000, *[(0x08008100 + 4 * i) | 1 for i in range(15)])
    rec = disasm.recover_raw(table + b"\0" * 0x400)
    assert rec.functions == [] and "--offset" in rec.note


def test_nothing_that_is_not_a_vector_table_is_called_one():
    rng = random.Random(3)
    blobs = [b"\0" * 4096, b"\xff" * 4096, b"text " * 900] + [
        bytes(rng.getrandbits(8) for _ in range(rng.choice([512, 4096, 16384])))
        for _ in range(300)] + [os.urandom(8192) for _ in range(100)]
    assert [i for i, blob in enumerate(blobs) if disasm.cortex_m_layout(blob)] == []


def test_the_binary_functions_command_takes_an_offset(tmp_path, capsys):
    path = tmp_path / "update.bin"
    path.write_bytes(b"\xff" * 0x4F0 + fw.SLOT_BIN)
    assert main(["binary-functions", str(path)]) == 1
    capsys.readouterr()
    assert main(["binary-functions", "--offset", "0x4F0", str(path)]) == 0
    assert "# thumb: " in capsys.readouterr().out
    path.write_bytes(_mcuboot(fw.APP_BIN))     # a different base, same command
    assert main(["binary-functions", str(path)]) == 0
    assert "MCUboot image header" in capsys.readouterr().out
