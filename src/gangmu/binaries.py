"""Prebuilt binaries: say what is there instead of staying silent.

Chinese SDKs ship their Wi-Fi, BLE, RF and codec stacks as ``.a`` archives with no
source. Fingerprinting cannot see them, and a scan that says nothing about them
reads as "nothing here". This module does two modest things:

* inventories every prebuilt archive or shared library (path, SHA-256, size, and
  whether the link map shows it was linked), so the SBOM names the code it cannot
  analyse;
* also reads firmware images (``.elf``, ``.axf``, ``.bin``), where no source or build is
  at hand: a stripped image still carries its banner strings, though not its symbols;
* reads version banners out of the bytes. Open-source libraries usually leave one
  (``libopus 1.3-fixed``, ``Xiph.Org libVorbis 1.3.7``, ``speex-1.2.1``), and a
  vendor's own components often carry one too (Bouffalo's
  ``component_version_fhost_1.7.10``).

A banner is evidence that a library is *inside* the binary, not proof of a clean
upstream copy; the finding is reported at modest confidence and marked as read
from a string.
"""

from __future__ import annotations

import hashlib
import os
import re
import zlib
from urllib.parse import quote
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Set

from . import disasm
from .carve import carve, mask
from .binmeta import CARGO_SECTION, GoBuildInfo, cargo_auditable, go_buildinfo
from .dotnet import is_framework, parse_dotnet, read_deps_json
from .elf import ElfInfo, build_id, package_note, parse_elf, soname
from .pe import PeInfo, parse_pe
from .core.unpack import IMAGE_SUFFIXES as UNPACK_SUFFIXES, Layer, expand
from .core.walk import NOT_CONTENT_DIRS

IMAGE_SUFFIXES = {".elf", ".axf", ".bin"} | UNPACK_SUFFIXES   # linked products, not link inputs:
#                                      a link map has nothing to say about them
# Windows executables and libraries. An .exe is a linked product like a firmware image (a link
# map names link inputs, never products); a .dll/.sys/.ocx/.pyd is a shared library like a .so.
PE_PRODUCT_SUFFIXES = {".exe"}
PE_LIBRARY_SUFFIXES = {".dll", ".sys", ".ocx", ".pyd"}
PE_SUFFIXES = PE_PRODUCT_SUFFIXES | PE_LIBRARY_SUFFIXES
PRODUCT_SUFFIXES = IMAGE_SUFFIXES | PE_PRODUCT_SUFFIXES
BLOB_SUFFIXES = {".a", ".lib", ".so"} | IMAGE_SUFFIXES | PE_SUFFIXES
SKIP_DIRS = set(NOT_CONTENT_DIRS)
# Directories that hold test inputs, not shipped products. A ``.bin`` or ``.elf`` in one of
# them (lwIP's fuzz inputs are ``.bin`` packets) is fixture data, so it is not inventoried as
# a firmware image. Libraries (``.a``, ``.lib``, ``.so``) are still listed wherever they are.
FIXTURE_DIRS = {"test", "tests", "testdata", "test_data", "fuzz", "fixtures"}
MAX_BANNER_BYTES = 64 * 1024 * 1024
MAX_EMBED_DEPTH = 2          # a binary inside a binary inside a binary, and no further
# An archive of object files: its members are ELF objects, not libraries that were shipped.
NO_CARVE_SUFFIXES = {".a", ".lib"}

# (name, display name, banner pattern). The version is group 1. Each pattern is a
# string the upstream project itself compiles in, not a guess from a file name.
BANNERS = (
    # Upstream compiles in "speex-1.2.1"; Bouffalo's wrapper stamps "speex_v1.2.1" (its
    # own component version, not the upstream release), so only the hyphen form counts.
    ("speex", "Speex", rb"speex-(\d+\.\d+\.\d+)"),
    ("libvorbis", "libvorbis", rb"Xiph\.Org libVorbis (\d+\.\d+\.\d+)"),
    ("opus", "Opus", rb"libopus (\d+\.\d+(?:\.\d+)?)"),
    ("openssl", "OpenSSL", rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)"),
    ("mbedtls", "Mbed TLS", rb"[Mm]bed ?TLS (\d+\.\d+\.\d+)"),
    ("wolfssl", "wolfSSL", rb"wolfSSL (?:Version )?(\d+\.\d+\.\d+)"),
    # "inflate 1.3 Copyright": a release is written 1.3 as well as 1.2.13 and 1.2.11.1
    ("zlib", "zlib", rb"(?:deflate|inflate) (\d+\.\d+(?:\.\d+){0,2}) Copyright"),
    ("libpng", "libpng", rb"libpng version (\d+\.\d+\.\d+)"),
    ("curl", "curl", rb"libcurl/(\d+\.\d+\.\d+)"),
    ("sqlite", "SQLite", rb"SQLite version (\d+\.\d+\.\d+)"),
    ("freertos", "FreeRTOS-Kernel", rb"FreeRTOS (?:Kernel )?V(\d+\.\d+\.\d+)"),
    # What a Linux userland carries (read off Ubuntu 24.04's libraries): XML_ExpatVersion()'s
    # string, the $LuaVersion$ copyright line (5.1 spells it $Lua$), libjpeg-turbo's version
    # string, and the banner BusyBox prints.
    ("expat", "Expat", rb"(?<![A-Za-z0-9_])expat_(\d+\.\d+\.\d+)(?![\d.])"),
    ("lua", "Lua", rb"\$Lua(?:Version)?: Lua (\d+\.\d+\.\d+)"),
    ("libjpeg-turbo", "libjpeg-turbo", rb"libjpeg-turbo version (\d+\.\d+\.\d+)"),
    ("busybox", "BusyBox", rb"BusyBox v(\d+\.\d+\.\d+(?:\.\d+)?)"),
)

# Libraries that leave no banner but export a recognisable API. Names are matched as whole
# NUL-delimited strings (the symbol table), so a short name inside a longer one does not
# count and no ELF parser is needed. At least ``need`` of them must be present: an API
# says the library is inside, never which release (those sets barely change).
# (name, display name, need, symbols)
SYMBOLS = (
    ("libogg", "libogg", 14, (
        "ogg_stream_init", "ogg_stream_clear", "ogg_stream_packetin", "ogg_stream_pageout",
        "ogg_stream_pagein", "ogg_stream_packetout", "ogg_stream_flush", "ogg_sync_init",
        "ogg_sync_buffer", "ogg_sync_wrote", "ogg_sync_pageout", "ogg_sync_pageseek",
        "ogg_page_serialno", "ogg_page_granulepos", "ogg_page_checksum_set",
        "oggpack_writeinit", "oggpack_read", "oggpack_write", "oggpackB_read")),
    ("speexdsp", "SpeexDSP", 10, (
        "speex_echo_state_init", "speex_echo_cancellation", "speex_echo_capture",
        "speex_echo_playback", "speex_preprocess_state_init", "speex_preprocess_run",
        "speex_resampler_init", "speex_resampler_process_float", "jitter_buffer_init",
        "jitter_buffer_put", "jitter_buffer_get", "speex_decorrelate_new",
        "speex_buffer_init", "kiss_fft_alloc", "kiss_fftr_alloc", "filterbank_new")),
    ("sonic", "Sonic", 12, (
        "sonicCreateStream", "sonicDestroyStream", "sonicFlushStream", "sonicSetSpeed",
        "sonicSetPitch", "sonicSetRate", "sonicSetVolume", "sonicSetChordPitch",
        "sonicWriteShortToStream", "sonicReadShortFromStream", "sonicWriteFloatToStream",
        "sonicReadFloatFromStream", "sonicSamplesAvailable", "sonicChangeShortSpeed")),
    ("pvmp3dec", "PacketVideo MP3 decoder", 6, (
        "pvmp3_InitDecoder", "pvmp3_framedecoder", "pvmp3_decode_header",
        "pvmp3_alias_reduction", "pvmp3_dct_9", "pvmp3_dct_16", "pvmp3_mdct_18",
        "pvmp3_decode_huff_cw_tab0", "pvmp3_poly_phase_synthesis", "pvmp3_stereo_proc")),
    ("pvmp4audiodecoder", "PacketVideo AAC decoder", 5, (
        "PVMP4AudioDecodeFrame", "PVMP4AudioDecoderConfig", "PVMP4AudioDecoderInitLibrary",
        "PVMP4AudioDecoderGetMemRequirements", "PVMP4AudioDecoderResetBuffer",
        "PVMP4SetAudioConfig", "PVMP4AudioDecoderDisableAacPlus")),
    ("opencore-amrnb", "OpenCORE AMR-NB", 6, (
        "GSMInitDecode", "GSMFrameDecode", "GSMDecodeFrameExit", "AMRDecode",
        "Decoder_amr_init", "Decoder_amr", "Speech_Decode_Frame_reset", "Bgn_scd",
        "Post_Filter", "D_plsf_3", "Lsp_Az")),
    # the symbols every libplctag 2.6 build exports, on all of ELF, Mach-O and PE and all
    # four CPU families of libplctag.NativeImport 1.0.41 (a managed wrapper only *declares*
    # these, see ``_banners``)
    ("libplctag", "libplctag", 24, (
        "plc_tag_create_ex", "plc_tag_destroy", "plc_tag_read", "plc_tag_write", "plc_tag_status",
        "plc_tag_shutdown", "plc_tag_get_size", "plc_tag_set_raw_bytes", "plc_tag_get_raw_bytes",
        "plc_tag_get_bit", "plc_tag_set_bit", "plc_tag_get_int8", "plc_tag_get_uint8",
        "plc_tag_get_int16", "plc_tag_get_uint16", "plc_tag_get_int32", "plc_tag_get_uint32",
        "plc_tag_get_int64", "plc_tag_get_uint64", "plc_tag_get_float32", "plc_tag_set_float32",
        "plc_tag_get_float64", "plc_tag_set_float64", "plc_tag_get_string",
        "plc_tag_set_string", "plc_tag_get_string_length", "plc_tag_get_string_capacity",
        "plc_tag_get_int_attribute", "plc_tag_set_int_attribute", "plc_tag_unlock",
        "plc_tag_register_callback", "plc_tag_unregister_callback",
        "plc_tag_unregister_logger", "plc_tag_get_byte_array_attribute")),
)
# What a library's shared-object name says about the release series, shown beside an API match.
# A SONAME is major.minor, not a release, so it is evidence text and never a version.
_SERIES = {"libplctag": re.compile(rb"\0libplctag(?:\.so\.|\.)(\d+\.\d+)(?:\.dylib)?\0")}
_SYMBOL_SETS = tuple((n, d, need, tuple(f"\0{x}\0".encode() for x in names))
                     for n, d, need, names in SYMBOLS)
_COMPILED = tuple((n, d, re.compile(p)) for n, d, p in BANNERS)
_VENDOR_COMPONENT = re.compile(rb"component_version_([A-Za-z0-9]+(?:_[A-Za-z]\w*)*?)_(\d+\.\d+\.\d+)")
_TOOLCHAIN = re.compile(rb"GCC: \(([^)\x00]{3,80})\) (\d+\.\d+\.\d+)")


@dataclass
class Embedded:
    """A library or vendor component whose banner was found inside a binary."""

    name: str
    display_name: str
    version: str
    banner: str
    vendor_component: bool = False      # a vendor's own component, no upstream
    method: str = "banner"      # banner | symbols | strings | functions | go-buildinfo |
    #                             cargo-auditable | deps-json | version-info | imports |
    #                             dotnet-reference | dotnet-assembly | package-note | file-name
    # version "" means the library is there (API symbols) but no release can be named
    purl: Optional[str] = None          # set by readers of a dependency list (Go, Rust)
    cpe: Optional[str] = None
    modified: bool = False              # a replace directive says the code is not that release


@dataclass
class Binary:
    path: str                           # relative to the scan root
    sha256: str
    size: int
    kind: str              # archive | shared-library | import-library | firmware-image
    linked: Optional[bool] = None       # None: no link map to ask
    toolchain: Optional[str] = None
    embedded: List[Embedded] = field(default_factory=list)
    stripped: Optional[bool] = None     # ELF only: True when there is no symbol table
    symbols: Optional[int] = None       # ELF only: named functions and objects defined
    functions: Optional[int] = None     # recovered function count (needs capstone)
    arch: Optional[str] = None          # architecture the disassembly used
    function_source: Optional[str] = None   # symbols | disassembly
    function_note: Optional[str] = None     # why no functions were recovered
    layers: int = 1                     # the file plus every container unwrapped from it
    product: Optional[dict] = None      # what the file says it is: version resource, main module
    pdb: Optional[str] = None           # PE only: the PDB path in the CodeView record
    signed: Optional[bool] = None       # PE only: an Authenticode signature is attached
    runtime: Optional[str] = None       # "go go1.24.7", "rust", "dotnet"
    imports: Optional[List[str]] = None # PE only: libraries the file imports
    container: Optional[str] = None     # path of the file this binary was found inside
    offset: Optional[int] = None        # where in that file it starts
    embedded_binaries: int = 0          # how many binaries were found inside this one
    opaque: bool = False                # raw image that looks encrypted or compressed: unread
    build_id: Optional[str] = None      # GNU build-id: names this exact build, not a release

    def to_dict(self):
        return {
            "path": self.path, "sha256": self.sha256, "size": self.size,
            "kind": self.kind, "linked": self.linked, "toolchain": self.toolchain,
            "embedded": [vars(e) for e in self.embedded],
            "stripped": self.stripped, "symbols": self.symbols, "layers": self.layers,
            "functions": self.functions, "arch": self.arch,
            "function_source": self.function_source, "function_note": self.function_note,
            "product": self.product, "pdb": self.pdb, "signed": self.signed,
            "runtime": self.runtime, "imports": self.imports,
            "container": self.container, "offset": self.offset,
            "embedded_binaries": self.embedded_binaries, "opaque": self.opaque,
            "build_id": self.build_id,
        }


# What a piece of evidence is about. A library can be *inside* the file (a banner, a Go module
# compiled in), *needed by* it (a DLL import, an assembly reference, a package in its
# deps.json: the code is another file), or what the file *itself* is (a managed DLL naming
# itself). The SBOM says which, because the three mean different things for a reader.
DEPENDENCY_METHODS = ("imports", "dotnet-reference", "deps-json")
SELF_METHODS = ("dotnet-assembly", "package-note")


def embedded_libraries(blob: Binary) -> List[Embedded]:
    """Libraries whose code or dependency record is inside the file."""
    return [e for e in blob.embedded
            if e.method not in DEPENDENCY_METHODS and e.method not in SELF_METHODS]


def imported_libraries(blob: Binary) -> List[Embedded]:
    """Libraries the file needs at run time (a DLL import, an assembly reference); the code
    is elsewhere."""
    return [e for e in blob.embedded if e.method in ("imports", "dotnet-reference")]


def declared_dependencies(blob: Binary) -> List[Embedded]:
    """Packages a ``.deps.json`` beside the program lists: exact, but separate files."""
    return [e for e in blob.embedded if e.method == "deps-json"]


def identified_as(blob: Binary) -> List[Embedded]:
    """What the file says it is (a .NET assembly named like a package)."""
    return [e for e in blob.embedded if e.method in SELF_METHODS]


def _shown(items: Sequence[Embedded], with_version: bool, limit: int = 8) -> str:
    names = [((e.display_name + " " + e.version).strip() if with_version else e.display_name)
             for e in items]
    more = f" and {len(names) - limit} more" if len(names) > limit else ""
    return ", ".join(names[:limit]) + more


def describe_binary(blob: Binary) -> str:
    """One-line description shared by the SPDX writers."""
    text = f"prebuilt {blob.kind}, no source available"
    for label, items, versions in (
            ("embeds", embedded_libraries(blob), True),
            ("identifies itself as", identified_as(blob), True),
            ("imports", imported_libraries(blob), False),
            ("lists as dependencies in its deps.json", declared_dependencies(blob), True)):
        if items:
            text += f"; {label} {_shown(items, versions)}"
    if blob.runtime:
        text += f"; built with {blob.runtime}"
    if blob.embedded_binaries:
        text += f"; contains {blob.embedded_binaries} embedded binar" + (
            "y" if blob.embedded_binaries == 1 else "ies")
    if blob.container:
        text += f"; found inside {blob.container}"
    return text


_KINDS = {".a": "archive", ".so": "shared-library", ".lib": "import-library",
          ".elf": "firmware-image", ".axf": "firmware-image",
          ".bin": "firmware-image", ".exe": "executable", ".dll": "shared-library",
          ".sys": "shared-library", ".ocx": "shared-library", ".pyd": "shared-library"}
# libz.so.1, libssl.so.3, libfoo.so.1.2.3: the names a Linux library has, whose last suffix is
# a number, so the suffix tables above never see them.
_VERSIONED_SO = re.compile(r"\.so(\.\d+)+$", re.I)


def _is_elf_program(path: Path) -> bool:
    """An ELF executable or shared object, by its magic number: a program or library on a
    Linux root file system has no extension to say so (busybox, sshd, ld-linux-x86-64.so.2
    aside), and an object file or a core dump is not one."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
    except OSError:
        return False
    if len(head) < 20 or head[:4] != b"\x7fELF" or head[5] not in (1, 2):
        return False
    return int.from_bytes(head[16:18], "little" if head[5] == 1 else "big") in (2, 3)


def _wanted(path: Path) -> bool:
    """Whether a file is inventoried as a prebuilt binary: by suffix, by a versioned shared
    object's name, or, for a name with no suffix (or only a number), by what is inside."""
    suffix = path.suffix.lower()
    if suffix in BLOB_SUFFIXES or _VERSIONED_SO.search(path.name):
        return True
    return (suffix == "" or suffix[1:].isdigit()) and _is_elf_program(path)


def _kind(path: Path, data: bytes = b"") -> str:
    kind = _KINDS.get(path.suffix.lower())
    if kind is not None:
        return kind
    if _VERSIONED_SO.search(path.name):
        return "shared-library"
    info = parse_elf(data) if data[:4] == b"\x7fELF" else None
    if info is not None:
        return "executable" if info.is_executable else "shared-library"
    return "firmware-image"


def collect_binaries(root: Path, linked_archives: Optional[Set[str]] = None,
                     string_signatures: Sequence = (),
                     function_prints: Sequence = (),
                     product_stem: str = "",
                     banners: Sequence = ()) -> List[Binary]:
    """*string_signatures*: ``(display name, name, FunctionSignature)`` per rule that
    can recognise its component from string constants (see ``binsig``); *function_prints*
    the same triple with a ``fprint.FunctionPrints`` (per-function fingerprints).
    *banners*: ``(display name, name, compiled bytes pattern)`` that rules supply for their
    component, read like the built-in ones (the first group is the version).
    *product_stem*: with a link map, the map's file stem; a firmware image is the build's own
    product only when it shares that stem (``fw.map`` and ``fw.elf``). Any other image in the
    tree belongs to some other build, so it is marked not linked."""
    root = Path(root).resolve()
    out: List[Binary] = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        in_fixtures = any(part.lower() in FIXTURE_DIRS
                          for part in Path(here).relative_to(root).parts)
        for name in sorted(files):
            path = Path(here) / name
            if path.is_symlink() or not _wanted(path):
                continue
            if in_fixtures and path.suffix.lower() in PRODUCT_SUFFIXES:
                continue
            try:
                out.extend(_inspect(path, root, linked_archives, string_signatures,
                                    function_prints, product_stem, banners))
            except OSError:
                continue
    return out


def _inspect(path: Path, root: Path, linked_archives: Optional[Set[str]],
             string_signatures: Sequence = (), function_prints: Sequence = (),
             product_stem: str = "", banners: Sequence = ()) -> List[Binary]:
    """The file, followed by every binary found inside it."""
    data = path.read_bytes() if path.stat().st_size <= MAX_BANNER_BYTES else b""
    digest = hashlib.sha256(data if data else path.read_bytes()).hexdigest()
    rel = path.relative_to(root).as_posix()
    blob = Binary(path=rel, sha256=digest, size=path.stat().st_size, kind=_kind(path, data))
    if path.suffix.lower() in PRODUCT_SUFFIXES:
        # A link map names link inputs, never images. With one in hand, an image that is not
        # this build's product (an audio .bin, another example's firmware) did not ship in it.
        if linked_archives is not None and product_stem:
            blob.linked = path.stem.lower() == product_stem
    elif linked_archives is not None:
        parent = path.parent.name
        blob.linked = any(
            Path(a.replace("\\", "/")).name == path.name
            and parent in Path(a.replace("\\", "/")).parts
            for a in linked_archives)
    out = [blob]
    if data:
        _analyze(blob, data, path.suffix.lower(), path, string_signatures, function_prints,
                 0, out, banners)
    return out


def _analyze(blob: Binary, data: bytes, suffix: str, sidecar: Optional[Path],
             string_signatures: Sequence, function_prints: Sequence, depth: int,
             out: List[Binary], banners: Sequence = ()) -> None:
    """Read banners, structure and dependency lists from *data* into *blob*.

    Binaries found inside *data* (see ``carve``) are blanked out of what *blob* itself is read
    from, so a banner or a toolchain string is credited to the binary it is in; each is then
    analysed the same way and appended to *out* as an entry of its own."""
    carved = ([] if depth >= MAX_EMBED_DEPTH or suffix in NO_CARVE_SUFFIXES
              else carve(data))
    original = data
    data = mask(data, carved)
    layers = expand(data, suffix) if suffix in IMAGE_SUFFIXES else [Layer("", data)]
    blob.layers = len(layers)
    for layer in layers:
        elf = parse_elf(layer.data) if not layer.label else None
        pe = parse_pe(layer.data) if not layer.label and suffix in PE_SUFFIXES else None
        found = _banners(layer.data, elf, managed=pe is not None and pe.is_dotnet,
                         extra=banners)
        if not layer.label:
            found += _toolchain_lists(blob, layer.data, pe, elf)
            found += _package_metadata(layer.data, elf)
            if elf is not None:
                blob.build_id = build_id(layer.data, elf)
                if sidecar is not None:
                    found += _file_name_release(sidecar, layer.data, elf, found + blob.embedded)
        if pe is not None:
            found += _pe_evidence(blob, pe, found + blob.embedded, layer.data)
            if sidecar is not None:
                found += _sidecar_packages(sidecar, found + blob.embedded)
        if string_signatures:
            found += _by_strings(layer.data, found + blob.embedded, string_signatures)
        # Function-level work costs seconds per megabyte, so a library or program on a
        # root file system gets it only when some rule has references built for its CPU.
        code = (not layer.label and disasm.available()
                and (suffix in IMAGE_SUFFIXES or _prints_for(elf, function_prints)))
        if function_prints and code:
            found += _by_functions(layer.data, found + blob.embedded, function_prints)
        for emb in found:
            if any((e.name, e.version) == (emb.name, emb.version) for e in blob.embedded):
                continue
            if layer.label:
                emb.banner += f"  [inside {layer.label}]"
            blob.embedded.append(emb)
        tool = _TOOLCHAIN.search(layer.data)
        if tool and not blob.toolchain:
            blob.toolchain = (f"{tool.group(1).decode('ascii', 'replace')} "
                              f"{tool.group(2).decode('ascii')}")
        if code:
            _recover_functions(blob, layer.data, elf, suffix == ".bin")
        if elf:
            blob.stripped, blob.symbols = elf.stripped, len(elf.defined)
            if not blob.toolchain:
                blob.toolchain = next((c for c in elf.comments if c.startswith("GCC")), None)
        # The linker version is only worth showing when nothing better is known: the Go and
        # .NET toolchains write their own numbers there (3.0, 48.0), and ``runtime`` says more.
        if pe is not None and not blob.toolchain and not blob.runtime and pe.linker != "0.0":
            blob.toolchain = f"linker {pe.linker}"
    blob.embedded_binaries = len(carved)
    if (depth == 0 and suffix == ".bin" and blob.layers == 1 and not blob.embedded
            and not blob.functions and _looks_unreadable(original)):
        blob.opaque = True
    names = _resource_names(original) if carved else {}
    for item in carved:
        sub = original[item.offset:item.offset + item.size]
        label = names.get(item.offset)
        child = Binary(
            path=f"{blob.path}!{label}" if label else f"{blob.path}#{item.offset:#x}",
            sha256=hashlib.sha256(sub).hexdigest(), size=item.size,
            kind=f"embedded-{item.kind}", linked=blob.linked, container=blob.path,
            offset=item.offset, arch=item.arch)
        out.append(child)
        _analyze(child, sub, item.suffix, None, string_signatures, function_prints,
                 depth + 1, out, banners)


def _resource_names(data: bytes) -> dict:
    """Offset -> name of each managed resource, so a binary carved out of a .NET assembly can be
    called by the name its author gave it."""
    from .dotnet import managed_resources
    pe = parse_pe(data) if data[:2] == b"MZ" else None
    return managed_resources(data, pe) if pe is not None and pe.is_dotnet else {}


def _banners(data: bytes, elf: Optional[ElfInfo] = None, managed: bool = False,
             extra: Sequence = ()) -> List[Embedded]:
    found: List[Embedded] = []
    seen = set()
    # (a rule's banner for a component the engine already knows loses to the built-in one)
    for name, display, pattern in list(_COMPILED) + list(extra):
        if name in seen:
            continue
        m = pattern.search(data)
        if m:
            version = m.group(1).decode("ascii")
            found.append(Embedded(name, display, version,
                                  m.group(0).decode("ascii", "replace")))
            seen.add(name)
    for name, display, need, wanted in ([] if managed else _SYMBOL_SETS):
        # a .NET assembly defines no native symbols: the names in its metadata are P/Invoke
        # declarations of what it calls, and the library is a separate file (or a carved one)
        if name in seen:
            continue                          # a banner already named it, with a version
        if elf and not elf.stripped:
            # a real symbol table: count what the file defines, not any string that matches
            hits = sum(1 for w in wanted if w[1:-1].decode() in elf.defined)
        else:
            hits = sum(1 for w in wanted if w in data)
        if hits >= need:
            series = _SERIES[name].search(data) if name in _SERIES else None
            found.append(Embedded(name, display, "",
                                  f"{hits} of {len(wanted)} {display} API symbols"
                                  + (f"; shared-object name says series {series.group(1).decode()}"
                                     if series else ""),
                                  method="symbols"))
            seen.add(name)
    vendor = set()
    for m in _VENDOR_COMPONENT.finditer(data):
        key = (m.group(1).decode("ascii"), m.group(2).decode("ascii"))
        if key not in vendor:
            vendor.add(key)
            found.append(Embedded(key[0], key[0], key[1],
                                  m.group(0).decode("ascii", "replace"),
                                  vendor_component=True))
    return found


# Files that are high-entropy by nature, or that something else reads: not "unreadable firmware".
_NOT_OPAQUE_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"ID3", b"\xff\xfb",
                     b"PK\x03\x04", b"7z\xbc\xaf", b"Rar!", b"\x1f\x8b", b"\xfd7zXZ", b"BZh",
                     b"GGUF", b"\x7fELF", b"MZ", b"fLaC", b"wOFF", b"%PDF")
OPAQUE_MIN_SIZE = 16 * 1024
OPAQUE_RATIO = 0.96             # deflate output over input: code and tables are well below it
_SAMPLE = 32 * 1024


def _looks_unreadable(data: bytes) -> bool:
    """Whether a raw image is high-entropy: encrypted, or compressed with a scheme nothing here
    unwraps (LZ4, zstd, a vendor's own). Sampled from the start, the middle and the end;
    every sample has to be incompressible, so a firmware with a compressed blob in it is not
    called opaque."""
    if len(data) < OPAQUE_MIN_SIZE or data[:4] in _NOT_OPAQUE_MAGIC or any(
            data.startswith(m) for m in _NOT_OPAQUE_MAGIC):
        return False
    last = len(data) - _SAMPLE
    for at in (0, last // 2, last):
        chunk = data[at:at + _SAMPLE]
        if len(zlib.compress(chunk, 1)) < OPAQUE_RATIO * len(chunk):
            return False
    return True


def _prints_for(elf: Optional[ElfInfo], prints: Sequence) -> bool:
    """Whether some rule has per-function references built for this ELF's CPU."""
    arch = disasm.arch_of_elf(elf) if elf is not None else None
    return bool(arch) and any(getattr(p[2], "arch", "") == arch for p in prints)


_PURL_TYPES = {"deb": "deb", "rpm": "rpm", "apk": "apk", "alpm": "alpm"}


def _package_metadata(data: bytes, elf: Optional[ElfInfo]) -> List[Embedded]:
    """The package the distribution's build says this file belongs to (``.note.package``).

    The version is the package's, with the distribution's revision (1.5.5+dfsg2-2build1.1),
    and it is kept whole: a distribution backports fixes without changing the upstream
    number, so it is no more an upstream release than a dpkg status entry is."""
    note = package_note(data, elf) if elf is not None else None
    if not note:
        return []
    name, version = str(note.get("name") or "").strip(), str(note.get("version") or "").strip()
    if not name or not version:
        return []
    kind = str(note.get("type") or "").strip().lower()
    distro = str(note.get("os") or "").strip()
    if not distro:                      # "cpe:/o:fedoraproject:fedora:33": the product, fedora
        cpe = str(note.get("osCpe") or "").split(":")
        distro = cpe[3] if len(cpe) > 3 else ""
    arch = str(note.get("architecture") or "").strip()
    namespace = quote(distro.lower().replace(" ", "-"), safe="") if distro else ""
    purl = (f"pkg:{_PURL_TYPES.get(kind, 'generic')}/" + (namespace + "/" if namespace else "")
            + quote(name, safe="") + "@" + quote(version, safe="~.-_")
            + (f"?arch={quote(arch, safe='')}" if arch else ""))
    where = ", ".join(x for x in (kind, distro, arch) if x)
    return [Embedded(name.lower(), name, version,
                     f"{name} {version}" + (f" ({where})" if where else ""),
                     method="package-note", purl=purl)]


# Libraries whose shared-object file name carries the release itself (libz.so.1.3.1 is zlib
# 1.3.1), with the fewest numbers that make it so. Libtool-versioned libraries (libexpat.so.1.8.10
# is expat 2.4.x) are not here: their number counts interface changes, not releases.
_FILE_NAME_RELEASES = {
    "libz": ("zlib", "zlib", 2),
    "liblzma": ("xz", "xz", 3),
    "libzstd": ("zstd", "zstd", 3),
    "liblz4": ("lz4", "lz4", 3),
    "libxml2": ("libxml2", "libxml2", 3),
}
_SHARED_OBJECT = re.compile(r"(lib[a-z0-9_]+)\.so((?:\.\d+)+)")


def _file_name_release(path: Path, data: bytes, elf: ElfInfo, known: Sequence[Embedded]
                       ) -> List[Embedded]:
    """The release a distribution's shared object names in its file name, for the libraries
    that number their files by release. It must agree with the object's own SONAME, so a file
    renamed by hand does not pass; and the ELF must be a library, not a program that merely
    sits beside one. Weaker than a banner (a file name is whatever the packager chose), so it
    only speaks when no banner named the library."""
    if elf.is_executable or elf.etype != 3:
        return []
    m = _SHARED_OBJECT.fullmatch(path.name)
    spec = _FILE_NAME_RELEASES.get(m.group(1)) if m else None
    if not m or spec is None:
        return []
    name, display, fewest = spec
    version = m.group(2)[1:]
    own = soname(data, elf)
    if len(version.split(".")) < fewest or not own or not own.startswith(f"{m.group(1)}.so"):
        return []
    if any(e.name == name and e.version for e in known):
        return []
    return [Embedded(name, display, version,
                     f"shared object {path.name} (SONAME {own})", method="file-name")]


def _by_strings(data: bytes, known: Sequence[Embedded], signatures: Sequence
                ) -> List[Embedded]:
    """Libraries recognised by the string constants of recorded upstream releases."""
    from .binsig import image_strings, match_image
    named = {e.name for e in known if e.version}
    present = None
    found: List[Embedded] = []
    for display, name, signature in signatures:
        if name in named:
            continue                          # a banner already gave a version
        if present is None:
            present = image_strings(data)
        hit = match_image(signature, present)
        if hit:
            version, matched, total, coverage, tied = hit
            found.append(Embedded(
                name, display, tied or version,       # a tie is a "low~high" span, as elsewhere
                f"{matched} of {total} string constants of {display}"
                + (f" {version}" if version else "") + f" ({coverage:.0%})"
                + (f"; releases {tied} fit equally well" if tied else ""),
                method="strings"))
    return found


def _recover_functions(blob: Binary, data: bytes, elf: Optional[ElfInfo], raw_ok: bool) -> None:
    """Function boundaries for an ELF, or for a bare Cortex-M ``.bin``."""
    if elf is not None:
        rec = disasm.recover_elf(data, elf)
    elif raw_ok:
        rec = disasm.recover_raw(data)
    else:
        return
    if rec is None:
        return
    if not rec.functions:
        blob.function_note = rec.note or None
        return
    blob.arch, blob.functions = rec.arch, len(rec.functions)
    blob.function_source = "symbols" if rec.from_symbols == len(rec.functions) else "disassembly"


def _by_functions(data: bytes, known: Sequence[Embedded], prints: Sequence) -> List[Embedded]:
    """Libraries whose functions are found, one by one, inside a compiled image."""
    from .fprint import image_features
    named = {e.name for e in known if e.version}
    image = None
    arch = None
    found: List[Embedded] = []
    done = set()
    # A rule may list a sidecar per architecture. Try the one built for this image's CPU
    # first: it compares constants as well as strings, the others strings only.
    todo = list(prints)
    for display, name, reference in todo:
        if name in named or name in done:
            continue
        if image is None:
            image, arch = image_features(data)
        candidates = sorted((p for p in todo if p[1] == name),
                            key=lambda p: 0 if arch and p[2].arch == arch else 1)
        for display, name, reference in candidates:
            hit = reference.match(image, arch=arch) if image else None
            if hit:
                version, matched, total, coverage, tied = hit
                if _compared_by_strings(reference, arch) and len(reference.versions) > 1:
                    # Strings alone cannot tell the releases of another CPU's build apart:
                    # on Mbed TLS they named one wrong release with 0.60 confidence. Name
                    # the library and everything the rule covers.
                    tied = f"{reference.versions[0]}~{reference.versions[-1]}"
                    version = ""
                found.append(Embedded(
                    name, display, tied or version,       # a tie is a "low~high" span, as elsewhere
                    f"{matched} of {total} fingerprinted functions of {display}"
                    + (f" {version}" if version else "")
                    + f" ({coverage:.0%})"
                    + ("; the version is not narrowed: all releases the rule covers are listed"
                       if _compared_by_strings(reference, arch) and len(reference.versions) > 1
                       else (f"; releases {tied} fit equally well" if tied else ""))
                    + _newest_note(reference, version, tied)
                    + _architecture_note(reference, arch)
                    + _calibration_note(reference)
                    + _coverage_note(reference, coverage),
                    method="functions"))
                done.add(name)
                break
    return found


LOW_COVERAGE = 0.5


def _coverage_note(prints, coverage: float) -> str:
    """Low coverage means the image is a build the references were not made from: another
    configuration, a vendor fork, or a release the rule does not cover. The release named is
    then only the nearest of the fingerprinted ones (docs/BINARY-VALIDATION.md, real firmware)."""
    if coverage >= LOW_COVERAGE:
        return ""
    return (f"; low coverage: the release is the nearest of the {len(prints.versions)} "
            "fingerprinted ones and may not be the one in the image")


def _newest_note(prints, version: str, tied: str) -> str:
    """The answer reaches the newest release the fingerprints were made from: a later one
    would be reported as this, since nothing newer can be told apart."""
    if len(prints.versions) < 2:
        return ""
    top = tied.split("~")[-1] if tied else version
    if top != prints.versions[-1]:
        return ""
    return (f"; {top} is the newest fingerprinted release, so the image may be a later one "
            "that the fingerprints do not cover")


def _compared_by_strings(prints, arch: Optional[str]) -> bool:
    """The references were built for another CPU than this image: only strings were compared."""
    return bool(arch and prints.arch and arch != prints.arch and prints.knows_strings())


def _architecture_note(prints, arch: Optional[str]) -> str:
    if _compared_by_strings(prints, arch):
        return (f"; the references were built for {prints.arch} and this image is {arch}, so "
                "only string literals were compared")
    return ""


def _calibration_note(prints) -> str:
    """What the rule's author tested, so a reader sees how far the claim was checked."""
    meta = getattr(prints, "meta", None) or {}
    cross = meta.get("cross_build")
    if not cross:
        return ""
    answered = cross["exact"] + cross["range"] + cross["wrong"]
    return (f"; rule self-test: {answered - cross['wrong']} of {answered + cross['none']} "
            f"cross-build images named the right release, "
            f"{meta.get('false_positives', 0)} false positive(s) in "
            f"{meta.get('negative_pairs', 0)} negative controls")


# What a Windows version resource says the product is, mapped to components this scanner
# already knows by name. Matched on the product name, never on the file name alone: a
# vendor's wrapper often keeps the library's file name. (name, display name, pattern)
_PRODUCTS = (
    ("curl", "curl", re.compile(r"^(?:lib)?curl\b", re.I)),
    ("openssl", "OpenSSL", re.compile(r"^OpenSSL\b", re.I)),
    ("zlib", "zlib", re.compile(r"^zlib\b", re.I)),
    ("libpng", "libpng", re.compile(r"^libpng\b", re.I)),
    ("sqlite", "SQLite", re.compile(r"^SQLite\d*\b", re.I)),
    ("mbedtls", "Mbed TLS", re.compile(r"^Mbed ?TLS\b", re.I)),
    ("wolfssl", "wolfSSL", re.compile(r"^wolfSSL\b", re.I)),
    ("opus", "Opus", re.compile(r"^(?:lib)?opus\b", re.I)),
    ("libvorbis", "libvorbis", re.compile(r"^(?:lib)?vorbis\b", re.I)),
    ("speex", "Speex", re.compile(r"^(?:lib)?speex\b", re.I)),
)
# Libraries a binary imports by DLL name. An import says the binary needs the library at run
# time; the library itself is a separate file, and the name never says which release.
_IMPORT_LIBS = (
    ("curl", "curl", re.compile(r"^libcurl(?:-\d+)?\.dll$")),
    ("openssl", "OpenSSL", re.compile(
        r"^(?:libssl|libcrypto)(?:-[\w]+)*\.dll$|^(?:ssleay32|libeay32)\.dll$")),
    ("zlib", "zlib", re.compile(r"^(?:zlib1?|libz(?:-\d+)?|zlibwapi)\.dll$")),
    ("libpng", "libpng", re.compile(r"^libpng\d*(?:-\d+)?\.dll$")),
    ("sqlite", "SQLite", re.compile(r"^(?:lib)?sqlite3(?:-\d+)?\.dll$")),
    ("mbedtls", "Mbed TLS", re.compile(r"^(?:lib)?mbed(?:tls|crypto|x509)\.dll$")),
    ("wolfssl", "wolfSSL", re.compile(r"^(?:lib)?wolfssl\.dll$")),
    ("opus", "Opus", re.compile(r"^(?:lib)?opus(?:-\d+)?\.dll$")),
    ("libvorbis", "libvorbis", re.compile(r"^(?:lib)?vorbis(?:file|enc)?(?:-\d+)?\.dll$")),
    ("speex", "Speex", re.compile(r"^(?:lib)?speex(?:-\d+)?\.dll$")),
)
_VERSION_TEXT = re.compile(r"(\d+\.\d+(?:\.\d+)?[a-z]?)")
_VERSION_KEYS = ("ProductName", "ProductVersion", "FileVersion", "CompanyName",
                 "OriginalFilename", "InternalName", "FileDescription")


def _numeric_version(text: str) -> str:
    """``3.0.11.0`` -> ``3.0.11``: the fourth field of a Windows version is a build number."""
    parts = text.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 and parts[3] == "0" else text


def _pe_evidence(blob: Binary, pe: PeInfo, known: Sequence[Embedded],
                 data: bytes = b"") -> List[Embedded]:
    """What the PE structure itself says: product, imports, build tree, signature."""
    blob.arch = pe.machine
    blob.signed = pe.signed
    blob.pdb = pe.pdb or None
    blob.imports = list(pe.imports)
    info = {k: pe.version_info[k] for k in _VERSION_KEYS if pe.version_info.get(k)}
    if pe.file_version and "FileVersion" not in info:
        info["FileVersion"] = pe.file_version
    if info and not blob.product:
        blob.product = info
    if pe.is_dotnet and not blob.runtime:
        blob.runtime = "dotnet"
    found: List[Embedded] = []
    named = {e.name for e in known if e.version}
    product = pe.version_info.get("ProductName", "")
    for name, display, pattern in _PRODUCTS:
        if name in named or not pattern.match(product):
            continue
        shown = pe.version_info.get("ProductVersion") or pe.version_info.get("FileVersion", "")
        m = _VERSION_TEXT.search(shown)
        version = m.group(1) if m else _numeric_version(pe.product_version or pe.file_version)
        if not version or version.startswith("0.0.0"):
            continue
        found.append(Embedded(
            name, display, version,
            f"ProductName={product!r} ProductVersion={shown!r}", method="version-info"))
        break
    if pe.is_dotnet:
        found += _dotnet_evidence(blob, pe, data)
    taken = {e.name for e in known} | {e.name for e in found}
    for dll in pe.imports:
        for name, display, pattern in _IMPORT_LIBS:
            if name not in taken and pattern.match(dll):
                found.append(Embedded(name, display, "", f"imports {dll}", method="imports"))
                taken.add(name)
    return found


def _toolchain_lists(blob: Binary, data: bytes, pe: Optional[PeInfo],
                     elf: Optional[ElfInfo]) -> List[Embedded]:
    """Dependency lists the Go and Rust toolchains record on purpose (see ``binmeta``)."""
    found: List[Embedded] = []
    go = go_buildinfo(data)
    if go is not None:
        found += _go_embedded(blob, go)
    blob_bytes = b""
    if pe is not None:
        blob_bytes = pe.section_bytes(data, CARGO_SECTION)
    elif elf is not None:
        sec = next((s for s in elf.sections if s.name == CARGO_SECTION), None)
        blob_bytes = data[sec.offset:sec.offset + sec.size] if sec else b""
    crates = cargo_auditable(blob_bytes) if blob_bytes else None
    if crates is not None:
        found += _cargo_embedded(blob, crates)
    return found


_GO_RELEASE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")


def _go_embedded(blob: Binary, info: GoBuildInfo) -> List[Embedded]:
    blob.runtime = f"go {info.go_version}"
    main = next((m for m in info.modules if m.main), None)
    blob.product = blob.product or ({"name": main.path, "version": main.version}
                                    if main else ({"name": info.path} if info.path else None))
    out: List[Embedded] = []
    release = info.go_version[2:] if info.go_version.startswith("go") else ""
    if _GO_RELEASE.match(release):
        out.append(Embedded(
            "stdlib", "Go standard library", release, f"{info.go_version} (toolchain)",
            method="go-buildinfo", purl=f"pkg:golang/stdlib@{release}",
            cpe=f"cpe:2.3:a:golang:go:{release}:*:*:*:*:*:*:*"))
    for mod in info.dependencies:
        if not mod.version:
            continue
        note = f"; replaced by {mod.replaced_by}" if mod.replaced_by else ""
        out.append(Embedded(
            mod.path, mod.path, mod.version,
            f"go module {mod.path} {mod.version}" + (f" {mod.sum}" if mod.sum else "") + note,
            method="go-buildinfo", purl=f"pkg:golang/{mod.path.lower()}@{mod.version}",
            modified=bool(mod.replaced_by)))
    return out


def _cargo_embedded(blob: Binary, crates: Sequence) -> List[Embedded]:
    root = next((c for c in crates if c.root), None)
    if root is not None:
        blob.product = blob.product or {"name": root.name, "version": root.version}
    blob.runtime = blob.runtime or "rust"
    out: List[Embedded] = []
    for crate in crates:
        # The root is the product itself; a build-only crate is a tool, not shipped code.
        if crate.root or crate.source == "local" or crate.kind == "build" or not crate.version:
            continue
        out.append(Embedded(
            crate.name, crate.name, crate.version,
            f"cargo crate {crate.name} {crate.version}"
            + (f" ({crate.source})" if crate.source else ""),
            method="cargo-auditable", purl=f"pkg:cargo/{crate.name.lower()}@{crate.version}"))
    return out


_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.\-]+)?")


def _dotnet_evidence(blob: Binary, pe: PeInfo, data: bytes) -> List[Embedded]:
    """A managed assembly's identity, and the third-party assemblies it references.

    An ``AssemblyRef`` carries the *assembly* version, which is not the NuGet package version
    (Newtonsoft.Json 13.0.3 is assembly 13.0.0.0), so a reference names a dependency and never
    a release. The version resource's ``ProductVersion`` usually is the package version, with
    build metadata after a ``+``.
    """
    info = parse_dotnet(data, pe) if data else None
    if info is None:
        return []
    product = dict(blob.product or {})
    product["AssemblyName"], product["AssemblyVersion"] = info.name, info.version
    blob.product = product
    out: List[Embedded] = []
    for ref in info.third_party_references():
        out.append(Embedded(
            ref.name, ref.name, "", f"references assembly {ref.name} {ref.version}",
            method="dotnet-reference", purl=f"pkg:nuget/{ref.name}"))
    informational = pe.version_info.get("ProductVersion", "").split("+", 1)[0]
    m = _SEMVER.match(informational)
    if pe.is_dll and info.name and not is_framework(info.name) and m:
        out.append(Embedded(
            info.name, info.name, m.group(0),
            f"assembly {info.name} with ProductVersion {pe.version_info['ProductVersion']!r}",
            method="dotnet-assembly", purl=f"pkg:nuget/{info.name}@{m.group(0)}"))
    return out


def _sidecar_packages(path: Path, known: Sequence[Embedded]) -> List[Embedded]:
    """NuGet packages from the ``<name>.deps.json`` the .NET SDK writes beside a program.

    An ``app.exe`` apphost and its ``app.dll`` share one ``app.deps.json``; it is attached to
    the executable when there is one, so the packages are not listed twice."""
    if path.suffix.lower() == ".dll" and path.with_suffix(".exe").exists():
        return []
    deps = path.with_name(path.stem + ".deps.json")
    packages = read_deps_json(deps) if deps.is_file() else None
    out: List[Embedded] = []
    seen = {(e.name, e.version) for e in known}
    for pkg in packages or ():
        name = pkg.name[len("runtimepack."):] if pkg.kind == "runtimepack" else pkg.name
        if (name, pkg.version) in seen:
            continue
        out.append(Embedded(name, name, pkg.version, f"{deps.name}: {pkg.name}/{pkg.version}",
                            method="deps-json", purl=f"pkg:nuget/{name}@{pkg.version}"))
    return out
