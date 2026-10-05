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
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Set

from . import disasm
from .elf import ElfInfo, parse_elf
from .unpack import IMAGE_SUFFIXES as UNPACK_SUFFIXES, Layer, expand

IMAGE_SUFFIXES = {".elf", ".axf", ".bin"} | UNPACK_SUFFIXES   # linked products, not link inputs:
#                                      a link map has nothing to say about them
BLOB_SUFFIXES = {".a", ".lib", ".so"} | IMAGE_SUFFIXES
SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv"}
# Directories that hold test inputs, not shipped products. A ``.bin`` or ``.elf`` in one of
# them (lwIP's fuzz inputs are ``.bin`` packets) is fixture data, so it is not inventoried as
# a firmware image. Libraries (``.a``, ``.lib``, ``.so``) are still listed wherever they are.
FIXTURE_DIRS = {"test", "tests", "testdata", "test_data", "fuzz", "fixtures"}
MAX_BANNER_BYTES = 64 * 1024 * 1024

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
    ("zlib", "zlib", rb"(?:deflate|inflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright"),
    ("libpng", "libpng", rb"libpng version (\d+\.\d+\.\d+)"),
    ("curl", "curl", rb"libcurl/(\d+\.\d+\.\d+)"),
    ("sqlite", "SQLite", rb"SQLite version (\d+\.\d+\.\d+)"),
    ("freertos", "FreeRTOS-Kernel", rb"FreeRTOS (?:Kernel )?V(\d+\.\d+\.\d+)"),
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
)
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
    method: str = "banner"              # banner | symbols | strings
    # version "" means the library is there (API symbols) but no release can be named


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

    def to_dict(self):
        return {
            "path": self.path, "sha256": self.sha256, "size": self.size,
            "kind": self.kind, "linked": self.linked, "toolchain": self.toolchain,
            "embedded": [vars(e) for e in self.embedded],
            "stripped": self.stripped, "symbols": self.symbols, "layers": self.layers,
            "functions": self.functions, "arch": self.arch,
            "function_source": self.function_source, "function_note": self.function_note,
        }


def _kind(path: Path) -> str:
    return {".a": "archive", ".so": "shared-library", ".lib": "import-library",
            ".elf": "firmware-image", ".axf": "firmware-image",
            ".bin": "firmware-image"}.get(path.suffix.lower(), "firmware-image")


def collect_binaries(root: Path, linked_archives: Optional[Set[str]] = None,
                     string_signatures: Sequence = (),
                     function_prints: Sequence = ()) -> List[Binary]:
    """*string_signatures*: ``(display name, name, FunctionSignature)`` per rule that
    can recognise its component from string constants (see ``binsig``); *function_prints*
    the same triple with a ``fprint.FunctionPrints`` (per-function fingerprints)."""
    root = Path(root).resolve()
    out: List[Binary] = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        in_fixtures = any(part.lower() in FIXTURE_DIRS
                          for part in Path(here).relative_to(root).parts)
        for name in sorted(files):
            path = Path(here) / name
            if path.suffix.lower() not in BLOB_SUFFIXES or path.is_symlink():
                continue
            if in_fixtures and path.suffix.lower() in IMAGE_SUFFIXES:
                continue
            try:
                out.append(_inspect(path, root, linked_archives, string_signatures,
                                    function_prints))
            except OSError:
                continue
    return out


def _inspect(path: Path, root: Path, linked_archives: Optional[Set[str]],
             string_signatures: Sequence = (), function_prints: Sequence = ()) -> Binary:
    data = path.read_bytes() if path.stat().st_size <= MAX_BANNER_BYTES else b""
    digest = hashlib.sha256(data if data else path.read_bytes()).hexdigest()
    rel = path.relative_to(root).as_posix()
    blob = Binary(path=rel, sha256=digest, size=path.stat().st_size, kind=_kind(path))
    if linked_archives is not None and path.suffix.lower() not in IMAGE_SUFFIXES:
        parent = path.parent.name
        blob.linked = any(
            Path(a.replace("\\", "/")).name == path.name
            and parent in Path(a.replace("\\", "/")).parts
            for a in linked_archives)
    if data:
        layers = (expand(data, path.suffix) if path.suffix.lower() in IMAGE_SUFFIXES
                  else [Layer("", data)])
        blob.layers = len(layers)
        for layer in layers:
            elf = parse_elf(layer.data) if not layer.label else None
            found = _banners(layer.data, elf)
            if string_signatures:
                found += _by_strings(layer.data, found + blob.embedded, string_signatures)
            if (function_prints and not layer.label and disasm.available()
                    and path.suffix.lower() in IMAGE_SUFFIXES):
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
            if not layer.label and disasm.available() and path.suffix.lower() in IMAGE_SUFFIXES:
                _recover_functions(blob, layer.data, elf, path.suffix.lower() == ".bin")
            if elf:
                blob.stripped, blob.symbols = elf.stripped, len(elf.defined)
                if not blob.toolchain:
                    blob.toolchain = next((c for c in elf.comments if c.startswith("GCC")), None)
    return blob


def _banners(data: bytes, elf: Optional[ElfInfo] = None) -> List[Embedded]:
    found: List[Embedded] = []
    seen = set()
    for name, display, pattern in _COMPILED:
        m = pattern.search(data)
        if m:
            version = m.group(1).decode("ascii")
            found.append(Embedded(name, display, version,
                                  m.group(0).decode("ascii", "replace")))
            seen.add(name)
    for name, display, need, wanted in _SYMBOL_SETS:
        if name in seen:
            continue                          # a banner already named it, with a version
        if elf and not elf.stripped:
            # a real symbol table: count what the file defines, not any string that matches
            hits = sum(1 for w in wanted if w[1:-1].decode() in elf.defined)
        else:
            hits = sum(1 for w in wanted if w in data)
        if hits >= need:
            found.append(Embedded(name, display, "",
                                  f"{hits} of {len(wanted)} {display} API symbols",
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
    from .fprint import image_function_features
    named = {e.name for e in known if e.version}
    image = None
    found: List[Embedded] = []
    for display, name, reference in prints:
        if name in named:
            continue
        if image is None:
            image = image_function_features(data)
        hit = reference.match(image) if image else None
        if hit:
            version, matched, total, coverage, tied = hit
            found.append(Embedded(
                name, display, tied or version,       # a tie is a "low~high" span, as elsewhere
                f"{matched} of {total} fingerprinted functions of {display} {version} "
                f"({coverage:.0%})" + (f"; releases {tied} fit equally well" if tied else "")
                + _calibration_note(reference),
                method="functions"))
    return found


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
