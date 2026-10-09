"""AI bill of materials: the machine-learning models and inference runtimes in a tree.

Two things are looked for, and both by name or by file signature, not by behaviour:

* **models** -- files whose signature or extension says "model" (TensorFlow Lite, GGUF,
  ONNX, safetensors, PyTorch, ...) and TensorFlow Lite models compiled into a C array;
* **runtimes** -- inference libraries named in the sources (TFLite Micro, CMSIS-NN,
  Edge Impulse, ONNX Runtime, llama.cpp, ...).

The result is a CycloneDX 1.6 document: models are ``machine-learning-model`` components
with a SHA-256, runtimes are ``library`` components. Where the artifact itself states
something (a GGUF file names its architecture) that goes into the model card; what it
cannot state -- training data, licence, intended use -- is left out, not guessed.

This module stands on ``gangmu.core`` and the shared directory lists; it does not import the
SBOM or CBOM engines.
"""
import datetime as _dt
import hashlib
import os
import re
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .binaries import FIXTURE_DIRS, SKIP_DIRS

SPEC_VERSION = "1.6"

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc", ".ino", ".py"}
DOC_DIRS = {"doc", "docs", "doxygen"}
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_OCCURRENCES = 20
HEAD_BYTES = 64 * 1024


@dataclass(frozen=True)
class ModelFormat:
    key: str
    name: str
    suffixes: Tuple[str, ...] = ()
    magic: Optional[Tuple[int, bytes]] = None     # (offset, bytes) that settles it
    note: str = ""


FORMATS: Tuple[ModelFormat, ...] = (
    ModelFormat("gguf", "GGUF", (".gguf",), (0, b"GGUF")),
    ModelFormat("tflite", "TensorFlow Lite", (".tflite",), (4, b"TFL3")),
    ModelFormat("executorch", "ExecuTorch", (".pte",), (4, b"ET12")),
    ModelFormat("onnx", "ONNX", (".onnx",)),
    ModelFormat("safetensors", "safetensors", (".safetensors",)),
    ModelFormat("pytorch", "PyTorch checkpoint", (".pt", ".pth", ".ckpt"),
                note="Pickle-based format: loading it can run code. Prefer safetensors, or "
                     "load it only from a source you trust."),
    ModelFormat("keras-h5", "Keras/HDF5", (".h5", ".keras", ".hdf5")),
    ModelFormat("coreml", "Core ML", (".mlmodel",)),
    ModelFormat("rknn", "Rockchip RKNN", (".rknn",)),
    ModelFormat("mnn", "MNN", (".mnn",)),
)

# A TensorFlow Lite flatbuffer starts with a 4-byte offset, then "TFL3". Compiled into a
# C array (xxd -i, or the TFLite Micro examples) it reads 0x54, 0x46, 0x4c, 0x33.
_EMBEDDED_TFLITE = re.compile(rb"0x54\s*,\s*0x46\s*,\s*0x4[cC]\s*,\s*0x33")


@dataclass(frozen=True)
class Runtime:
    key: str
    name: str
    patterns: Tuple[str, ...]


_B = r"(?<![A-Za-z0-9_])"

RUNTIMES: Tuple[Runtime, ...] = (
    Runtime("tflite-micro", "TensorFlow Lite Micro", (
        _B + r"(?:tflite::MicroInterpreter|tflite::MicroMutableOpResolver|"
             r"tensorflow/lite/micro/\w+)",)),
    Runtime("tflite", "TensorFlow Lite", (
        _B + r"(?:TfLiteInterpreter\w*|tflite::Interpreter\b|tflite::InterpreterBuilder|"
             r"tflite::FlatBufferModel)",)),
    Runtime("onnxruntime", "ONNX Runtime", (
        _B + r"(?:OrtCreateSession\w*|onnxruntime_c_api\.h|Ort::Session|OrtGetApiBase)",)),
    Runtime("cmsis-nn", "CMSIS-NN", (
        _B + r"(?:arm_convolve_s8|arm_convolve_s16|arm_fully_connected_s8|"
             r"arm_depthwise_conv_s8\w*|arm_nn_\w+|arm_nnfunctions\.h)",)),
    Runtime("edge-impulse", "Edge Impulse SDK", (
        _B + r"(?:run_classifier\w*|ei_impulse\w*|edge-impulse-sdk/\w+|EI_CLASSIFIER_\w+)",)),
    Runtime("microtvm", "Apache TVM (microTVM)", (
        _B + r"(?:tvmgen_default_\w+|TVMGraphExecutor\w*|tvm/runtime/\w+\.h)",)),
    Runtime("nnom", "NNoM", (_B + r"(?:nnom_model_create|nnom_model_run|nnom\.h)",)),
    Runtime("executorch", "ExecuTorch", (_B + r"(?:executorch::\w+|executorch/runtime/\w+)",)),
    Runtime("llama-cpp", "llama.cpp / ggml", (
        _B + r"(?:llama_model_load\w*|llama_load_model\w*|llama_init_from_\w+|ggml_init\b|"
             r"gguf_init_from_file)",)),
    Runtime("ncnn", "ncnn", (_B + r"(?:ncnn::Net\b|ncnn/net\.h)",)),
    Runtime("mnn", "MNN", (_B + r"(?:MNN::Interpreter|MNN/Interpreter\.hpp)",)),
    Runtime("esp-dl", "ESP-DL", (_B + r"(?:dl::Model\b|dl_tensor\w*|esp-dl/\w+)",)),
    Runtime("stm32-ai", "STM32Cube.AI (X-CUBE-AI)", (
        _B + r"(?:ai_network_create\w*|ai_platform\.h|stai_network_\w+|ai_\w+_run\b)",)),
    Runtime("rknn", "Rockchip RKNN runtime", (_B + r"(?:rknn_init|rknn_run|rknn_api\.h)",)),
    Runtime("tensorflow-c", "TensorFlow (C API)", (
        _B + r"(?:TF_NewGraph|TF_NewSession\w*|tensorflow/c/c_api\.h)",)),
)

_COMPILED = [(rt, [re.compile(p.encode()) for p in rt.patterns]) for rt in RUNTIMES]


@dataclass
class Occurrence:
    path: str
    line: Optional[int]
    symbol: str


@dataclass
class ModelFile:
    path: str
    fmt: ModelFormat
    size: int
    sha256: str
    verified: bool                  # the signature matched, not just the extension
    detail: Dict[str, str] = field(default_factory=dict)


@dataclass
class EmbeddedModel:
    path: str
    line: int


@dataclass
class RuntimeHit:
    runtime: Runtime
    count: int = 0
    occurrences: List[Occurrence] = field(default_factory=list)


@dataclass
class AibomResult:
    root: str
    models: List[ModelFile]
    embedded: List[EmbeddedModel]
    runtimes: List[RuntimeHit]
    files_scanned: int = 0
    notes: List[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sniff(path: Path, head: bytes) -> Optional[Tuple[ModelFormat, bool]]:
    """The model format of a file and whether its signature (not just its name) says so."""
    suffix = path.suffix.lower()
    for fmt in FORMATS:
        if fmt.magic:
            offset, magic = fmt.magic
            if head[offset:offset + len(magic)] == magic:
                return fmt, True
    for fmt in FORMATS:
        if suffix in fmt.suffixes:
            return fmt, False
    return None


def _gguf_detail(head: bytes) -> Dict[str, str]:
    """``general.architecture`` and ``general.name`` from a GGUF header, when they fit in
    the bytes read. The key/value section is length-prefixed, so this walks it and stops at
    the first thing it cannot parse."""
    out: Dict[str, str] = {}
    try:
        version, = struct.unpack_from("<I", head, 4)
        out["gguf-version"] = str(version)
        _tensors, kv_count = struct.unpack_from("<QQ", head, 8)
        pos = 24
        sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
        for _ in range(min(kv_count, 64)):
            klen, = struct.unpack_from("<Q", head, pos)
            key = head[pos + 8:pos + 8 + klen].decode("utf-8", "replace")
            pos += 8 + klen
            vtype, = struct.unpack_from("<I", head, pos)
            pos += 4
            if vtype == 8:
                slen, = struct.unpack_from("<Q", head, pos)
                value = head[pos + 8:pos + 8 + slen].decode("utf-8", "replace")
                if len(head) < pos + 8 + slen:
                    break
                pos += 8 + slen
                if key in ("general.architecture", "general.name"):
                    out[key.split(".", 1)[1]] = value[:120]
            elif vtype in sizes:
                pos += sizes[vtype]
            else:
                break                       # an array or an unknown type: stop here
            if "architecture" in out and "name" in out:
                break
    except (struct.error, IndexError):
        pass
    return out


def _line_of(offsets: Sequence[int], pos: int) -> int:
    lo, hi = 0, len(offsets)
    while lo < hi:
        mid = (lo + hi) // 2
        if offsets[mid] < pos:
            lo = mid + 1
        else:
            hi = mid
    return lo + 1


def _scan_text(data: bytes, rel: str, runtimes: Dict[str, RuntimeHit],
               embedded: List[EmbeddedModel]) -> None:
    offsets: Optional[List[int]] = None
    for rt, regexes in _COMPILED:
        for regex in regexes:
            for m in regex.finditer(data):
                if offsets is None:
                    offsets = [x.start() for x in re.finditer(b"\n", data)]
                hit = runtimes.setdefault(rt.key, RuntimeHit(rt))
                hit.count += 1
                if len(hit.occurrences) < MAX_OCCURRENCES:
                    hit.occurrences.append(Occurrence(
                        rel, _line_of(offsets, m.start()),
                        m.group(0).decode("ascii", "replace")[:80]))
    m = _EMBEDDED_TFLITE.search(data)
    if m:
        if offsets is None:
            offsets = [x.start() for x in re.finditer(b"\n", data)]
        embedded.append(EmbeddedModel(rel, _line_of(offsets, m.start())))


def scan_aibom(root: Path, include_tests: bool = False) -> AibomResult:
    root = Path(root).resolve()
    models: List[ModelFile] = []
    embedded: List[EmbeddedModel] = []
    runtimes: Dict[str, RuntimeHit] = {}
    scanned = 0
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d.lower() not in DOC_DIRS)
        rel_parts = Path(here).relative_to(root).parts
        if not include_tests and any(p.lower() in FIXTURE_DIRS for p in rel_parts):
            continue
        for name in sorted(files):
            path = Path(here) / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            try:
                size = path.stat().st_size
                with open(path, "rb") as fh:
                    head = fh.read(HEAD_BYTES)
                sniffed = _sniff(path, head)
                if sniffed:
                    fmt, verified = sniffed
                    detail = _gguf_detail(head) if fmt.key == "gguf" else {}
                    models.append(ModelFile(rel, fmt, size, _sha256(path), verified, detail))
                    scanned += 1
                elif path.suffix.lower() in SOURCE_SUFFIXES and size <= MAX_TEXT_BYTES:
                    data = head if size <= HEAD_BYTES else path.read_bytes()
                    _scan_text(data, rel, runtimes, embedded)
                    scanned += 1
            except OSError:
                continue
    notes = [
        "Models and runtimes are found by file signature, extension or identifier, not by "
        "analysis. No compile database or link map is used, so a runtime named in a source "
        "file may not be part of the build.",
        "Training data, licence and intended use cannot be read from a model file; they are "
        "not filled in.",
    ]
    return AibomResult(str(root), models, embedded,
                       sorted(runtimes.values(), key=lambda h: h.runtime.key),
                       scanned, notes)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _model_component(m: ModelFile) -> Dict[str, Any]:
    props = [
        {"name": "gangmu:format", "value": m.fmt.key},
        {"name": "gangmu:bytes", "value": str(m.size)},
        {"name": "gangmu:detectedBy", "value": "file signature" if m.verified else "extension"},
    ]
    if m.fmt.note:
        props.append({"name": "gangmu:note", "value": m.fmt.note})
    comp: Dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": f"model/{m.path}",
        "name": m.detail.get("name") or Path(m.path).name,
        "hashes": [{"alg": "SHA-256", "content": m.sha256}],
        "evidence": {"occurrences": [{"location": m.path}]},
        "properties": props,
    }
    if m.detail.get("architecture"):
        comp["modelCard"] = {"modelParameters": {
            "architectureFamily": m.detail["architecture"]}}
    return comp


def _embedded_component(e: EmbeddedModel) -> Dict[str, Any]:
    return {
        "type": "machine-learning-model",
        "bom-ref": f"model/embedded/{e.path}",
        "name": f"TensorFlow Lite model compiled into {Path(e.path).name}",
        "evidence": {"occurrences": [{"location": e.path, "line": e.line}]},
        "properties": [
            {"name": "gangmu:format", "value": "tflite"},
            {"name": "gangmu:detectedBy", "value": "C array starting 0x54 0x46 0x4c 0x33 (TFL3)"},
        ],
    }


def _runtime_component(h: RuntimeHit) -> Dict[str, Any]:
    return {
        "type": "library",
        "bom-ref": f"runtime/{h.runtime.key}",
        "name": h.runtime.name,
        "evidence": {"occurrences": [
            {"location": o.path, **({"line": o.line} if o.line else {}), "symbol": o.symbol}
            for o in h.occurrences]},
        "properties": [
            {"name": "gangmu:role", "value": "inference-runtime"},
            {"name": "gangmu:hits", "value": str(h.count)},
        ],
    }


def to_aibom(result: AibomResult, app_name: str = "firmware",
             app_version: str = "") -> Dict[str, Any]:
    app: Dict[str, Any] = {"type": "firmware", "name": app_name, "bom-ref": "firmware"}
    if app_version:
        app["version"] = app_version
    comps = ([_model_component(m) for m in result.models]
             + [_embedded_component(e) for e in result.embedded]
             + [_runtime_component(h) for h in result.runtimes])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{"type": "application", "name": "gangmu",
                                      "version": __version__}]},
            "component": app,
            "properties": [{"name": "gangmu:aibom:note", "value": n} for n in result.notes],
        },
        "components": comps,
        "dependencies": [{"ref": "firmware", "dependsOn": [c["bom-ref"] for c in comps]}],
    }


def aibom_table(result: AibomResult) -> str:
    rows = [("KIND", "NAME", "DETAIL", "WHERE")]
    for m in result.models:
        extra = m.detail.get("architecture", "")
        rows.append(("model", m.fmt.name, f"{m.size} bytes" + (f", {extra}" if extra else "")
                     + ("" if m.verified else ", by extension"), m.path))
    for e in result.embedded:
        rows.append(("model", "TensorFlow Lite", "compiled into a C array", f"{e.path}:{e.line}"))
    for h in result.runtimes:
        first = h.occurrences[0]
        rows.append(("runtime", h.runtime.name, f"{h.count} hit(s)", f"{first.path}:{first.line}"))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    lines.append("")
    lines.append(f"{len(result.models) + len(result.embedded)} model(s), "
                 f"{len(result.runtimes)} runtime(s) over {result.files_scanned} file(s).")
    unsafe = [m for m in result.models if m.fmt.note]
    if unsafe:
        lines.append(f"{len(unsafe)} model file(s) use a pickle-based format that can run code "
                     "when loaded: " + ", ".join(m.path for m in unsafe[:5]))
    lines.extend(f"note: {n}" for n in result.notes)
    return "\n".join(lines)
