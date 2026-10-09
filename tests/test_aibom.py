"""``gangmu aibom``: models by signature or extension, runtimes by identifier."""
import json
import struct
from pathlib import Path

from gangmu.aibom import scan_aibom, to_aibom
from gangmu.cli import main


def _gguf() -> bytes:
    def s(text: str) -> bytes:
        raw = text.encode()
        return struct.pack("<Q", len(raw)) + raw

    kv = (s("general.architecture") + struct.pack("<I", 8) + s("llama")
          + s("general.name") + struct.pack("<I", 8) + s("tiny-test"))
    return b"GGUF" + struct.pack("<IQQ", 3, 0, 2) + kv + b"\0" * 64


def _tree(tmp: Path) -> Path:
    (tmp / "models").mkdir()
    (tmp / "models" / "kws.tflite").write_bytes(b"\x1c\0\0\0TFL3" + b"\0" * 32)
    (tmp / "models" / "chat.gguf").write_bytes(_gguf())
    (tmp / "models" / "net.onnx").write_bytes(b"\x08\x07" + b"\0" * 16)
    (tmp / "models" / "old.pt").write_bytes(b"PK\x03\x04" + b"\0" * 16)
    (tmp / "readme.txt").write_text("not a model")
    (tmp / "src").mkdir()
    (tmp / "src" / "main.cc").write_text(
        '#include "tensorflow/lite/micro/micro_interpreter.h"\n'
        "tflite::MicroInterpreter interp(model, resolver, arena, kArenaSize);\n"
        "arm_fully_connected_s8(0);\n")
    (tmp / "src" / "model_data.cc").write_text(
        "const unsigned char g_model[] = {\n 0x1c, 0x00, 0x00, 0x00, 0x54, 0x46, 0x4c, 0x33,\n};\n")
    return tmp


def test_models_found_by_signature_and_extension(tmp_path):
    result = scan_aibom(_tree(tmp_path))
    by = {m.path: m for m in result.models}
    assert set(by) == {"models/kws.tflite", "models/chat.gguf", "models/net.onnx",
                       "models/old.pt"}
    assert by["models/kws.tflite"].verified and by["models/chat.gguf"].verified
    assert not by["models/net.onnx"].verified          # extension only
    assert len(by["models/kws.tflite"].sha256) == 64
    assert by["models/chat.gguf"].detail["architecture"] == "llama"
    assert by["models/chat.gguf"].detail["name"] == "tiny-test"


def test_runtimes_and_embedded_model(tmp_path):
    result = scan_aibom(_tree(tmp_path))
    assert {h.runtime.key for h in result.runtimes} == {"tflite-micro", "cmsis-nn"}
    micro = next(h for h in result.runtimes if h.runtime.key == "tflite-micro")
    assert micro.occurrences[0].path == "src/main.cc" and micro.occurrences[0].line == 1
    assert [(e.path, e.line) for e in result.embedded] == [("src/model_data.cc", 2)]


def test_cyclonedx_output(tmp_path):
    bom = to_aibom(scan_aibom(_tree(tmp_path)), "fw", "1.0")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    types = [c["type"] for c in bom["components"]]
    assert types.count("machine-learning-model") == 5     # 4 files + 1 compiled in
    assert types.count("library") == 2
    gguf = next(c for c in bom["components"] if c["bom-ref"] == "model/models/chat.gguf")
    assert gguf["name"] == "tiny-test"
    assert gguf["modelCard"]["modelParameters"]["architectureFamily"] == "llama"
    assert gguf["hashes"][0]["alg"] == "SHA-256"
    pt = next(c for c in bom["components"] if c["bom-ref"] == "model/models/old.pt")
    assert any("can run code" in p["value"] for p in pt["properties"])
    refs = {c["bom-ref"] for c in bom["components"]}
    assert set(bom["dependencies"][0]["dependsOn"]) == refs
    assert any("Training data" in p["value"] for p in bom["metadata"]["properties"])


def test_a_tree_without_models_is_empty_not_an_error(tmp_path):
    (tmp_path / "a.c").write_text("int main(void) { return 0; }\n")
    result = scan_aibom(tmp_path)
    assert not result.models and not result.runtimes and not result.embedded


def test_truncated_gguf_does_not_crash(tmp_path):
    (tmp_path / "bad.gguf").write_bytes(b"GGUF\x03\x00")
    result = scan_aibom(tmp_path)
    assert result.models[0].detail == {}


def test_cli_table_json_and_missing_dir(tmp_path, capsys):
    root = _tree(tmp_path)
    assert main(["aibom", str(root)]) == 0
    text = capsys.readouterr().out
    assert "TensorFlow Lite Micro" in text and "5 model(s), 2 runtime(s)" in text
    assert "pickle-based" in text
    out = tmp_path / "ai.cdx.json"
    assert main(["aibom", str(root), "--format", "cyclonedx", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"
    assert main(["aibom", str(tmp_path / "nope")]) == 2
