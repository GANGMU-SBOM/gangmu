"""``gangmu aibom``: models by signature or extension, runtimes by identifier."""
import json

import pytest
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


# --- the declaration file -------------------------------------------------------------

DECL = """\
version: 1
models:
  - path: models/kws.tflite
    name: Keyword spotter
    version: "1.2"
    supplier: ACME Audio
    license: Apache-2.0
    intended-use: Wake-word detection on a Cortex-M4
    limitations: [English only, "Degrades above 70 dB noise"]
    datasets:
      - name: Speech Commands v2
        url: https://example.org/speech-commands
        license: CC-BY-4.0
        personal-data: true
    metrics:
      - {type: accuracy, value: "0.94", unit: top-1}
  - path: models/chat.gguf
    license: Llama 3 Community License
  - sha256: "%s"
    name: Fetched at run time
    license: MIT
    datasets: [Internal corpus]
"""


def _declared(tmp: Path) -> Path:
    root = _tree(tmp)
    (root / "gangmu-aibom.yaml").write_text(DECL % ("ab" * 32))
    return root


def test_declarations_fill_the_model_card(tmp_path):
    from gangmu.aibom_decl import find_declarations, load_declarations
    root = _declared(tmp_path)
    decls = load_declarations(find_declarations(root))
    bom = to_aibom(scan_aibom(root, declarations=decls))
    kws = next(c for c in bom["components"] if c["bom-ref"] == "model/models/kws.tflite")
    assert kws["name"] == "Keyword spotter" and kws["version"] == "1.2"
    assert kws["supplier"] == {"name": "ACME Audio"}
    assert kws["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    card = kws["modelCard"]
    ds = card["modelParameters"]["datasets"][0]
    assert ds["name"] == "Speech Commands v2" and ds["sensitiveData"] == ["personal data"]
    assert card["considerations"]["technicalLimitations"][0] == "English only"
    assert card["quantitativeAnalysis"]["performanceMetrics"] == [
        {"type": "accuracy", "value": "0.94"}]
    assert {"name": "gangmu:declaredBy", "value": "declaration file"} in kws["properties"]
    # a licence that is not an SPDX id goes out as a name, not as a made-up id
    gguf = next(c for c in bom["components"] if c["bom-ref"] == "model/models/chat.gguf")
    assert gguf["licenses"] == [{"license": {"name": "Llama 3 Community License"}}]
    assert gguf["modelCard"]["modelParameters"]["architectureFamily"] == "llama"
    # an entry that matches nothing in the tree is kept, marked declaration-only
    only = next(c for c in bom["components"] if c["bom-ref"].startswith("model/declared/"))
    assert only["name"] == "Fetched at run time"
    assert {"name": "gangmu:detectedBy", "value": "declaration only"} in only["properties"]
    # the model with no entry is untouched
    onnx = next(c for c in bom["components"] if c["bom-ref"] == "model/models/net.onnx")
    assert "licenses" not in onnx and "declaredBy" not in json.dumps(onnx)


def test_declared_cyclonedx_validates_against_the_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    from gangmu.aibom_decl import find_declarations, load_declarations
    schemas = Path(__file__).resolve().parent / "fixtures" / "schemas"
    registry = Registry()
    for name, uri in (("spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"),
                      ("jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json")):
        registry = registry.with_resource(
            uri, Resource.from_contents(json.loads((schemas / name).read_text(encoding="utf-8"))))
    schema = json.loads((schemas / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    root = _declared(tmp_path)
    bom = to_aibom(scan_aibom(root, declarations=load_declarations(find_declarations(root))))
    errors = list(jsonschema.Draft7Validator(schema, registry=registry).iter_errors(bom))
    assert not errors, errors[0].message


def test_gaps_name_models_without_licence_or_training_data(tmp_path):
    from gangmu.aibom_decl import find_declarations, load_declarations
    root = _declared(tmp_path)
    result = scan_aibom(root, declarations=load_declarations(find_declarations(root)))
    gaps = result.gaps()
    assert "models/kws.tflite: no licence or training data declared" not in gaps
    assert "models/chat.gguf: no training data declared" in gaps
    assert "models/net.onnx: no licence or training data declared" in gaps
    assert not any("Fetched at run time" in g or "abababab" in g for g in gaps)


@pytest.mark.parametrize("text, message", [
    ("models: {}", "'models' must be a list"),
    ("models: [{name: x}]", "give a 'path'"),
    ("models: [{path: a, sha256: zz}]", "64 hex digits"),
    ("models: [{path: a, datasets: [{url: u}]}]", "needs a name"),
    ("models: [{path: a, metrics: [{type: t}]}]", "type and a value"),
    ("version: 2\nmodels: []", "unsupported version"),
])
def test_bad_declarations_are_rejected_with_a_reason(tmp_path, text, message):
    import pytest as _pytest
    from gangmu.aibom_decl import DeclarationError, load_declarations
    path = tmp_path / "gangmu-aibom.yaml"
    path.write_text(text)
    with _pytest.raises(DeclarationError, match=message):
        load_declarations(path)


def test_cli_picks_up_the_file_and_gates_on_gaps(tmp_path, capsys):
    root = _declared(tmp_path)
    assert main(["aibom", str(root)]) == 0
    out = capsys.readouterr().out
    assert "gap(s) in the declarations" in out and "declared only" in out
    assert main(["aibom", str(root), "--require-declarations"]) == 1
    err = capsys.readouterr().err
    assert "models/net.onnx: no licence or training data declared" in err
    # the gate needs a file to compare against
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "a.tflite").write_bytes(b"\x1c\0\0\0TFL3")
    assert main(["aibom", str(bare), "--require-declarations"]) == 2
    # a broken file is an error, not a silent skip
    (bare / "gangmu-aibom.yaml").write_text("models: 3")
    assert main(["aibom", str(bare)]) == 2
    assert "must be a list" in capsys.readouterr().err


def test_json_declaration_file_and_explicit_path(tmp_path):
    root = _tree(tmp_path)
    other = tmp_path / "elsewhere.json"
    other.write_text(json.dumps({"models": [{"path": "models/*.onnx", "license": "MIT",
                                            "datasets": ["ImageNet"]}]}))
    out = tmp_path / "out.json"
    assert main(["aibom", str(root), "--declarations", str(other),
                 "--format", "cyclonedx", "-o", str(out)]) == 0
    bom = json.loads(out.read_text())
    onnx = next(c for c in bom["components"] if c["bom-ref"] == "model/models/net.onnx")
    assert onnx["licenses"] == [{"license": {"id": "MIT"}}]
