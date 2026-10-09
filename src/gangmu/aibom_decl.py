"""The AIBOM declaration file: what a model file cannot say about itself.

Training data, licence, intended use and evaluation results are not in a ``.tflite`` or
``.gguf``. A person who knows them writes them down once, in ``gangmu-aibom.yaml`` (or
``.yml`` / ``.json``) at the root of the tree, and ``gangmu aibom`` merges them into the
model it found. Nothing here is checked against the model; it is the supplier's statement,
and the output says so (``gangmu:declaredBy``).

An entry names the model by ``path`` (a glob against the path relative to the root) or by
``sha256``; if it names a model that is not in the tree (one fetched at run time) it is kept
as a *declared-only* component, so the document still records it.
"""
import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

DEFAULT_NAMES = ("gangmu-aibom.yaml", "gangmu-aibom.yml", "gangmu-aibom.json")

_TEXT_FIELDS = ("name", "version", "supplier", "description", "url", "base-model")
_LIST_FIELDS = ("intended-use", "users", "limitations", "ethical-considerations")
_SPDX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_SPDX_EXPR = re.compile(r"\s(AND|OR|WITH)\s")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class DeclarationError(ValueError):
    pass


@dataclass
class Dataset:
    name: str
    url: str = ""
    license: str = ""
    description: str = ""
    personal_data: Optional[bool] = None


@dataclass
class Metric:
    type: str
    value: str
    unit: str = ""


@dataclass
class ModelDeclaration:
    index: int
    path: str = ""
    sha256: str = ""
    name: str = ""
    version: str = ""
    supplier: str = ""
    description: str = ""
    url: str = ""
    base_model: str = ""
    license: str = ""
    intended_use: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    ethical_considerations: List[str] = field(default_factory=list)
    datasets: List[Dataset] = field(default_factory=list)
    metrics: List[Metric] = field(default_factory=list)
    used: bool = False

    def matches(self, rel_path: str, sha256: str) -> bool:
        if self.sha256 and self.sha256.lower() == sha256.lower():
            return True
        return bool(self.path) and fnmatch.fnmatchcase(rel_path, self.path)

    @property
    def label(self) -> str:
        return self.path or self.sha256[:12] or self.name or f"#{self.index}"

    def has_license(self) -> bool:
        return bool(self.license)

    def has_training_data(self) -> bool:
        return bool(self.datasets)


@dataclass
class Declarations:
    source: str
    models: List[ModelDeclaration]

    def find(self, rel_path: str, sha256: str) -> Optional[ModelDeclaration]:
        for decl in self.models:
            if decl.matches(rel_path, sha256):
                decl.used = True
                return decl
        return None

    def unmatched(self) -> List[ModelDeclaration]:
        return [d for d in self.models if not d.used]


def _text(entry: Dict[str, Any], key: str, where: str) -> str:
    value = entry.get(key, "")
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        raise DeclarationError(f"{where}: '{key}' must be text")
    return str(value).strip()


def _texts(entry: Dict[str, Any], key: str, where: str) -> List[str]:
    value = entry.get(key)
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out = []
    for item in items:
        if isinstance(item, (dict, list)):
            raise DeclarationError(f"{where}: '{key}' must be text or a list of text")
        if str(item).strip():
            out.append(str(item).strip())
    return out


def _dataset(raw: Any, where: str) -> Dataset:
    if isinstance(raw, str):
        raw = {"name": raw}
    if not isinstance(raw, dict) or not str(raw.get("name", "")).strip():
        raise DeclarationError(f"{where}: each dataset needs a name")
    personal = raw.get("personal-data")
    if personal is not None and not isinstance(personal, bool):
        raise DeclarationError(f"{where}: 'personal-data' must be true or false")
    return Dataset(str(raw["name"]).strip(), _text(raw, "url", where),
                   _text(raw, "license", where), _text(raw, "description", where), personal)


def _metric(raw: Any, where: str) -> Metric:
    if not isinstance(raw, dict) or not str(raw.get("type", "")).strip() \
            or raw.get("value") is None:
        raise DeclarationError(f"{where}: each metric needs a type and a value")
    return Metric(str(raw["type"]).strip(), str(raw["value"]), _text(raw, "unit", where))


def parse_declarations(data: Any, source: str = "declarations") -> Declarations:
    if not isinstance(data, dict):
        raise DeclarationError(f"{source}: the top level must be a mapping with a 'models' list")
    if data.get("version", 1) != 1:
        raise DeclarationError(f"{source}: unsupported version {data.get('version')!r}")
    raw_models = data.get("models")
    if not isinstance(raw_models, list):
        raise DeclarationError(f"{source}: 'models' must be a list")
    models: List[ModelDeclaration] = []
    for i, entry in enumerate(raw_models, 1):
        where = f"{source}: models[{i}]"
        if not isinstance(entry, dict):
            raise DeclarationError(f"{where}: must be a mapping")
        path = _text(entry, "path", where)
        digest = _text(entry, "sha256", where)
        if not path and not digest:
            raise DeclarationError(f"{where}: give a 'path' (glob) or a 'sha256' to say which model")
        if digest and not _SHA256.match(digest):
            raise DeclarationError(f"{where}: 'sha256' must be 64 hex digits")
        text = {k: _text(entry, k, where) for k in _TEXT_FIELDS}
        models.append(ModelDeclaration(
            index=i, path=path.replace("\\", "/").lstrip("./") if path else "", sha256=digest,
            name=text["name"], version=text["version"], supplier=text["supplier"],
            description=text["description"], url=text["url"], base_model=text["base-model"],
            license=_text(entry, "license", where),
            intended_use=_texts(entry, "intended-use", where),
            users=_texts(entry, "users", where),
            limitations=_texts(entry, "limitations", where),
            ethical_considerations=_texts(entry, "ethical-considerations", where),
            datasets=[_dataset(d, where) for d in entry.get("datasets") or []],
            metrics=[_metric(m, where) for m in entry.get("metrics") or []]))
    return Declarations(source, models)


def load_declarations(path: Path) -> Declarations:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DeclarationError(f"{path}: cannot read: {exc}") from exc
    try:
        if str(path).lower().endswith(".json"):
            data = json.loads(text)
        else:
            import yaml
            data = yaml.safe_load(text)
    except Exception as exc:                      # yaml.YAMLError, json.JSONDecodeError
        raise DeclarationError(f"{path}: not valid {'JSON' if str(path).endswith('json') else 'YAML'}: {exc}") from exc
    return parse_declarations(data, Path(path).name)


def find_declarations(root: Path, names: Sequence[str] = DEFAULT_NAMES) -> Optional[Path]:
    for name in names:
        candidate = Path(root) / name
        if candidate.is_file():
            return candidate
    return None


def license_entry(text: str) -> Dict[str, Any]:
    """A CycloneDX licence choice from what a person wrote: an SPDX id the schema knows, an
    SPDX expression, or (for anything else, such as a model-specific licence) a free-text
    name, which the schema accepts for any string."""
    from .licenses import COMMON_IDS

    text = text.strip()
    if text in COMMON_IDS:
        return {"license": {"id": text}}
    if _SPDX_EXPR.search(text) and all(
            _SPDX_ID.match(t) for t in re.split(r"\s+|[()]", text) if t):
        return {"expression": text}
    return {"license": {"name": text}}
