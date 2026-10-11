"""Reproducible documents: ``SOURCE_DATE_EPOCH``.

By default a document gets the current time and a random id (CycloneDX asks for a
fresh serial number per BOM). With ``SOURCE_DATE_EPOCH`` set, as reproducible builds
do (https://reproducible-builds.org/specs/source-date-epoch/), the time is that
moment and the id is derived from the document's content, so the same input gives
byte-identical output, which a signature or an evidence bundle can be re-checked
against.

A writer puts :data:`ID_PLACEHOLDER` wherever the id goes and passes the finished
document through :func:`fill_document_id`.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import uuid
from typing import Any, Dict, Optional

ID_PLACEHOLDER = "00000000-0000-0000-0000-67616e676d75"     # "gangmu", never random
# Fixed namespace for content-derived ids (uuid5).
_NAMESPACE = uuid.UUID("5b0b2a8e-4f39-5d1e-9a43-6a1f0e9c7d21")


def source_date_epoch() -> Optional[_dt.datetime]:
    """``SOURCE_DATE_EPOCH`` as a UTC time, ``None`` when unset or not a number."""
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not raw:
        return None
    try:
        return _dt.datetime.fromtimestamp(int(raw), _dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def timestamp() -> str:
    """The document time: ``SOURCE_DATE_EPOCH`` if set, else now (UTC, seconds)."""
    moment = source_date_epoch() or _dt.datetime.now(_dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def fill_document_id(doc: Dict[str, Any]) -> Dict[str, Any]:
    """*doc* with every :data:`ID_PLACEHOLDER` replaced by its id.

    The id is random, or with ``SOURCE_DATE_EPOCH`` set a uuid5 of the document as
    written with the placeholder still in it.
    """
    text = json.dumps(doc, ensure_ascii=False)
    if ID_PLACEHOLDER not in text:
        return doc
    if source_date_epoch() is not None:
        canonical = json.dumps(doc, sort_keys=True, ensure_ascii=False)
        value = uuid.uuid5(_NAMESPACE, canonical)
    else:
        value = uuid.uuid4()
    return json.loads(text.replace(ID_PLACEHOLDER, str(value)))
