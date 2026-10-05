import json
import shutil

from gangmu.cli import main
from gangmu.licenses import (cyclonedx_licenses, detect_license_text, differs,
                             expression_ids, observe, observed_license_ids,
                             parse_spdx_headers, spdx_license_declared)

MIT = """MIT License

Copyright (c) 2020 Someone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
"""
BSD3 = """Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software."""


def test_header_parsing_handles_comment_styles():
    assert parse_spdx_headers("/* SPDX-License-Identifier: Apache-2.0 */\n") == ["Apache-2.0"]
    assert parse_spdx_headers("// SPDX-License-Identifier: MIT OR Apache-2.0\nint x;") == ["MIT OR Apache-2.0"]
    assert parse_spdx_headers("# SPDX-License-Identifier: GPL-2.0-only\n") == ["GPL-2.0-only"]
    assert parse_spdx_headers("no licence here") == []


def test_expression_ids():
    assert expression_ids("(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0") \
        == ["MIT", "Apache-2.0", "GPL-2.0-only", "Classpath-exception-2.0"]


def test_licence_text_only_recognises_the_unmistakable():
    assert detect_license_text(MIT) == "MIT"
    assert detect_license_text(BSD3) == "BSD-3-Clause"
    assert detect_license_text("GNU GENERAL PUBLIC LICENSE Version 2, June 1991") is None
    assert detect_license_text("Apache License\nVersion 2.0, January 2004") == "Apache-2.0"


def test_observe_reads_headers_and_the_licence_file(tmp_path):
    (tmp_path / "LICENSE").write_text(MIT)
    (tmp_path / "a.c").write_text("/* SPDX-License-Identifier: BSD-3-Clause */\n")
    (tmp_path / "b.c").write_text("/* SPDX-License-Identifier: BSD-3-Clause */\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.h").write_text("// SPDX-License-Identifier: GPL-2.0-only\n")
    (tmp_path / "notes.txt").write_text("SPDX-License-Identifier: WTFPL\n")   # not source
    headers, files = observe(tmp_path)
    assert headers == ["BSD-3-Clause", "GPL-2.0-only"]      # most common first
    assert files == {"LICENSE": "MIT"}
    assert observed_license_ids(headers, files) == ["BSD-3-Clause", "GPL-2.0-only", "MIT"]


def test_differs_only_when_the_tree_shows_something_new():
    assert not differs("MIT", ["MIT"])
    assert not differs("Apache-2.0 OR MIT", ["MIT", "Apache-2.0"])
    assert differs("Apache-2.0", ["Apache-2.0", "GPL-2.0-only"])
    assert not differs(None, ["GPL-2.0-only"])      # nothing declared, nothing to contradict


def test_cyclonedx_licences_follow_the_schema_shapes():
    assert cyclonedx_licenses("MIT", [], {}) == [{"license": {"id": "MIT"}}]
    assert cyclonedx_licenses(None, ["MIT"], {}) == \
        [{"license": {"id": "MIT", "acknowledgement": "declared"}}]
    out = cyclonedx_licenses(None, ["MIT OR Apache-2.0", "BSD-3-Clause"], {})
    assert out == [{"expression": "(MIT OR Apache-2.0) AND BSD-3-Clause",
                    "acknowledgement": "declared"}]
    assert cyclonedx_licenses(None, [], {}) == []
    assert cyclonedx_licenses(None, [], {"LICENSE": "ISC"}) == \
        [{"license": {"id": "ISC", "acknowledgement": "declared"}}]


def test_spdx_declared_falls_back_to_the_tree():
    assert spdx_license_declared("MIT", ["GPL-2.0-only"], {}) == "MIT"
    assert spdx_license_declared(None, ["MIT", "GPL-2.0-only"], {}) == "MIT AND GPL-2.0-only"
    assert spdx_license_declared(None, [], {}) == "NOASSERTION"


def _tinynet(project_dir):
    return next(p for p in project_dir.rglob("tinynet") if p.is_dir())


def test_scan_reports_what_the_files_say(project_dir, rules_dir, tmp_path):
    proj = tmp_path / "proj"
    shutil.copytree(project_dir, proj)
    src = next(_tinynet(proj).rglob("*.c"))
    src.write_text("/* SPDX-License-Identifier: GPL-2.0-only */\n" + src.read_text())
    out = tmp_path / "bom.json"
    assert main(["scan", str(proj), "--rules", str(rules_dir), "--format", "cyclonedx",
                 "-o", str(out)]) == 0
    comp = next(c for c in json.loads(out.read_text())["components"] if c["name"] == "tinynet")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert "GPL-2.0-only" in props["gangmu:observedLicenses"]
    assert props["gangmu:licenseDiffersFromRule"] == "true"
    assert comp["licenses"] == [{"license": {"id": "MIT"}}]       # the rule's licence stays


def test_no_licenses_skips_reading(project_dir, rules_dir, tmp_path):
    proj = tmp_path / "proj"
    shutil.copytree(project_dir, proj)
    src = next(_tinynet(proj).rglob("*.c"))
    src.write_text("/* SPDX-License-Identifier: GPL-2.0-only */\n" + src.read_text())
    out = tmp_path / "bom.json"
    assert main(["scan", str(proj), "--rules", str(rules_dir), "--format", "cyclonedx",
                 "--no-licenses", "-o", str(out)]) == 0
    comp = next(c for c in json.loads(out.read_text())["components"] if c["name"] == "tinynet")
    assert "gangmu:observedLicenses" not in {p["name"] for p in comp["properties"]}
