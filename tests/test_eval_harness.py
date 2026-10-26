"""The mutation benchmark must make the changes a vendor makes, and no others."""

from gangmu.eval.harness import Mutation, mutate_tree
from gangmu.functions import extract_functions

SOURCE = (b"static unsigned int helper_value(unsigned int counter) {\n"
          b"    struct packet_header header;\n"
          b"    switch (counter) { default: break; }\n"
          b"    return sizeof(header) + counter;\n"
          b"}\n")


def test_a_rename_never_touches_the_language(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_bytes(SOURCE)
    mutate_tree(src, tmp_path / "out", Mutation(rename_ratio=1.0), seed=1)
    out = (tmp_path / "out" / "a.c").read_bytes()
    for keyword in (b"static", b"unsigned", b"struct", b"switch", b"default",
                    b"return", b"sizeof"):
        assert b"vnd_" + keyword not in out
    assert b"vnd_helper_value" in out and b"vnd_counter" in out
    # Every name renamed and no keyword touched: the abstracted body is unchanged.
    [before], [after] = extract_functions(SOURCE), extract_functions(out)
    assert before.hash != after.hash and before.abstract_hash == after.abstract_hash
