"""Write small SquashFS 2.x / 3.x images for the tests, as squashfs-tools 3.4's
``squashfs_fs.h`` lays them out (squashfs-tools 2.x/3.x no longer build on current
systems). The reader is checked against real OpenWrt Kamikaze and White Russian images
as well; this keeps a regression test that needs no download.

Only what the tests need: regular files and directories, every table in one metadata
block (so the tree must stay small), file tails in one shared fragment.
"""

import lzma
import struct
import zlib
from typing import Callable, Dict, List, Tuple

BLOCK = 4096
LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}]

CODECS: Dict[str, Callable[[bytes], bytes]] = {
    "zlib": lambda b: zlib.compress(b, 9),
    "lzma": lambda b: lzma.compress(b, format=lzma.FORMAT_RAW, filters=LZMA_FILTERS),
    "lzma-alone": lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE),
    "lzma-props": lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE)[:5]
    + lzma.compress(b, format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 23}]),
}


def _pack(fields: List[Tuple[int, int, int]], size: int, big: bool) -> bytes:
    n = 0
    for pos, width, value in fields:
        assert value < 1 << width, (pos, width, value)
        n |= value << (size * 8 - pos - width if big else pos)
    return n.to_bytes(size, "big" if big else "little")


def build(files: Dict[str, bytes], major: int = 3, big: bool = False, codec: str = "zlib",
          magic: bytes = b"", check: bool = False, sqlzma: bool = False) -> bytes:
    """A SquashFS image holding *files* ({"usr/lib/opkg/status": b"..."})."""
    e = ">" if big else "<"
    compress = CODECS[codec]
    v3 = major == 3
    dirs: Dict[str, List[str]] = {"": []}
    for path in sorted(files):
        parts = path.split("/")
        for i in range(1, len(parts)):
            parent, here = "/".join(parts[:i - 1]), "/".join(parts[:i])
            if here not in dirs:
                dirs[here] = []
                dirs[parent].append(here)
        dirs["/".join(parts[:-1])].append(path)

    def packed(raw: bytes, n: int) -> Tuple[bytes, bool]:
        if sqlzma and n % 2:
            out = zlib.compress(raw, 9)          # sqlzma: some blocks stay zlib
        else:
            out = compress(raw)
        return (out, True) if len(out) < len(raw) else (raw, False)

    # data blocks and one shared fragment of file tails
    data = bytearray(b"\0" * 128)
    layout: Dict[str, Tuple[int, List[int], int, int, int]] = {}  # start, words, frag, off, size
    tails: List[bytearray] = [bytearray()]
    for i, path in enumerate(sorted(files)):
        body = files[path]
        start, words = len(data), []
        full = len(body) // BLOCK
        for b in range(full):
            out, ok = packed(body[b * BLOCK:(b + 1) * BLOCK], i + b)
            data += out
            words.append(len(out) | (0 if ok else 1 << 24))
        tail = body[full * BLOCK:]
        if tail and len(tails[-1]) + len(tail) > BLOCK:
            tails.append(bytearray())
        frag, frag_off = (len(tails) - 1, len(tails[-1])) if tail else (-1, 0)
        tails[-1] += tail
        layout[path] = (start, words, frag, frag_off, len(body))
    fragments = []                                         # (start, word) per fragment
    for i, chunk in enumerate(tails):
        frag_raw, ok = packed(bytes(chunk), i)
        fragments.append((len(data), len(frag_raw) | (0 if ok else 1 << 24)))
        data += frag_raw

    # directory listings (inode offsets filled in after the inodes are placed)
    def dir_listing(path: str, offsets: Dict[str, int], numbers: Dict[str, int]) -> bytes:
        names = sorted(dirs[path], key=lambda p: p.rsplit("/", 1)[-1])
        if not names:
            return b""
        out = bytearray()
        if v3:
            out += _pack([(0, 8, len(names) - 1), (8, 32, 0), (40, 32, numbers[names[0]])], 9, big)
        else:
            out += _pack([(0, 8, len(names) - 1), (8, 24, 0)], 4, big)
        for child in names:
            name = child.rsplit("/", 1)[-1].encode()
            kind = 1 if child in dirs else 2
            if v3:
                delta = numbers[child] - numbers[names[0]]
                out += _pack([(0, 13, offsets[child]), (13, 3, kind), (16, 8, len(name) - 1),
                              (24, 16, delta & 0xFFFF)], 5, big)
            else:
                out += _pack([(0, 13, offsets[child]), (13, 3, kind), (16, 8, len(name) - 1)],
                             3, big)
            out += name
        return bytes(out)

    order = sorted(dirs, key=len, reverse=True) + []       # children before parents
    everything = [p for p in sorted(files)] + order
    numbers = {p: i + 1 for i, p in enumerate(everything)}

    def inode(path: str, offsets: Dict[str, int], dir_at: Dict[str, Tuple[int, int]]) -> bytes:
        if path in dirs:
            size, at = dir_at[path]
            if v3:
                return _pack([(0, 4, 1), (4, 12, 0o755), (16, 8, 0), (24, 8, 0), (32, 32, 0),
                              (64, 32, numbers[path]), (96, 32, 2), (128, 19, size + 3),
                              (147, 13, at), (160, 32, 0), (192, 32, 0)], 28, big)
            return _pack([(0, 4, 1), (4, 12, 0o755), (16, 8, 0), (24, 8, 0), (32, 19, size),
                          (51, 13, at), (64, 32, 0), (96, 24, 0)], 15, big)
        start, words, frag, frag_off, size = layout[path]
        frag = frag if frag >= 0 else 0xFFFFFFFF
        if v3:
            head = _pack([(0, 4, 2), (4, 12, 0o644), (16, 8, 0), (24, 8, 0), (32, 32, 0),
                          (64, 32, numbers[path]), (96, 64, start), (160, 32, frag),
                          (192, 32, frag_off), (224, 32, size)], 32, big)
        else:
            head = _pack([(0, 4, 2), (4, 12, 0o644), (16, 8, 0), (24, 8, 0), (32, 32, 0),
                          (64, 32, start), (96, 32, frag), (128, 32, frag_off),
                          (160, 32, size)], 24, big)
        return head + b"".join(struct.pack(e + "I", w) for w in words)

    # place: inode sizes do not depend on offsets, listings' sizes do not either
    sizes = {p: len(inode(p, {q: 0 for q in everything}, {d: (0, 0) for d in dirs}))
             for p in everything}
    offsets, at = {}, 0
    for p in everything:
        offsets[p] = at
        at += sizes[p]
    dir_at, listing, pos = {}, bytearray(), 0
    for d in order:
        body = dir_listing(d, offsets, numbers)
        dir_at[d] = (len(body), pos)
        listing += body
        pos += len(body)
    inode_table = b"".join(inode(p, offsets, dir_at) for p in everything)
    assert len(inode_table) <= 8192 and len(listing) <= 8192

    def metadata(raw: bytes) -> bytes:
        out = compress(raw)
        word = len(out) if len(out) < len(raw) else len(raw) | 0x8000
        body = out if len(out) < len(raw) else raw
        return struct.pack(e + "H", word) + (b"\xff" if check else b"") + body

    inode_start = len(data)
    data += metadata(inode_table)
    dir_start = len(data)
    data += metadata(bytes(listing))
    frag_table_block = len(data)
    if v3:
        data += metadata(b"".join(struct.pack(e + "QII", s, w, 0) for s, w in fragments))
    else:
        data += metadata(b"".join(struct.pack(e + "II", s, w) for s, w in fragments))
    frag_index = len(data)
    data += struct.pack(e + ("Q" if v3 else "I"), frag_table_block)
    uid_start = len(data)
    data += struct.pack(e + "I", 0)
    used = len(data)
    root = offsets[""]
    sb = bytearray(128)
    struct.pack_into(e + "I", sb, 0, 0x73717368)
    struct.pack_into(e + "6I", sb, 4, len(everything), used, uid_start, uid_start,
                     inode_start, dir_start)
    struct.pack_into(e + "4H", sb, 28, major, 1 if major == 2 else 0, 0, 12)
    sb[36] = 0x40 | (4 if check else 0)
    sb[37], sb[38] = 1, 0
    struct.pack_into(e + "I", sb, 39, 0)
    struct.pack_into(e + "Q", sb, 43, root)
    struct.pack_into(e + "3I", sb, 51, BLOCK, len(fragments), frag_index)
    if v3:
        struct.pack_into(e + "7q", sb, 63, used, uid_start, uid_start, inode_start, dir_start,
                         frag_index, uid_start)
    if magic:
        sb[0:4] = magic
    data[0:128] = sb
    return bytes(data)
