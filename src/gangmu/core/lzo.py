"""LZO1X decompression in pure Python.

UBIFS compresses with LZO by default, and JFFS2 and SquashFS images use it too; the
``python-lzo`` binding needs the native library to build, which most machines lack. This
is a port of ``lzo1x_decompress_safe`` (minilzo's ``lzo1x_d.ch``): every read and every
back-reference is bounds-checked, and the output never grows past the size the caller
gives, so corrupt input raises ``LzoError`` instead of running away.
"""

from __future__ import annotations


class LzoError(ValueError):
    pass


def decompress(src: bytes, size: int) -> bytes:
    """Decompress one LZO1X block whose decompressed size is at most *size*."""
    out = bytearray()
    n = len(src)
    ip = 0

    def need(k: int) -> None:
        if ip + k > n:
            raise LzoError("input overrun")

    def copy_match(dist: int, length: int) -> None:
        start = len(out) - dist
        if start < 0:
            raise LzoError("back-reference before the start")
        if len(out) + length > size:
            raise LzoError("output overrun")
        if dist >= length:
            out.extend(out[start:start + length])
        else:
            for i in range(length):
                out.append(out[start + i])

    def copy_literals(count: int) -> None:
        nonlocal ip
        need(count)
        if len(out) + count > size:
            raise LzoError("output overrun")
        out.extend(src[ip:ip + count])
        ip += count

    def extended(t: int, base: int) -> int:
        nonlocal ip
        while True:
            need(1)
            if src[ip] != 0:
                break
            t += 255
            ip += 1
            if t > size + 255:
                raise LzoError("length overrun")
        t += base + src[ip]
        ip += 1
        return t

    need(1)
    state = "literal"
    t = 0
    if src[0] > 17:
        t = src[0] - 17
        ip = 1
        if t < 4:
            state = "match_next"
        else:
            copy_literals(t)
            state = "first_literal"
    while True:
        if state == "literal":
            need(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                state = "match"
                continue
            if t == 0:
                t = extended(t, 15)
            copy_literals(t + 3)
            state = "first_literal"
            continue
        if state == "first_literal":
            need(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                state = "match"
                continue
            need(1)
            dist = 1 + 0x0800 + (t >> 2) + (src[ip] << 2)
            ip += 1
            copy_match(dist, 3)
            state = "match_done"
            continue
        if state == "match":
            if t >= 64:
                need(1)
                dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                ip += 1
                copy_match(dist, (t >> 5) + 1)
            elif t >= 32:
                t &= 31
                if t == 0:
                    t = extended(t, 31)
                need(2)
                dist = 1 + (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                copy_match(dist, t + 2)
            elif t >= 16:
                high = (t & 8) << 11
                t &= 7
                if t == 0:
                    t = extended(t, 7)
                need(2)
                dist = high + (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                if dist == 0:
                    return bytes(out)                    # end of stream
                copy_match(dist + 0x4000, t + 2)
            else:
                need(1)
                dist = 1 + (t >> 2) + (src[ip] << 2)
                ip += 1
                copy_match(dist, 2)
            state = "match_done"
            continue
        if state == "match_done":
            t = src[ip - 2] & 3
            if t == 0:
                state = "literal"
                continue
            state = "match_next"
            continue
        # match_next: 1 to 3 literals, then a match
        copy_literals(t)
        need(1)
        t = src[ip]
        ip += 1
        state = "match"
