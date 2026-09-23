"""Byte-wise Shamir sharing over GF(2^8), reduction polynomial 0x11b (PROTOCOL.md §3).

Multiplication by a constant is a 256-entry byte map, so whole payloads are
processed with ``bytes.translate`` and integer XOR instead of per-byte loops.
"""

import secrets
from collections.abc import Callable, Sequence

_POLY = 0x11B
_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    value = 1
    for i in range(255):
        _EXP[i] = value
        _LOG[value] = i
        doubled = value << 1
        if doubled & 0x100:
            doubled ^= _POLY
        value = doubled ^ value  # multiply by the generator 3
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8).")
    return _EXP[255 - _LOG[a]]


_MUL_TABLES = [bytes(mul(c, v) for v in range(256)) for c in range(256)]


def _scale(constant: int, data: bytes) -> bytes:
    return data.translate(_MUL_TABLES[constant])


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def split(
    payload: bytes,
    threshold: int,
    count: int,
    *,
    coefficients: Callable[[int], bytes] = secrets.token_bytes,
) -> list[tuple[int, bytes]]:
    """Share ``payload`` into ``count`` shares, any ``threshold`` of which recover it.

    ``coefficients(n)`` must return ``n`` uniformly random bytes; it is called
    ``threshold - 1`` times, for c_1 first through c_{k-1} last. Only tests may
    replace it.
    """
    if not isinstance(payload, bytes):
        raise TypeError("Payload must be bytes.")
    if type(threshold) is not int or type(count) is not int or not 2 <= threshold <= count <= 255:
        raise ValueError("Require 2 <= threshold <= count <= 255.")
    coeffs = [coefficients(len(payload)) for _ in range(threshold - 1)]
    if any(not isinstance(c, bytes) or len(c) != len(payload) for c in coeffs):
        raise ValueError("Coefficient source returned the wrong length.")
    shares = []
    for index in range(1, count + 1):
        value = bytes(len(payload))
        for coefficient in reversed(coeffs):  # Horner from c_{k-1} down to c_1
            value = _xor(_scale(index, value), coefficient)
        shares.append((index, _xor(_scale(index, value), payload)))
    return shares


def combine(points: Sequence[tuple[int, bytes]]) -> bytes:
    """Interpolate the polynomial's constant term from distinct points.

    Every supplied point is used; the caller chooses the subset. A wrong or
    insufficient set returns wrong bytes without error, so callers must check
    the payload digest.
    """
    if not points:
        raise ValueError("No points supplied.")
    indices = [index for index, _ in points]
    if any(type(i) is not int or not 1 <= i <= 255 for i in indices):
        raise ValueError("Share indices must be integers from 1 to 255.")
    if len(set(indices)) != len(indices):
        raise ValueError("Duplicate share index.")
    length = len(points[0][1])
    if any(not isinstance(y, bytes) or len(y) != length for _, y in points):
        raise ValueError("Share values must be bytes of equal length.")
    result = bytes(length)
    for x_j, y_j in points:
        weight = 1
        for x_m in indices:
            if x_m != x_j:
                weight = mul(weight, mul(x_m, inv(x_m ^ x_j)))
        result = _xor(result, _scale(weight, y_j))
    return result
