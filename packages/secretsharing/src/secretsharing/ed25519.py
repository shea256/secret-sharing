"""Pure-Python Ed25519 (RFC 8032, PureEdDSA, no context) for signature algorithm 1.

Signing keys are generated per backup, used once, and discarded, so this
implementation's non-constant-time arithmetic is acceptable; verification
touches only public data. Cross-checked against RFC 8032 vectors and pyca.
"""

import hashlib
import secrets

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, -1, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P:
        raise ValueError("Point is not on the curve.")
    return _P - x if x & 1 else x  # the even root, as in RFC 8032


def _add(a: Point, b: Point) -> Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _mul(scalar: int, point: Point) -> Point:
    result: Point = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


_BY = 4 * pow(5, -1, _P) % _P
_BX = _x_recover(_BY)
_B: Point = (_BX, _BY, 1, _BX * _BY % _P)


def _encode(point: Point) -> bytes:
    x, y, z, _ = point
    inv_z = pow(z, -1, _P)
    x, y = x * inv_z % _P, y * inv_z % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(data: bytes) -> Point:
    if len(data) != 32:
        raise ValueError("Invalid point length.")
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("Invalid point.")
    x = _x_recover(y)
    if x & 1 != sign:
        x = _P - x
    if x == 0 and sign:
        raise ValueError("Invalid point.")
    return x, y, 1, x * y % _P


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def generate_seed() -> bytes:
    return secrets.token_bytes(32)


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Seed must be 32 bytes.")
    scalar, _ = _expand(seed)
    return _encode(_mul(scalar, _B))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Seed must be 32 bytes.")
    scalar, prefix = _expand(seed)
    public = _encode(_mul(scalar, _B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_encoded = _encode(_mul(r, _B))
    k = int.from_bytes(hashlib.sha512(r_encoded + public + message).digest(), "little") % _L
    return r_encoded + ((r + k * scalar) % _L).to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        point_a = _decode(public)
        point_r = _decode(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _encode(_mul(s, _B)) == _encode(_add(point_r, _mul(k, point_a)))
