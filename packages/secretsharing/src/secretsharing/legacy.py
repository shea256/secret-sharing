"""Explicit recovery of unversioned shares; never creates new legacy shares.

Original field and length may be unknowable. Only an independent reference
can mark a candidate verified. There is intentionally no automatic fallback.
"""

import hashlib
import hmac
import string
from dataclasses import dataclass, field

from .errors import InvalidShare, DuplicateShare, RecoveryError
from .primes import STANDARD_PRIMES, is_probable_prime

HEX = "0123456789abcdef"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
FORMATS = {"hex": (HEX, HEX), "text": (HEX, string.printable),
           "bitcoin-b58": (BASE58, BASE58), "bitcoin-b32": (BASE32, BASE58),
           "bitcoin-zb32": (ZBASE32, BASE58)}


@dataclass(frozen=True)
class LegacyResult:
    secret: str = field(repr=False)
    verified: bool
    inferred_prime: bool


def _charset(charset, *, share=False):
    if (not isinstance(charset, str) or not 2 <= len(charset) <= 256
            or len(set(charset)) != len(charset) or (share and "-" in charset)):
        raise ValueError("Invalid legacy character set.")


def _to_int(text, charset):
    if not text or any(c not in charset for c in text):
        raise InvalidShare("Empty or invalid legacy share coordinate.")
    value = 0
    for character in text:
        value = value * len(charset) + charset.index(character)
        if value.bit_length() > 1280:
            raise InvalidShare("Legacy coordinate exceeds the supported field size.")
    return value


def _to_string(value, charset):
    if value == 0:
        return charset[0]
    digits = []
    while value:
        value, digit = divmod(value, len(charset))
        digits.append(charset[digit])
    return "".join(reversed(digits))


def recover_secret(shares, *, format="hex", prime=None, original_length=None,
                   expected_sha256=None, share_charset=None, secret_charset=None) -> LegacyResult:
    if not isinstance(shares, (list, tuple)) or not 2 <= len(shares) <= 255:
        raise InvalidShare("Supply between 2 and 255 legacy share strings.")
    if format not in FORMATS:
        raise ValueError("Unknown legacy format.")
    default_share, default_secret = FORMATS[format]
    share_charset = default_share if share_charset is None else share_charset
    secret_charset = default_secret if secret_charset is None else secret_charset
    _charset(share_charset, share=True)
    _charset(secret_charset)
    points = []
    indices = set()
    for share in shares:
        if not isinstance(share, str) or len(share) > 16384 or share.count("-") != 1:
            raise InvalidShare("Invalid legacy share format.")
        x_string, y_string = share.split("-")
        x, y = _to_int(x_string, share_charset), _to_int(y_string, share_charset)
        if x == 0:
            raise InvalidShare("Legacy share indices must be nonzero.")
        if x in indices:
            raise DuplicateShare("Duplicate legacy share index.")
        indices.add(x)
        points.append((x, y))
    inferred = prime is None
    if inferred:
        # Deliberately preserve historical >= selection for legacy decoding.
        prime = next((p for p in STANDARD_PRIMES if max(y for _, y in points) <= p), None)
    if (type(prime) is not int or prime < 3 or prime.bit_length() > 1280
            or (prime not in STANDARD_PRIMES and not is_probable_prime(prime))):
        raise InvalidShare("Supply a valid original prime (at most 1280 bits).")
    if any(not 1 <= x < prime or not 0 <= y < prime for x, y in points):
        raise InvalidShare("Coordinates do not fit the original field; supply the correct prime.")
    value = 0
    for i, (x, y) in enumerate(points):
        numerator = denominator = 1
        for j, (other_x, _) in enumerate(points):
            if i != j:
                numerator = numerator * -other_x % prime
                denominator = denominator * (x - other_x) % prime
        value = (value + y * numerator * pow(denominator, -1, prime)) % prime
    secret = _to_string(value, secret_charset)
    if original_length is not None:
        if type(original_length) is not int or not 0 <= original_length <= 4096:
            raise ValueError("Original string length must be from 0 to 4096.")
        if original_length == 0 and value == 0:
            secret = ""
        elif len(secret) > original_length:
            raise RecoveryError("Recovered candidate exceeds the supplied original length.")
        else:
            secret = secret_charset[0] * (original_length - len(secret)) + secret
    verified = False
    if expected_sha256 is not None:
        if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256)):
            raise ValueError("Expected digest must be a full SHA-256 hexadecimal value.")
        verified = hmac.compare_digest(hashlib.sha256(secret.encode("utf-8")).hexdigest(), expected_sha256.lower())
        if not verified:
            raise RecoveryError("Legacy candidate does not match the independent expected digest.")
    return LegacyResult(secret, verified, inferred)
