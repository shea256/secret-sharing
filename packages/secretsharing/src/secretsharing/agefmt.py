"""age identity strings for protection 2, file format 1 (PROTOCOL.md §9).

Only bech32 encoding and calls to the ``age`` binaries live here. X25519 and
ChaCha20-Poly1305 are deliberately not implemented in the core package.
"""

import shutil
import subprocess

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
IDENTITY_HRP = "age-secret-key-"
RECIPIENT_HRP = "age"


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for i, generator in enumerate(_GENERATORS):
            if (top >> i) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: list[int] | bytes, from_bits: int, to_bits: int, pad: bool) -> list[int]:
    acc = bits = 0
    out = []
    max_value = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & max_value)
    if pad:
        if bits:
            out.append((acc << (to_bits - bits)) & max_value)
    elif bits >= from_bits or (acc << (to_bits - bits)) & max_value:
        raise ValueError("Invalid bech32 padding.")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    values = _convert_bits(data, 8, 5, True)
    polymod = _polymod(_hrp_expand(hrp) + values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in values + checksum)


def bech32_decode(text: str) -> tuple[str, bytes]:
    if not isinstance(text, str) or text != text.lower() and text != text.upper():
        raise ValueError("Invalid bech32 string.")
    text = text.lower()
    position = text.rfind("1")
    if position < 1 or position + 7 > len(text):
        raise ValueError("Invalid bech32 string.")
    hrp, body = text[:position], text[position + 1 :]
    if any(c not in _CHARSET for c in body):
        raise ValueError("Invalid bech32 string.")
    values = [_CHARSET.index(c) for c in body]
    if _polymod(_hrp_expand(hrp) + values) != 1:
        raise ValueError("Invalid bech32 checksum.")
    return hrp, bytes(_convert_bits(values[:-6], 5, 8, False))


def identity_from_key(key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("An age identity is exactly 32 bytes.")
    return bech32_encode(IDENTITY_HRP, key).upper()


def key_from_identity(text: str) -> bytes:
    hrp, key = bech32_decode(text.strip())
    if hrp != IDENTITY_HRP or len(key) != 32:
        raise ValueError("Not an age identity.")
    return key


def find_age() -> tuple[str, str] | None:
    """Paths of the ``age`` and ``age-keygen`` binaries, or None if either is missing."""
    age, keygen = shutil.which("age"), shutil.which("age-keygen")
    return (age, keygen) if age and keygen else None


def recipient_from_identity(identity: str) -> str:
    """Derive the ``age1...`` recipient by running ``age-keygen -y``; identity goes over stdin."""
    tools = find_age()
    if tools is None:
        raise FileNotFoundError("age and age-keygen are required; see https://age-encryption.org")
    result = subprocess.run([tools[1], "-y"], input=identity + "\n", capture_output=True, text=True, check=True)
    recipient = result.stdout.strip()
    if not recipient.startswith(RECIPIENT_HRP + "1"):
        raise ValueError("age-keygen did not return a recipient.")
    return recipient
