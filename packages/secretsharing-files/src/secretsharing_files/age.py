"""Minimal age v1 implementation for a single X25519 recipient (age-encryption.org/v1).

Header:  age-encryption.org/v1 / "-> X25519 <ephemeral pk>" / <wrapped file key> / "--- <mac>"
Payload: 16-byte nonce, then STREAM chunks of 64 KiB under ChaCha20-Poly1305.
Verified against the reference ``age`` binary in the test suite.
"""

import base64
import hmac
import secrets
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from secretsharing.agefmt import bech32_decode, bech32_encode

VERSION_LINE = b"age-encryption.org/v1"
X25519_INFO = b"age-encryption.org/v1/X25519"
CHUNK = 65536
_ZERO_NONCE = bytes(12)


class AgeError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    if "=" in text or not text.isascii():
        raise AgeError("Invalid base64 in age header.")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except ValueError:
        raise AgeError("Invalid base64 in age header.") from None


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def recipient_string(identity_key: bytes) -> str:
    public = X25519PrivateKey.from_private_bytes(identity_key).public_key().public_bytes_raw()
    return bech32_encode("age", public)


def _recipient_bytes(recipient: str) -> bytes:
    hrp, public = bech32_decode(recipient)
    if hrp != "age" or len(public) != 32:
        raise AgeError("Not an age X25519 recipient.")
    return public


def _chunk_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def encrypt(plaintext: bytes, recipient: str) -> bytes:
    recipient_public = _recipient_bytes(recipient)
    file_key = secrets.token_bytes(16)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    wrap_key = _hkdf(shared, ephemeral_public + recipient_public, X25519_INFO)
    wrapped = ChaCha20Poly1305(wrap_key).encrypt(_ZERO_NONCE, file_key, None)
    header = (
        VERSION_LINE
        + b"\n-> X25519 "
        + _b64(ephemeral_public).encode()
        + b"\n"
        + _b64(wrapped).encode()
        + b"\n---"
    )
    mac = hmac.new(_hkdf(file_key, None, b"header"), header, sha256).digest()
    nonce = secrets.token_bytes(16)
    stream = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    body = bytearray()
    chunks = [plaintext[i : i + CHUNK] for i in range(0, len(plaintext), CHUNK)] or [b""]
    for counter, chunk in enumerate(chunks):
        body += stream.encrypt(_chunk_nonce(counter, counter == len(chunks) - 1), chunk, None)
    return header + b" " + _b64(mac).encode() + b"\n" + nonce + bytes(body)


def _parse_header(data: bytes) -> tuple[list[tuple[list[str], bytes]], bytes, bytes, int]:
    """Return (stanzas, header bytes through '---', mac, payload offset)."""
    lines = data.split(b"\n")
    if not lines or lines[0] != VERSION_LINE:
        raise AgeError("Not an age v1 file.")
    stanzas: list[tuple[list[str], bytes]] = []
    i = 1
    while i < len(lines) and lines[i].startswith(b"-> "):
        args = lines[i][3:].decode("ascii", "strict").split(" ")
        i += 1
        body = b""
        while True:
            if i >= len(lines):
                raise AgeError("Truncated age header.")
            line = lines[i]
            i += 1
            body += _unb64(line.decode("ascii", "strict"))
            if len(line) < 64:
                break
        stanzas.append((args, body))
    if i >= len(lines) or not lines[i].startswith(b"--- "):
        raise AgeError("Malformed age header.")
    mac = _unb64(lines[i][4:].decode("ascii", "strict"))
    header_end = sum(len(line) + 1 for line in lines[:i]) + 3  # through "---"
    payload_offset = header_end + (len(lines[i]) - 3) + 1  # skip " <mac>" and the newline
    return stanzas, data[:header_end], mac, payload_offset


def decrypt(ciphertext: bytes, identity_key: bytes) -> bytes:
    identity = X25519PrivateKey.from_private_bytes(identity_key)
    our_public = identity.public_key().public_bytes_raw()
    stanzas, header, mac, offset = _parse_header(ciphertext)
    file_key = None
    for args, body in stanzas:
        if args[0] != "X25519" or len(args) != 2:
            continue
        ephemeral_public = _unb64(args[1])
        if len(ephemeral_public) != 32 or len(body) != 32:
            raise AgeError("Malformed X25519 stanza.")
        shared = identity.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
        if not any(shared):
            raise AgeError("Invalid X25519 shared secret.")
        wrap_key = _hkdf(shared, ephemeral_public + our_public, X25519_INFO)
        try:
            file_key = ChaCha20Poly1305(wrap_key).decrypt(_ZERO_NONCE, body, None)
            break
        except InvalidTag:
            continue
    if file_key is None:
        raise AgeError("No stanza matched this identity.")
    expected_mac = hmac.new(_hkdf(file_key, None, b"header"), header, sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise AgeError("Header MAC mismatch.")
    nonce = ciphertext[offset : offset + 16]
    if len(nonce) != 16:
        raise AgeError("Truncated payload.")
    stream = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    body = ciphertext[offset + 16 :]
    out = bytearray()
    counter = 0
    position = 0
    while True:
        chunk = body[position : position + CHUNK + 16]
        if len(chunk) < 16:
            raise AgeError("Truncated payload.")
        last = position + len(chunk) >= len(body)
        try:
            plain = stream.decrypt(_chunk_nonce(counter, last), chunk, None)
        except InvalidTag:
            raise AgeError("Payload authentication failed.") from None
        if last and not plain and (counter > 0):
            raise AgeError("Empty final chunk.")
        out += plain
        position += len(chunk)
        counter += 1
        if last:
            break
    return bytes(out)
