"""Text representation ``SS:V1:B32:<Base32>`` (PROTOCOL.md §7)."""

import base64
import binascii

from .errors import InvalidShare, UnsupportedVersion

PREFIX = "SS:V1:B32:"
MAX_SHARE_TEXT = 262144
_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_NOISE = str.maketrans("", "", "- \t\r\n")


def encode(raw: bytes) -> str:
    return PREFIX + base64.b32encode(raw).decode("ascii").rstrip("=")


def decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > MAX_SHARE_TEXT:
        raise InvalidShare("Expected a share string of at most 256 KiB.")
    if not text.isascii():
        raise InvalidShare("Share text must be ASCII.")
    text = text.strip(" \t\r\n")
    if text[: len(PREFIX)].upper() != PREFIX:
        raise UnsupportedVersion("Not an SS:V1:B32: share. Legacy v0 shares need explicit legacy recovery.")
    body = text[len(PREFIX) :].translate(_NOISE).upper()
    if not body or any(c not in _ALPHABET for c in body):
        raise InvalidShare("Invalid Base32 share body.")
    try:
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
    except (ValueError, binascii.Error):
        raise InvalidShare("Invalid Base32 share body.") from None
    if base64.b32encode(raw).decode("ascii").rstrip("=") != body:
        raise InvalidShare("Noncanonical Base32 share body.")
    return raw


def format_lines(text: str) -> str:
    """Prefix on its own line, then eight-character groups, eight groups per line."""
    body = text[len(PREFIX) :]
    groups = [body[i : i + 8] for i in range(0, len(body), 8)]
    lines = ["-".join(groups[i : i + 8]) for i in range(0, len(groups), 8)]
    return PREFIX + "\n" + "\n".join(lines) + "\n"
