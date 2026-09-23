import secrets

import pytest
from secretsharing import encoding
from secretsharing.errors import InvalidShare, UnsupportedVersion


def test_round_trip_and_prefix():
    raw = secrets.token_bytes(77)
    text = encoding.encode(raw)
    assert text.startswith("SS:V1:B32:")
    assert "=" not in text
    assert encoding.decode(text) == raw


def test_formatting_noise_is_accepted():
    raw = bytes(range(64))
    text = encoding.encode(raw)
    noisy = (
        "  " + text[:10].lower() + "-".join(text[10:][i : i + 5] for i in range(0, len(text) - 10, 5)).lower()
    )
    noisy = noisy.replace("-", "\r\n", 3).replace("-", "\t", 1) + "   \r\n"
    assert encoding.decode(noisy) == raw
    assert encoding.decode(encoding.format_lines(text)) == raw


def test_format_lines_layout():
    text = encoding.encode(bytes(100))
    lines = encoding.format_lines(text).split("\n")
    assert lines[0] == "SS:V1:B32:"
    assert all(len(group) <= 8 for group in lines[1].split("-"))
    assert lines[1].count("-") == 7
    assert lines[-1] == ""


@pytest.mark.parametrize(
    "bad",
    [
        "SS:V1:B32:ABCDEFG=",
        "SS:V1:B32:ABC1DEF",  # '1' is not Base32
        "SS:V1:B32:",
        "SS:V1:B32:A",  # invalid length
        "SS:V1:B32:AB",  # 'B' has nonzero unused bits: noncanonical
        "SS:V1:B32:AAAAAAAé",
    ],
)
def test_invalid_bodies(bad):
    with pytest.raises(InvalidShare):
        encoding.decode(bad)


@pytest.mark.parametrize("bad", ["SS:V2:B32:AAAA", "SS:V1:B64:AAAA", "SS2:AAAA", "hello", ""])
def test_unknown_prefixes(bad):
    with pytest.raises(UnsupportedVersion):
        encoding.decode(bad)


def test_oversize_and_type():
    with pytest.raises(InvalidShare):
        encoding.decode("SS:V1:B32:" + "A" * encoding.MAX_SHARE_TEXT)
    with pytest.raises(InvalidShare):
        encoding.decode(b"SS:V1:B32:AAAA")  # type: ignore[arg-type]
