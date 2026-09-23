import itertools
import secrets
import time

import pytest

from secretsharing import field


def test_known_products():
    assert field.mul(0x53, 0xCA) == 0x01  # AES inverse pair
    assert field.mul(0x57, 0x83) == 0xC1  # FIPS-197 example
    assert field.mul(0x00, 0x7F) == 0
    for x in range(256):
        assert field.mul(x, 1) == x
        assert field.mul(x, 2) == ((x << 1) ^ (0x11B if x & 0x80 else 0)) & 0xFF


def test_mul_is_commutative_and_inverse_consistent():
    for a in range(1, 256):
        assert field.mul(a, field.inv(a)) == 1
        for b in (3, 17, 200):
            assert field.mul(a, b) == field.mul(b, a)


def test_hand_computed_one_byte_example():
    shares = field.split(b"\x2a", 2, 3, coefficients=lambda n: b"\x03" * n)
    assert shares == [(1, b"\x29"), (2, b"\x2c"), (3, bytes([0x2A ^ field.mul(3, 3)]))]
    assert field.combine(shares[:2]) == b"\x2a"


def test_coefficient_order_is_c1_first():
    # k=3: P + c1 x + c2 x^2 with c1=1, c2=2 at x=2: P ^ 2 ^ mul(2, 4) = P ^ 2 ^ 8
    draws = iter([b"\x01", b"\x02"])
    shares = field.split(b"\x00", 3, 3, coefficients=lambda n: next(draws))
    assert shares[1] == (2, bytes([0x02 ^ 0x08]))


@pytest.mark.parametrize("threshold,count", [(2, 2), (2, 3), (3, 5), (4, 6), (5, 5)])
def test_round_trip_every_subset(threshold, count):
    payload = secrets.token_bytes(40)
    shares = field.split(payload, threshold, count)
    for subset in itertools.combinations(shares, threshold):
        assert field.combine(subset) == payload
    # More than threshold also works; fewer gives a different answer.
    assert field.combine(shares) == payload
    if threshold > 2:
        assert field.combine(shares[: threshold - 1]) != payload


def test_empty_payload():
    shares = field.split(b"", 2, 3)
    assert shares == [(1, b""), (2, b""), (3, b"")]
    assert field.combine(shares[:2]) == b""


def test_rejects_bad_parameters():
    with pytest.raises(ValueError):
        field.split(b"x", 1, 3)
    with pytest.raises(ValueError):
        field.split(b"x", 4, 3)
    with pytest.raises(ValueError):
        field.split(b"x", 2, 256)
    with pytest.raises(TypeError):
        field.split("x", 2, 3)
    with pytest.raises(ValueError):
        field.split(b"xx", 2, 3, coefficients=lambda n: b"\x00")


def test_combine_rejects_duplicates_and_bad_indices():
    shares = field.split(b"abc", 2, 3)
    with pytest.raises(ValueError):
        field.combine([shares[0], shares[0]])
    with pytest.raises(ValueError):
        field.combine([(0, b"abc"), (1, b"abc")])
    with pytest.raises(ValueError):
        field.combine([(256, b"abc"), (1, b"abc")])
    with pytest.raises(ValueError):
        field.combine([(1, b"abc"), (2, b"ab")])
    with pytest.raises(ValueError):
        field.combine([])


def test_large_payload_is_fast():
    payload = secrets.token_bytes(65535)
    start = time.perf_counter()
    shares = field.split(payload, 5, 255)
    assert field.combine(shares[:5]) == payload
    assert time.perf_counter() - start < 3.0
    start = time.perf_counter()
    dense = field.split(secrets.token_bytes(4096), 255, 255)
    assert field.combine(dense) == field.combine(dense[::-1])
    assert time.perf_counter() - start < 5.0
