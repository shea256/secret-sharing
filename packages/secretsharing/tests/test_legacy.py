import hashlib
import random

import pytest
from secretsharing.errors import DuplicateShare, InvalidShare, RecoveryError
from secretsharing.legacy import FORMATS, _to_int, _to_string, recover_secret
from secretsharing.primes import STANDARD_PRIMES, is_probable_prime


def legacy_split(secret_int: int, threshold: int, count: int, prime: int, charset: str) -> list[str]:
    """Reproduce the historical 0.2.x share construction for self-consistency tests."""
    coefficients = [secret_int] + [random.randrange(prime) for _ in range(threshold - 1)]
    shares = []
    for x in range(1, count + 1):
        y = sum(c * pow(x, i, prime) for i, c in enumerate(coefficients)) % prime
        shares.append(f"{_to_string(x, charset)}-{_to_string(y, charset)}")
    return shares


def test_transcript_example():
    result = recover_secret(["1-2", "2-0"], prime=7, original_length=4)
    assert (result.secret, result.verified, result.inferred_prime) == ("0004", False, False)
    guessed = recover_secret(["1-2", "2-0"])  # historical guess picks prime 3
    assert guessed.inferred_prime is True and guessed.secret != "4"


def test_hex_round_trip_with_historical_prime_rule():
    secret = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"
    value = _to_int(secret, FORMATS["hex"][0])
    prime = next(p for p in STANDARD_PRIMES if value < p and 5 < p)
    shares = legacy_split(value, 3, 5, prime, FORMATS["hex"][0])
    digest = hashlib.sha256(secret.encode()).hexdigest()
    result = recover_secret(shares[1:4], prime=prime, expected_sha256=digest)
    assert result.secret == secret and result.verified is True
    inferred = recover_secret(shares[:3])
    assert inferred.secret == secret and inferred.inferred_prime is True
    with pytest.raises(RecoveryError):
        recover_secret(shares[:3], expected_sha256="0" * 64)


def test_printable_text_format_and_leading_zero_loss():
    charset = FORMATS["text"][1]
    value = _to_int("00hi", charset)
    shares = legacy_split(value, 2, 3, STANDARD_PRIMES[8], FORMATS["text"][0])
    assert recover_secret(shares[:2], format="text", prime=STANDARD_PRIMES[8]).secret == "hi"
    assert (
        recover_secret(shares[:2], format="text", prime=STANDARD_PRIMES[8], original_length=4).secret
        == "00hi"
    )


def test_invalid_inputs():
    with pytest.raises(InvalidShare):
        recover_secret(["1-2"])
    with pytest.raises(InvalidShare):
        recover_secret(["1-2", "0-5"], prime=7)
    with pytest.raises(DuplicateShare):
        recover_secret(["1-2", "1-2"], prime=7)
    with pytest.raises(InvalidShare):
        recover_secret(["1-2", "2-0"], prime=9)
    with pytest.raises(InvalidShare):
        recover_secret(["1-2", "2-9"], prime=7)
    with pytest.raises(ValueError):
        recover_secret(["1-2", "2-0"], format="nope")


def test_primality():
    assert all(is_probable_prime(p) for p in STANDARD_PRIMES)
    assert is_probable_prime(2) and is_probable_prime(3) and is_probable_prime(97)
    assert not is_probable_prime(1) and not is_probable_prime(0) and not is_probable_prime(-7)
    assert not is_probable_prime(561) and not is_probable_prime(3215031751)  # Carmichael and MR pseudoprime
    assert not is_probable_prime((2**127 - 1) * (2**61 - 1))
    assert is_probable_prime(2**521 - 1) and not is_probable_prime(2**521 + 1)
