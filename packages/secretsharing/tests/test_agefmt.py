import secrets
import subprocess

import pytest
from secretsharing import agefmt


def test_bip173_vectors():
    assert agefmt.bech32_encode("a", b"") == "a12uel5l"
    assert agefmt.bech32_decode("A12UEL5L") == ("a", b"")
    long_hrp = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio"
    assert agefmt.bech32_decode(long_hrp + "1tt5tgs") == (long_hrp, b"")
    with pytest.raises(ValueError):
        agefmt.bech32_decode("a12uel5m")  # bad checksum
    with pytest.raises(ValueError):
        agefmt.bech32_decode("A12uel5l")  # mixed case


def test_identity_round_trip():
    key = secrets.token_bytes(32)
    identity = agefmt.identity_from_key(key)
    assert identity.startswith("AGE-SECRET-KEY-1") and identity == identity.upper()
    assert agefmt.key_from_identity(identity) == key
    assert agefmt.key_from_identity(identity.lower() + "\n") == key
    with pytest.raises(ValueError):
        agefmt.identity_from_key(key[:31])
    with pytest.raises(ValueError):
        agefmt.key_from_identity(agefmt.bech32_encode("age", key))


@pytest.mark.skipif(agefmt.find_age() is None, reason="age binaries not installed")
def test_matches_real_age_keygen():
    generated = subprocess.run([agefmt.find_age()[1]], capture_output=True, text=True, check=True).stdout
    identity = next(line for line in generated.splitlines() if line.startswith("AGE-SECRET-KEY-"))
    assert agefmt.identity_from_key(agefmt.key_from_identity(identity)) == identity
    recipient = agefmt.recipient_from_identity(identity)
    assert recipient.startswith("age1")
    expected = next(line.split(": ")[1] for line in generated.splitlines() if "public key" in line)
    assert recipient == expected
