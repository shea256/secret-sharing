import secrets

import pytest
from secretsharing import ed25519

# RFC 8032 §7.1 test vectors 1 and 2.
VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


@pytest.mark.parametrize("seed,public,message,signature", VECTORS)
def test_rfc8032_vectors(seed, public, message, signature):
    seed, public, message, signature = (bytes.fromhex(x) for x in (seed, public, message, signature))
    assert ed25519.public_key(seed) == public
    assert ed25519.sign(seed, message) == signature
    assert ed25519.verify(public, message, signature)
    assert not ed25519.verify(public, message + b"x", signature)
    assert not ed25519.verify(public, message, signature[:-1] + bytes([signature[-1] ^ 1]))
    assert not ed25519.verify(
        public,
        message,
        signature[:32] + (2**252 + 27742317777372353535851937790883648493).to_bytes(32, "little"),
    )


def test_random_round_trip_and_bad_inputs():
    seed = ed25519.generate_seed()
    public = ed25519.public_key(seed)
    message = secrets.token_bytes(100)
    assert ed25519.verify(public, message, ed25519.sign(seed, message))
    assert not ed25519.verify(public[:31], message, ed25519.sign(seed, message))
    assert not ed25519.verify(b"\xff" * 32, message, ed25519.sign(seed, message))
    with pytest.raises(ValueError):
        ed25519.sign(b"short", message)


def test_matches_pyca_when_available():
    pyca = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    seed = ed25519.generate_seed()
    theirs = pyca.Ed25519PrivateKey.from_private_bytes(seed)
    message = b"cross-check"
    assert theirs.public_key().public_bytes_raw() == ed25519.public_key(seed)
    assert theirs.sign(message) == ed25519.sign(seed, message)
    theirs.public_key().verify(ed25519.sign(seed, message), message)
    assert ed25519.verify(ed25519.public_key(seed), message, theirs.sign(message))
