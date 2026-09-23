"""ML-DSA-65 (FIPS 204, algorithm 2) signer and verifier via pyca/cryptography."""

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import mldsa
from secretsharing import Signer


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        return False


def ml_dsa_65_signer() -> Signer:
    key = mldsa.MLDSA65PrivateKey.generate()
    return Signer(2, key.public_key().public_bytes_raw(), key.sign, verify)


VERIFIERS = {2: verify}
