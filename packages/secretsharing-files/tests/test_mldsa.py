import secrets

import pytest
from secretsharing import InvalidSignature, UnsupportedSignature, combine, inspect_share, split_text
from secretsharing.encoding import decode, encode
from secretsharing_files import VERIFIERS, ml_dsa_65_signer, mldsa, recover


def test_signer_shape_and_verify():
    signer = ml_dsa_65_signer()
    assert signer.alg == 2 and len(signer.public_key) == 1952
    signature = signer.sign(b"msg")
    assert len(signature) == 3309
    assert mldsa.verify(signer.public_key, b"msg", signature)
    assert not mldsa.verify(signer.public_key, b"other", signature)
    assert not mldsa.verify(secrets.token_bytes(1952), b"msg", signature)
    assert not mldsa.verify(signer.public_key, b"msg", signature[:-1])


def test_dual_signed_backup():
    backup = split_text("pq secret", threshold=2, shares=3, signed=True, signers=[ml_dsa_65_signer()])
    info = inspect_share(backup.shares[0], verifiers=VERIFIERS)
    assert info.signature_algs == (1, 2) and info.verified_signatures == (1, 2)
    with pytest.raises(UnsupportedSignature):  # core alone cannot verify ML-DSA
        combine(backup.shares)
    assert combine(backup.shares, allow_unverified=[2]).unverified_signatures == (2,)
    result = recover(backup.shares[1:], expected_backup_id=backup.backup_id)
    assert result.text() == "pq secret" and result.unverified_signatures == ()
    raw = bytearray(decode(backup.shares[0]))
    raw[-100] ^= 0x01  # inside the ML-DSA signature
    with pytest.raises(InvalidSignature):
        inspect_share(encode(bytes(raw)), verifiers=VERIFIERS)
