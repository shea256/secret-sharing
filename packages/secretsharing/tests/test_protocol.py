import hashlib
import itertools
import secrets

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from secretsharing import (
    DuplicateShare,
    IdentityMismatch,
    InsufficientShares,
    InvalidChecksum,
    InvalidShare,
    MixedBackups,
    RecoveryError,
    UnsupportedSignature,
    UnsupportedVersion,
    combine,
    estimate_share_size,
    field,
    inspect_share,
    protocol,
    split_bytes,
    split_file_key,
    split_text,
)
from secretsharing.encoding import decode, encode


def fixed_rng(seed: bytes):
    """Deterministic byte source for tests only: SHA-256 counter stream."""
    counter = 0

    def draw(n: int) -> bytes:
        nonlocal counter
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
            counter += 1
        return out[:n]

    return draw


def test_descriptor_bytes_exact():
    backup = split_bytes(b"\x00\x01\xff", threshold=2, shares=3, _rng=fixed_rng(b"seed"))
    raw = decode(backup.shares[0])
    set_id = fixed_rng(b"seed")(16)
    assert raw[:25] == b"SS" + bytes([1, 1, 0, 2, 3]) + (3).to_bytes(2, "big") + set_id
    assert raw[25] == 1
    assert len(raw) == 25 + 1 + (3 + 3 + 16) + 4 == estimate_share_size(3)
    assert backup.backup_id == hashlib.sha256(protocol.ID_DOMAIN + raw[:25]).hexdigest()


def test_backup_id_independent_of_secret():
    a = split_bytes(b"one", threshold=2, shares=2, _rng=fixed_rng(b"k"))
    b = split_bytes(b"two", threshold=2, shares=2, _rng=fixed_rng(b"k"))
    assert a.backup_id == b.backup_id
    assert a.shares != b.shares


def test_payload_digest_layout():
    backup = split_bytes(b"hi", threshold=2, shares=2, _rng=fixed_rng(b"d"))
    raw = [decode(s) for s in backup.shares]
    descriptor = raw[0][:25]
    payload = field.combine([(r[25], r[26:-4]) for r in raw])
    assert payload[:3] == b"\x00\x00\x02"
    assert payload[3:5] == b"hi"
    head = payload[:-16]
    assert payload[-16:] == hashlib.sha256(protocol.DIGEST_DOMAIN + descriptor + head).digest()[:16]


@pytest.mark.parametrize("secret", ["", "00demo café 🔑\n", "x" * 1000])
def test_text_round_trip(secret):
    backup = split_text(secret, threshold=2, shares=3)
    result = combine(backup.shares[1:], expected_backup_id=backup.backup_id)
    assert result.text() == secret
    assert result.kind == "text"
    assert result.identity_verified is True
    assert result.protection == 1


def test_bytes_round_trip_and_max_size():
    data = secrets.token_bytes(65535)
    backup = split_bytes(data, threshold=3, shares=4)
    result = combine(backup.shares[::-1])
    assert result.data == data
    assert result.kind == "bytes"
    assert result.identity_verified is False
    with pytest.raises(TypeError):
        result.text()
    with pytest.raises(ValueError):
        split_bytes(data + b"x", threshold=2, shares=2)


def test_capacity_pads_and_hides_length():
    short = split_text("a", threshold=2, shares=2, capacity=32)
    longer = split_text("a" * 20, threshold=2, shares=2, capacity=32)
    assert len(short.shares[0]) == len(longer.shares[0])
    assert inspect_share(short.shares[0]).capacity == 32
    assert combine(short.shares).text() == "a"
    with pytest.raises(ValueError):
        split_text("a" * 33, threshold=2, shares=2, capacity=32)


@pytest.mark.parametrize("threshold,count", [(2, 3), (3, 5)])
def test_every_subset_recovers(threshold, count):
    backup = split_bytes(b"\x00\x00\xffabc", threshold=threshold, shares=count)
    for subset in itertools.combinations(backup.shares, threshold):
        assert combine(subset).data == b"\x00\x00\xffabc"
    with pytest.raises(InsufficientShares):
        combine(backup.shares[: threshold - 1])


def test_inspect_share():
    backup = split_text("s", threshold=2, shares=3)
    info = inspect_share(backup.shares[2])
    assert (info.threshold, info.count, info.index, info.capacity) == (2, 3, 3, 1)
    assert info.backup_id == backup.backup_id
    assert info.signature_algs == ()
    assert info.file_format is None and info.version == 1


def test_corrupted_share_fails_checksum():
    backup = split_text("secret", threshold=2, shares=2)
    raw = bytearray(decode(backup.shares[0]))
    raw[30] ^= 0x01
    with pytest.raises(InvalidChecksum):
        combine([encode(bytes(raw)), backup.shares[1]])


def test_recomputed_checksum_fails_digest_and_returns_nothing():
    backup = split_text("secret", threshold=2, shares=2)
    raw = bytearray(decode(backup.shares[0]))
    raw[30] ^= 0x01
    descriptor, index, value = bytes(raw[:25]), raw[25], bytes(raw[26:-4])
    forged = encode(descriptor + bytes([index]) + value + protocol._checksum(descriptor, index, value))
    assert inspect_share(forged).index == 1
    with pytest.raises(RecoveryError):
        combine([forged, backup.shares[1]])


def test_mixed_duplicate_identity_and_version_errors():
    a = split_text("a", threshold=2, shares=2)
    b = split_text("a", threshold=2, shares=2)
    with pytest.raises(MixedBackups):
        combine([a.shares[0], b.shares[1]])
    with pytest.raises(DuplicateShare):
        combine([a.shares[0], a.shares[0]])
    with pytest.raises(IdentityMismatch):
        combine(a.shares, expected_backup_id=b.backup_id)
    with pytest.raises(IdentityMismatch):
        combine(a.shares, expected_backup_id="short")
    raw = bytearray(decode(a.shares[0]))
    raw[2] = 2
    with pytest.raises(UnsupportedVersion):
        inspect_share(encode(bytes(raw)))
    raw[2] = 1
    raw[3] = 9
    with pytest.raises(InvalidShare):
        inspect_share(encode(bytes(raw)))
    with pytest.raises(InvalidShare):
        combine("not a list")
    with pytest.raises(InsufficientShares):
        combine([])


def _signed_shares(alg: int, sig_len: int, pk_len: int, unknown: bool = False):
    rng = fixed_rng(b"sig")
    signers = [(alg, b"\x11" * pk_len)]
    descriptor = protocol._descriptor(1, 2, 2, 4, rng(16), signers=signers)
    if unknown:
        descriptor = descriptor[:25] + bytes([200]) + descriptor[26:]
    payload = protocol._payload(descriptor, 0, b"key!", 4)
    out = []
    for index, value in field.split(payload, 2, 2, coefficients=rng):
        out.append(
            encode(
                descriptor
                + bytes([index])
                + value
                + protocol._checksum(descriptor, index, value)
                + b"\x22" * sig_len
            )
        )
    return out


def test_fake_ed25519_signature_is_rejected():
    from secretsharing import InvalidSignature

    with pytest.raises(InvalidSignature):
        inspect_share(_signed_shares(1, 64, 32)[0])


def test_unsupported_algorithm_refused_by_default_and_recoverable_with_override():
    shares = _signed_shares(2, 3309, 1952)
    with pytest.raises(UnsupportedSignature):
        inspect_share(shares[0])
    with pytest.raises(UnsupportedSignature):
        combine(shares)
    info = inspect_share(shares[0], allow_unverified=[2])
    assert info.signature_algs == (2,) and info.verified_signatures == ()
    result = combine(shares, allow_unverified=[2])
    assert result.data == b"key!"
    assert result.unverified_signatures == (2,)
    with pytest.raises(UnsupportedSignature):
        combine(shares, allow_unverified=[1])


def test_ml_dsa_lengths_and_unknown_alg():
    shares = _signed_shares(2, 3309, 1952)
    assert inspect_share(shares[1], allow_unverified=[2]).signature_algs == (2,)
    with pytest.raises(InvalidShare):
        inspect_share(_signed_shares(1, 64, 32, unknown=True)[0], allow_unverified=[200])


def test_file_key_backup():
    key = secrets.token_bytes(32)
    digest = hashlib.sha256(b"ciphertext").digest()
    backup = split_file_key(key, threshold=2, shares=3, file_format=1, file_hash=digest)
    info = inspect_share(backup.shares[0])
    assert (info.protection, info.capacity, info.file_format, info.file_hash) == (2, 32, 1, digest)
    result = combine(backup.shares[:2])
    assert (result.data, result.protection, result.file_format, result.file_hash) == (key, 2, 1, digest)
    for bad in (dict(key=key[:31]), dict(file_format=9), dict(file_hash=b"x")):
        args = dict(key=key, threshold=2, shares=3, file_format=1, file_hash=digest) | bad
        with pytest.raises(ValueError):
            split_file_key(args.pop("key"), **args)


def test_parameter_validation():
    for kwargs in (dict(threshold=1, shares=3), dict(threshold=3, shares=2), dict(threshold=2, shares=256)):
        with pytest.raises(ValueError):
            split_text("x", **kwargs)
    with pytest.raises(TypeError):
        split_text(b"x", threshold=2, shares=2)
    with pytest.raises(TypeError):
        split_bytes("x", threshold=2, shares=2)
    with pytest.raises(ValueError):
        split_text("\ud800", threshold=2, shares=2)


def test_self_check_failure_produces_nothing(monkeypatch):
    monkeypatch.setattr(protocol.field, "combine", lambda points: b"\x00" * 21)
    with pytest.raises(RecoveryError):
        split_text("x", threshold=2, shares=2)


def test_reprs_hide_secrets():
    backup = split_text("hidden-secret", threshold=2, shares=2)
    assert "hidden" not in repr(backup) and backup.shares[0] not in repr(backup)
    assert "hidden" not in repr(combine(backup.shares))


@settings(max_examples=40, deadline=None)
@given(
    data=st.binary(max_size=300),
    threshold=st.integers(2, 5),
    extra=st.integers(0, 3),
    pad=st.integers(0, 40),
)
def test_hypothesis_round_trip(data, threshold, extra, pad):
    backup = split_bytes(data, threshold=threshold, shares=threshold + extra, capacity=len(data) + pad)
    picked = sorted(secrets.SystemRandom().sample(backup.shares, threshold))
    assert combine(picked).data == data


def test_signed_round_trip_and_tamper_detection():
    from secretsharing import InvalidSignature

    backup = split_text("signed secret", threshold=2, shares=3, signed=True)
    assert len(decode(backup.shares[0])) == estimate_share_size(13, signed=True)
    info = inspect_share(backup.shares[0])
    assert info.signature_algs == (1,) and info.verified_signatures == (1,)
    result = combine(backup.shares[1:])
    assert result.text() == "signed secret" and result.unverified_signatures == ()
    raw = bytearray(decode(backup.shares[0]))
    raw[-1] ^= 0x01  # flip a signature bit; checksum still passes
    with pytest.raises(InvalidSignature):
        inspect_share(encode(bytes(raw)))
    # Altering the share value and recomputing the checksum still fails the signature.
    raw = bytearray(decode(backup.shares[0]))
    descriptor_end = 25 + 1 + 32
    raw[descriptor_end + 5] ^= 0x01
    value_end = descriptor_end + 1 + 13 + 19
    raw[value_end : value_end + 4] = protocol._checksum(
        bytes(raw[:descriptor_end]), raw[descriptor_end], bytes(raw[descriptor_end + 1 : value_end])
    )
    with pytest.raises(InvalidSignature):
        inspect_share(encode(bytes(raw)))


def test_signature_stripping_is_detected():
    backup = split_text("s", threshold=2, shares=2, signed=True)

    def strip(share: str) -> bytes:
        raw = decode(share)
        return raw[:4] + b"\x00" + raw[5:25] + raw[25 + 1 + 32 : -64]  # drop alg ID, pubkey, signature

    stripped = [strip(share) for share in backup.shares]
    with pytest.raises(InvalidChecksum):  # descriptor changed, checksum covers it
        inspect_share(encode(stripped[0]))
    forged = []
    for raw in stripped:
        descriptor, index, value = raw[:25], raw[25], raw[26:-4]
        forged.append(
            encode(descriptor + bytes([index]) + value + protocol._checksum(descriptor, index, value))
        )
    assert inspect_share(forged[0]).signature_algs == ()
    with pytest.raises(RecoveryError):  # digest covers the descriptor too
        combine(forged)


def test_custom_signer_and_verifier_for_algorithm_2():
    from secretsharing import Signer

    public = b"\x07" * 1952
    calls = []

    def fake_sign(message: bytes) -> bytes:
        calls.append(message)
        return hashlib.sha256(message).digest() * 103 + b"\x00" * 13  # 3309 bytes

    def fake_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        return pk == public and signature == fake_sign(message)

    signer = Signer(2, public, fake_sign, fake_verify)
    backup = split_bytes(b"pq", threshold=2, shares=2, signed=True, signers=[signer])
    assert inspect_share(backup.shares[0], verifiers={2: fake_verify}).verified_signatures == (1, 2)
    with pytest.raises(UnsupportedSignature):
        combine(backup.shares)
    partial = combine(backup.shares, allow_unverified=[2])
    assert partial.data == b"pq" and partial.unverified_signatures == (2,)
    assert combine(backup.shares, verifiers={2: fake_verify}).unverified_signatures == ()
    with pytest.raises(ValueError):
        Signer(9, public, fake_sign, fake_verify)
    with pytest.raises(ValueError):
        Signer(2, public[:10], fake_sign, fake_verify)
