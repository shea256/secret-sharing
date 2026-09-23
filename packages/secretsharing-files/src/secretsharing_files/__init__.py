"""secretsharing-files: in-process age encryption and ML-DSA-65 signatures for protocol v1."""

import hashlib
import secrets
from pathlib import Path

from secretsharing import MAX_CAPACITY, Backup, Recovered, Signer, combine, split_bytes, split_file_key
from secretsharing.agefmt import identity_from_key
from secretsharing.files import export_backup, read_limited, write_private

from . import age, mldsa
from .mldsa import VERIFIERS, ml_dsa_65_signer

__version__ = "1.0.0a1"
FILE_FORMAT_AGE = 1
MAX_FILE_BYTES = 1 << 32


def _signers(signed: bool, post_quantum: bool) -> tuple[bool, list[Signer]]:
    """Post-quantum implies signed: ML-DSA-65 is always paired with Ed25519, and both must verify."""
    return signed or post_quantum, [ml_dsa_65_signer()] if post_quantum else []


def create_file_backup(
    path: str | Path,
    *,
    threshold: int,
    shares: int,
    out: str | Path,
    signed: bool = False,
    post_quantum: bool = False,
    qr: bool = False,
) -> Backup:
    """Encrypt ``path`` to ``out/<name>.age`` with a fresh identity and share that identity."""
    source = Path(path)
    out = Path(out)
    plaintext = read_limited(source, MAX_FILE_BYTES)
    key = secrets.token_bytes(32)
    ciphertext = age.encrypt(plaintext, age.recipient_string(key))
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_private(out / (source.name + ".age"), ciphertext)
    signed, extra = _signers(signed, post_quantum)
    backup = split_file_key(
        key,
        threshold=threshold,
        shares=shares,
        file_format=FILE_FORMAT_AGE,
        file_hash=hashlib.sha256(ciphertext).digest(),
        signed=signed,
        signers=extra,
    )
    export_backup(backup, out / "shares", qr=qr, verifiers=VERIFIERS)
    return backup


def create_backup(
    path: str | Path,
    *,
    threshold: int,
    shares: int,
    out: str | Path,
    protection: str = "auto",
    signed: bool = False,
    post_quantum: bool = False,
    qr: bool = False,
) -> Backup:
    """``auto``: direct sharing up to the protocol cap, file encryption above it."""
    size = Path(path).stat().st_size
    if protection not in ("auto", "direct", "file"):
        raise ValueError("protection must be auto, direct, or file.")
    if protection == "file" or (protection == "auto" and size > MAX_CAPACITY):
        return create_file_backup(
            path, threshold=threshold, shares=shares, out=out, signed=signed, post_quantum=post_quantum, qr=qr
        )
    signed, extra = _signers(signed, post_quantum)
    backup = split_bytes(
        read_limited(path, MAX_CAPACITY), threshold=threshold, shares=shares, signed=signed, signers=extra
    )
    export_backup(backup, out, qr=qr, verifiers=VERIFIERS)
    return backup


def recover(shares: list[str], *, expected_backup_id: str | None = None) -> Recovered:
    """``secretsharing.combine`` with the ML-DSA-65 verifier available."""
    return combine(shares, expected_backup_id=expected_backup_id, verifiers=VERIFIERS)


def recover_file(
    shares: list[str],
    ciphertext_path: str | Path,
    out_path: str | Path,
    *,
    expected_backup_id: str | None = None,
) -> Path:
    """Recover the identity from shares, check the ciphertext hash, decrypt to a new private file."""
    result = recover(shares, expected_backup_id=expected_backup_id)
    if result.protection != 2 or result.file_format != FILE_FORMAT_AGE:
        raise ValueError("These shares do not protect an age-encrypted file.")
    ciphertext = read_limited(ciphertext_path, MAX_FILE_BYTES)
    if hashlib.sha256(ciphertext).digest() != result.file_hash:
        raise ValueError("Ciphertext SHA-256 does not match the hash recorded in the shares.")
    plaintext = age.decrypt(ciphertext, result.data)
    write_private(out_path, plaintext)
    return Path(out_path)


__all__ = [
    "create_file_backup",
    "create_backup",
    "recover",
    "recover_file",
    "identity_from_key",
    "ml_dsa_65_signer",
    "VERIFIERS",
    "age",
    "mldsa",
]
