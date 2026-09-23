"""secretsharing-files: in-process age encryption for protocol v1 file backups (protection 2)."""

import hashlib
import secrets
from pathlib import Path

from secretsharing import MAX_CAPACITY, Backup, combine, split_bytes, split_file_key
from secretsharing.agefmt import identity_from_key
from secretsharing.files import export_backup, read_limited, write_private

from . import age

__version__ = "1.0.0a1"
FILE_FORMAT_AGE = 1
MAX_FILE_BYTES = 1 << 32


def create_file_backup(path: str | Path, *, threshold: int, shares: int, out: str | Path) -> Backup:
    """Encrypt ``path`` to ``out/<name>.age`` with a fresh key and split that key into ``out/shares``."""
    source = Path(path)
    out = Path(out)
    plaintext = read_limited(source, MAX_FILE_BYTES)
    key = secrets.token_bytes(32)
    ciphertext = age.encrypt(plaintext, age.recipient_string(key))
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_private(out / (source.name + ".age"), ciphertext)
    backup = split_file_key(
        key,
        threshold=threshold,
        shares=shares,
        file_format=FILE_FORMAT_AGE,
        file_hash=hashlib.sha256(ciphertext).digest(),
    )
    export_backup(backup, out / "shares")
    return backup


def create_backup(
    path: str | Path, *, threshold: int, shares: int, out: str | Path, protection: str = "auto"
) -> Backup:
    """``auto``: direct sharing up to the protocol cap, file encryption above it."""
    size = Path(path).stat().st_size
    if protection not in ("auto", "direct", "file"):
        raise ValueError("protection must be auto, direct, or file.")
    if protection == "file" or (protection == "auto" and size > MAX_CAPACITY):
        return create_file_backup(path, threshold=threshold, shares=shares, out=out)
    backup = split_bytes(read_limited(path, MAX_CAPACITY), threshold=threshold, shares=shares)
    export_backup(backup, out)
    return backup


def recover_file(
    shares: list[str],
    ciphertext_path: str | Path,
    out_path: str | Path,
    *,
    expected_backup_id: str | None = None,
) -> Path:
    """Recover the key from shares, check the ciphertext hash, decrypt to a new private file."""
    result = combine(shares, expected_backup_id=expected_backup_id)
    if result.protection != 2 or result.file_format != FILE_FORMAT_AGE:
        raise ValueError("These shares do not protect an age-encrypted file.")
    ciphertext = read_limited(ciphertext_path, MAX_FILE_BYTES)
    if hashlib.sha256(ciphertext).digest() != result.file_hash:
        raise ValueError("Ciphertext SHA-256 does not match the hash recorded in the shares.")
    plaintext = age.decrypt(ciphertext, result.data)
    write_private(out_path, plaintext)
    return Path(out_path)


__all__ = ["create_file_backup", "create_backup", "recover_file", "identity_from_key", "age"]
