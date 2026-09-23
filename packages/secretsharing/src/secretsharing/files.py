"""Share files. Filenames are cosmetic; only the encoded contents control recovery."""

import os
from pathlib import Path

from .encoding import MAX_SHARE_TEXT, decode, format_lines
from .errors import InvalidShare, RecoveryError
from .protocol import Backup, ShareInfo, inspect_share

SUFFIX = ".ss.txt"


def read_limited(path: str | os.PathLike[str], limit: int) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{Path(path).name} exceeds the supported size limit.")
    return data


def read_share(path: str | os.PathLike[str]) -> str:
    try:
        return read_limited(path, MAX_SHARE_TEXT).decode("ascii")
    except UnicodeDecodeError:
        raise InvalidShare(f"{Path(path).name} is not an ASCII share file.") from None


def write_private(path: str | os.PathLike[str], data: bytes) -> None:
    """Create with 0600 and O_EXCL: never overwrites, and rejects existing symlinks."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def share_filename(info: ShareInfo) -> str:
    return f"{info.backup_id[:12]}--share{info.index:02d}--{info.threshold}of{info.count}{SUFFIX}"


def export_backup(backup: Backup, directory: str | os.PathLike[str]) -> tuple[Path, ...]:
    """Write one private file per share into a new private directory and read each back."""
    infos = [inspect_share(share) for share in backup.shares]
    if {i.index for i in infos} != set(range(1, backup.count + 1)) or any(
        i.backup_id != backup.backup_id for i in infos
    ):
        raise ValueError("Inconsistent backup export.")
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    paths = []
    for share, info in zip(backup.shares, infos, strict=True):
        path = directory / share_filename(info)
        write_private(path, format_lines(share).encode("ascii"))
        if decode(read_share(path)) != decode(share):
            raise RecoveryError("Export readback check failed.")
        paths.append(path)
    return tuple(paths)
