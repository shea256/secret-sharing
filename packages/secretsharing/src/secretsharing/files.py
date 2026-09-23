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


def qr_svg(share: str) -> bytes | None:
    """SVG QR code of the one-line share, or None if it does not fit one QR symbol.

    Requires the optional ``qrcode`` package (``pip install secretsharing[qr]``).
    Upper-case Base32 plus ``:`` fits QR alphanumeric mode, the densest text mode.
    """
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError:
        raise ValueError("QR export needs the qrcode package: pip install 'secretsharing[qr]'") from None
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    code.add_data(share)
    try:
        code.make(fit=True)
    except (qrcode.exceptions.DataOverflowError, ValueError):
        return None
    return code.make_image(image_factory=SvgPathImage).to_string()


def export_backup(
    backup: Backup, directory: str | os.PathLike[str], *, qr: bool = False, verifiers=None
) -> tuple[Path, ...]:
    """Write one private file per share into a new private directory and read each back.

    With ``qr``, also write ``<share>.svg`` beside each share that fits a single QR symbol.
    """
    infos = [inspect_share(share, verifiers=verifiers) for share in backup.shares]
    if {i.index for i in infos} != set(range(1, backup.count + 1)) or any(
        i.backup_id != backup.backup_id for i in infos
    ):
        raise ValueError("Inconsistent backup export.")
    images = [qr_svg(share) for share in backup.shares] if qr else []  # preflight before writing
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    paths = []
    for position, (share, info) in enumerate(zip(backup.shares, infos, strict=True)):
        path = directory / share_filename(info)
        write_private(path, format_lines(share).encode("ascii"))
        if decode(read_share(path)) != decode(share):
            raise RecoveryError("Export readback check failed.")
        paths.append(path)
        if qr and images[position] is not None:
            write_private(path.with_suffix(".svg"), images[position])
    return tuple(paths)
