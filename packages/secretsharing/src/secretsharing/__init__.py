"""Self-describing threshold secret sharing, protocol v1. See PROTOCOL.md."""

__version__ = "1.0.0a1"

from .errors import (
    DuplicateShare,
    IdentityMismatch,
    InsufficientShares,
    InvalidChecksum,
    InvalidShare,
    InvalidSignature,
    MixedBackups,
    RecoveryError,
    ShareError,
    UnsupportedSignature,
    UnsupportedVersion,
)
from .protocol import (
    FILE_FORMATS,
    MAX_CAPACITY,
    MAX_SHARES,
    SIGNATURE_ALGS,
    Backup,
    Recovered,
    ShareInfo,
    combine,
    estimate_share_size,
    inspect_share,
    split_bytes,
    split_file_key,
    split_text,
)

__all__ = [
    "Backup", "Recovered", "ShareInfo", "combine", "estimate_share_size", "inspect_share",
    "split_bytes", "split_file_key", "split_text", "FILE_FORMATS", "MAX_CAPACITY", "MAX_SHARES",
    "SIGNATURE_ALGS", "ShareError", "InvalidShare", "UnsupportedVersion", "InvalidChecksum",
    "InvalidSignature", "UnsupportedSignature", "MixedBackups", "DuplicateShare",
    "InsufficientShares", "IdentityMismatch", "RecoveryError",
]
