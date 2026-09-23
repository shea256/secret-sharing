"""Public errors. Messages never include secret bytes or share text."""


class ShareError(ValueError):
    """Invalid backup input or unsuccessful recovery."""


class InvalidShare(ShareError):
    """The share could not be parsed or failed a structural check."""


class UnsupportedVersion(InvalidShare):
    """Prefix, version byte, or encoding tag this reader does not implement."""


class InvalidChecksum(InvalidShare):
    """Per-share checksum mismatch: a transcription error."""


class InvalidSignature(InvalidShare):
    """A signature the reader supports failed to verify."""


class UnsupportedSignature(InvalidShare):
    """The share requires a signature algorithm this reader cannot verify."""


class MixedBackups(ShareError):
    """Supplied shares carry different descriptors."""


class DuplicateShare(ShareError):
    """Two supplied shares carry the same index."""


class InsufficientShares(ShareError):
    """Fewer distinct shares than the declared threshold."""


class IdentityMismatch(ShareError):
    """The backup ID does not match the independently supplied one."""


class RecoveryError(ShareError):
    """Reconstruction failed its integrity check; no secret was returned."""
