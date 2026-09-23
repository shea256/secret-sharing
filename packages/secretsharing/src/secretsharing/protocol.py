"""Protocol v1 descriptor, payload, share assembly, and recovery (PROTOCOL.md §4–§11)."""

import hashlib
import hmac
import secrets
import struct
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field

from . import field
from .encoding import decode, encode
from .errors import (
    DuplicateShare,
    IdentityMismatch,
    InsufficientShares,
    InvalidChecksum,
    InvalidShare,
    MixedBackups,
    RecoveryError,
    UnsupportedSignature,
    UnsupportedVersion,
)

VERSION = 1
PROTECTION_DIRECT = 1
PROTECTION_FILE = 2
MAX_CAPACITY = 65535
MAX_SHARES = 255
FILE_KEY_LENGTH = 32
DIGEST_LENGTH = 16
CHECK_LENGTH = 4
PAYLOAD_OVERHEAD = 3 + DIGEST_LENGTH

DIGEST_DOMAIN = b"secretsharing/v1/digest\x00"
CHECK_DOMAIN = b"secretsharing/v1/check\x00"
ID_DOMAIN = b"secretsharing/v1/id\x00"
SIGN_DOMAIN = b"secretsharing/v1/sign\x00"

# alg -> (public key length, signature length). Lengths are fixed by the ID.
SIGNATURE_ALGS: dict[int, tuple[int, int]] = {1: (32, 64), 2: (1952, 3309)}
FILE_FORMATS: dict[int, str] = {1: "age-x25519"}

_HEAD = struct.Struct(
    ">2sBBBBBH16s"
)  # magic, version, protection, sig_count, threshold, count, capacity, set_id
_FILE_FIELDS = struct.Struct(">B32s")
_PAYLOAD_HEAD = struct.Struct(">BH")

Rng = Callable[[int], bytes]


@dataclass(frozen=True)
class Backup:
    shares: tuple[str, ...] = dc_field(repr=False)
    backup_id: str
    protection: int
    threshold: int
    count: int
    capacity: int


@dataclass(frozen=True)
class ShareInfo:
    backup_id: str
    protection: int
    threshold: int
    count: int
    index: int
    capacity: int
    signature_algs: tuple[int, ...] = ()
    file_format: int | None = None
    file_hash: bytes | None = None
    version: int = VERSION


@dataclass(frozen=True)
class Recovered:
    data: bytes = dc_field(repr=False)
    kind: str
    backup_id: str
    protection: int
    identity_verified: bool
    file_format: int | None = None
    file_hash: bytes | None = None
    unverified_signatures: tuple[int, ...] = ()

    def text(self) -> str:
        if self.kind != "text":
            raise TypeError("This backup holds binary data; use .data.")
        return self.data.decode("utf-8")


@dataclass(frozen=True, repr=False)
class _Parsed:
    info: ShareInfo
    descriptor: bytes
    index: int
    value: bytes


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}.")
    return value


def backup_id(descriptor: bytes) -> str:
    return hashlib.sha256(ID_DOMAIN + descriptor).hexdigest()


def _descriptor(
    protection: int,
    threshold: int,
    count: int,
    capacity: int,
    set_id: bytes,
    file_format: int | None = None,
    file_hash: bytes | None = None,
    signers: Iterable[tuple[int, bytes]] = (),
) -> bytes:
    signers = tuple(signers)
    out = _HEAD.pack(b"SS", VERSION, protection, len(signers), threshold, count, capacity, set_id)
    if protection == PROTECTION_FILE:
        out += _FILE_FIELDS.pack(file_format, file_hash)
    for alg, public_key in signers:
        out += bytes([alg]) + public_key
    return out


def _payload(descriptor: bytes, kind: int, data: bytes, capacity: int) -> bytes:
    head = _PAYLOAD_HEAD.pack(kind, len(data)) + data + bytes(capacity - len(data))
    return head + hashlib.sha256(DIGEST_DOMAIN + descriptor + head).digest()[:DIGEST_LENGTH]


def _checksum(descriptor: bytes, index: int, value: bytes) -> bytes:
    return hashlib.sha256(CHECK_DOMAIN + descriptor + bytes([index]) + value).digest()[:CHECK_LENGTH]


def estimate_share_size(length: int, *, capacity: int | None = None) -> int:
    """Binary bytes per unsigned direct share, before Base32 and the prefix."""
    return _capacity(length, capacity) + _HEAD.size + 1 + PAYLOAD_OVERHEAD + CHECK_LENGTH


def _capacity(length: int, capacity: int | None) -> int:
    _integer(length, "Secret byte length", 0, MAX_CAPACITY)
    if capacity is None:
        return length
    _integer(capacity, "capacity", 0, MAX_CAPACITY)
    if capacity < length:
        raise ValueError("The secret exceeds the requested capacity.")
    return capacity


def _split(
    data: bytes,
    kind: int,
    threshold: int,
    count: int,
    capacity: int,
    protection: int,
    file_format: int | None,
    file_hash: bytes | None,
    rng: Rng,
) -> Backup:
    descriptor = _descriptor(protection, threshold, count, capacity, rng(16), file_format, file_hash)
    payload = _payload(descriptor, kind, data, capacity)
    shares = []
    for index, value in field.split(payload, threshold, count, coefficients=rng):
        shares.append(encode(descriptor + bytes([index]) + value + _checksum(descriptor, index, value)))
    backup = Backup(tuple(shares), backup_id(descriptor), protection, threshold, count, capacity)
    recovered = combine(backup.shares, expected_backup_id=backup.backup_id)
    if not hmac.compare_digest(recovered.data, data) or recovered.kind != ("text" if kind else "bytes"):
        raise RecoveryError("Backup creation self-check failed; nothing was produced.")
    return backup


def _counts(threshold: object, shares: object) -> tuple[int, int]:
    _integer(threshold, "threshold", 2, MAX_SHARES)
    _integer(shares, "shares", threshold, MAX_SHARES)  # type: ignore[arg-type]
    return threshold, shares  # type: ignore[return-value]


def split_bytes(
    secret: bytes,
    *,
    threshold: int,
    shares: int,
    capacity: int | None = None,
    _rng: Rng = secrets.token_bytes,
) -> Backup:
    if not isinstance(secret, bytes):
        raise TypeError("Secret must be bytes.")
    threshold, shares = _counts(threshold, shares)
    return _split(
        secret, 0, threshold, shares, _capacity(len(secret), capacity), PROTECTION_DIRECT, None, None, _rng
    )


def split_text(
    secret: str, *, threshold: int, shares: int, capacity: int | None = None, _rng: Rng = secrets.token_bytes
) -> Backup:
    if not isinstance(secret, str):
        raise TypeError("Secret must be text.")
    try:
        data = secret.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Secret must be valid UTF-8 text.") from None
    threshold, shares = _counts(threshold, shares)
    return _split(
        data, 1, threshold, shares, _capacity(len(data), capacity), PROTECTION_DIRECT, None, None, _rng
    )


def split_file_key(
    key: bytes,
    *,
    threshold: int,
    shares: int,
    file_format: int,
    file_hash: bytes,
    _rng: Rng = secrets.token_bytes,
) -> Backup:
    """Protection 2: share the 32-byte key of a file encrypted with a registered external format."""
    if not isinstance(key, bytes) or len(key) != FILE_KEY_LENGTH:
        raise ValueError("File key must be exactly 32 bytes.")
    if type(file_format) is not int or file_format not in FILE_FORMATS:
        raise ValueError("Unknown external file format ID.")
    if not isinstance(file_hash, bytes) or len(file_hash) != 32:
        raise ValueError("File hash must be the 32-byte SHA-256 of the ciphertext.")
    threshold, shares = _counts(threshold, shares)
    return _split(key, 0, threshold, shares, FILE_KEY_LENGTH, PROTECTION_FILE, file_format, file_hash, _rng)


def _parse(share: str, allow_unverified: Iterable[int]) -> _Parsed:
    raw = decode(share)
    if len(raw) < _HEAD.size:
        raise InvalidShare("Truncated share.")
    magic, version, protection, sig_count, threshold, count, capacity, set_id = _HEAD.unpack_from(raw)
    if magic != b"SS" or version != VERSION:
        raise UnsupportedVersion("Unsupported share version.")
    if protection not in (PROTECTION_DIRECT, PROTECTION_FILE):
        raise InvalidShare("Unknown protection ID.")
    if not 2 <= threshold <= count <= MAX_SHARES or capacity > MAX_CAPACITY:
        raise InvalidShare("Invalid threshold, share count, or capacity.")
    offset = _HEAD.size
    file_format = file_hash = None
    if protection == PROTECTION_FILE:
        if capacity != FILE_KEY_LENGTH:
            raise InvalidShare("File-key shares must have capacity 32.")
        if len(raw) < offset + _FILE_FIELDS.size:
            raise InvalidShare("Truncated share.")
        file_format, file_hash = _FILE_FIELDS.unpack_from(raw, offset)
        offset += _FILE_FIELDS.size
        if file_format not in FILE_FORMATS:
            raise InvalidShare("Unknown external file format ID.")
    algs = []
    for _ in range(sig_count):
        if len(raw) < offset + 1:
            raise InvalidShare("Truncated share.")
        alg = raw[offset]
        if alg not in SIGNATURE_ALGS:
            raise InvalidShare("Unknown signature algorithm ID; this share cannot be parsed.")
        algs.append(alg)
        offset += 1 + SIGNATURE_ALGS[alg][0]
    descriptor_end = offset
    value_length = capacity + PAYLOAD_OVERHEAD
    expected = descriptor_end + 1 + value_length + CHECK_LENGTH + sum(SIGNATURE_ALGS[a][1] for a in algs)
    if len(raw) != expected:
        raise InvalidShare("Share length does not match its descriptor.")
    descriptor = raw[:descriptor_end]
    index = raw[descriptor_end]
    if not 1 <= index <= count:
        raise InvalidShare("Share index must be between 1 and the declared count.")
    value = raw[descriptor_end + 1 : descriptor_end + 1 + value_length]
    check = raw[descriptor_end + 1 + value_length : descriptor_end + 1 + value_length + CHECK_LENGTH]
    if not hmac.compare_digest(_checksum(descriptor, index, value), check):
        raise InvalidChecksum("Share checksum failed: check the copied share for typos.")
    allowed = set(allow_unverified)
    unsupported = sorted({a for a in algs if a not in allowed})
    if unsupported:
        raise UnsupportedSignature(
            f"This reader cannot verify signature algorithm(s) {unsupported}; "
            "pass allow_unverified to proceed without verification."
        )
    info = ShareInfo(
        backup_id(descriptor),
        protection,
        threshold,
        count,
        index,
        capacity,
        tuple(algs),
        file_format,
        file_hash,
    )
    return _Parsed(info, descriptor, index, value)


def inspect_share(share: str, *, allow_unverified: Iterable[int] = ()) -> ShareInfo:
    """Validate a single share and return its public metadata. Never reconstructs."""
    return _parse(share, allow_unverified).info


def combine(
    shares: Iterable[str],
    *,
    expected_backup_id: str | None = None,
    allow_unverified: Iterable[int] = (),
) -> Recovered:
    if isinstance(shares, (str, bytes)) or not isinstance(shares, Iterable):
        raise InvalidShare("Pass a collection of share strings.")
    allow = tuple(allow_unverified)
    parsed: list[_Parsed] = []
    seen: set[int] = set()
    for share in shares:
        if len(parsed) >= MAX_SHARES:
            raise InvalidShare("At most 255 shares may be supplied.")
        point = _parse(share, allow)
        if parsed and point.descriptor != parsed[0].descriptor:
            raise MixedBackups("Shares belong to different backups.")
        if point.index in seen:
            raise DuplicateShare("Duplicate share index; copies never count as additional shares.")
        seen.add(point.index)
        parsed.append(point)
    if not parsed:
        raise InsufficientShares("No shares supplied.")
    first = parsed[0]
    info = first.info
    if expected_backup_id is not None:
        if (
            not isinstance(expected_backup_id, str)
            or len(expected_backup_id) != 64
            or any(c not in "0123456789abcdefABCDEF" for c in expected_backup_id)
        ):
            raise IdentityMismatch("Expected backup ID must be the full 64-character hexadecimal ID.")
        if not hmac.compare_digest(info.backup_id, expected_backup_id.lower()):
            raise IdentityMismatch("Backup does not match the expected backup ID.")
    if len(parsed) < info.threshold:
        raise InsufficientShares(f"Collected {len(parsed)} of {info.threshold} required shares.")
    chosen = sorted(parsed, key=lambda p: p.index)[: info.threshold]
    payload = field.combine([(p.index, p.value) for p in chosen])
    head, digest = payload[:-DIGEST_LENGTH], payload[-DIGEST_LENGTH:]
    expected_digest = hashlib.sha256(DIGEST_DOMAIN + first.descriptor + head).digest()[:DIGEST_LENGTH]
    if not hmac.compare_digest(digest, expected_digest):
        raise RecoveryError(
            "Recovery integrity check failed: one or more shares are wrong. No secret returned."
        )
    kind, length = _PAYLOAD_HEAD.unpack_from(head)
    if kind not in (0, 1) or length > info.capacity or any(head[3 + length :]):
        raise RecoveryError("Invalid payload encoding.")
    if info.protection == PROTECTION_FILE and (kind != 0 or length != FILE_KEY_LENGTH):
        raise RecoveryError("Invalid file-key payload.")
    data = head[3 : 3 + length]
    if kind == 1:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise RecoveryError("Invalid text encoding in payload.") from None
    unverified = tuple(a for a in info.signature_algs if a in allow)
    return Recovered(
        data,
        "text" if kind else "bytes",
        info.backup_id,
        info.protection,
        expected_backup_id is not None,
        info.file_format,
        info.file_hash,
        unverified,
    )
