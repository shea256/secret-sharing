"""Offline command-line interface. Plaintext reaches stdout only with --stdout."""

import argparse
import getpass
import hashlib
import secrets
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from . import agefmt, legacy
from .errors import ShareError
from .files import export_backup, read_limited, read_share, write_private
from .protocol import (
    FILE_KEY_LENGTH,
    MAX_CAPACITY,
    PROTECTION_FILE,
    Recovered,
    combine,
    estimate_share_size,
    inspect_share,
    split_bytes,
    split_file_key,
    split_text,
)

PAD_CHOICES = tuple(2**n for n in range(5, 17))  # 32 .. 65536 (capped at MAX_CAPACITY)


def _algs(text: str | None) -> tuple[int, ...]:
    if not text:
        return ()
    try:
        return tuple(int(part) for part in text.split(","))
    except ValueError:
        raise SystemExit("--allow-unverified takes comma-separated numeric algorithm IDs.") from None


def _load_shares(paths: Sequence[str]) -> list[str]:
    if paths:
        return [read_share(path) for path in paths]
    print("Paste one share per line; finish with an empty line.", file=sys.stderr)
    shares = []
    while True:
        line = sys.stdin.readline()
        if not line.strip():
            break
        shares.append(line.strip())
    return shares


def _confirm(args: argparse.Namespace, message: str) -> None:
    if args.yes or not sys.stdin.isatty():
        return
    if input(f"{message} Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
        raise SystemExit("Cancelled.")


def _report_export(backup, paths) -> None:
    print(f"Backup ID: {backup.backup_id}")
    print(f"Record the backup ID separately; it is public and lets you verify recovery later.")
    print(f"Wrote {len(paths)} shares, any {backup.threshold} recover the secret:")
    for path in paths:
        print(f"  {path}")
    print("Distribute the shares to separate places now; a full set together defeats the threshold.")


def cmd_create(args: argparse.Namespace) -> int:
    capacity = None if args.capacity in (None, 0) else min(args.capacity, MAX_CAPACITY)
    if args.input:
        data = read_limited(args.input, MAX_CAPACITY)
        size = estimate_share_size(len(data), capacity=capacity)
        _confirm(args, f"{args.threshold}-of-{args.shares} shares of {len(data)} bytes, {size} bytes per share.")
        backup = split_bytes(data, threshold=args.threshold, shares=args.shares, capacity=capacity)
    else:
        if not sys.stdin.isatty():
            raise SystemExit("Text secrets are read from a hidden terminal prompt; use --input for files.")
        first = getpass.getpass("Secret text (hidden): ")
        if getpass.getpass("Repeat secret text: ") != first:
            raise SystemExit("Entries differ; nothing written.")
        size = estimate_share_size(len(first.encode("utf-8")), capacity=capacity)
        _confirm(args, f"{args.threshold}-of-{args.shares} shares, {size} bytes per share.")
        backup = split_text(first, threshold=args.threshold, shares=args.shares, capacity=capacity)
    _report_export(backup, export_backup(backup, args.out))
    return 0


def cmd_create_file(args: argparse.Namespace) -> int:
    tools = agefmt.find_age()
    if tools is None:
        raise SystemExit("create-file needs the age and age-keygen binaries (https://age-encryption.org), "
                         "or install secretsharing-files for in-process encryption.")
    source = Path(args.file)
    if not source.is_file():
        raise SystemExit(f"{source} is not a file.")
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    key = secrets.token_bytes(FILE_KEY_LENGTH)
    recipient = agefmt.recipient_from_identity(agefmt.identity_from_key(key))
    ciphertext = out / (source.name + ".age")
    subprocess.run([tools[0], "-r", recipient, "-o", str(ciphertext), str(source)], check=True)
    file_hash = hashlib.sha256(read_limited(ciphertext, 1 << 40)).digest()
    backup = split_file_key(key, threshold=args.threshold, shares=args.shares, file_format=1, file_hash=file_hash)
    paths = export_backup(backup, out / "shares")
    print(f"Encrypted file: {ciphertext}")
    print(f"Ciphertext SHA-256: {file_hash.hex()}")
    print("Keep copies of the encrypted file; the shares alone cannot recover it.")
    _report_export(backup, paths)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    allow = _algs(args.allow_unverified)
    for path in args.shares:
        info = inspect_share(read_share(path), allow_unverified=allow)
        line = (f"{Path(path).name}: share {info.index} of {info.count}, need {info.threshold}, "
                f"capacity {info.capacity}, protection {info.protection}, backup {info.backup_id}")
        if info.file_format is not None:
            line += f", file format {info.file_format}, ciphertext sha256 {info.file_hash.hex()}"
        if info.signature_algs:
            line += f", signatures {list(info.signature_algs)} (not verified by this reader)"
        print(line)
    return 0


def _recover(args: argparse.Namespace) -> Recovered:
    result = combine(_load_shares(args.shares), expected_backup_id=args.expected_backup_id,
                     allow_unverified=_algs(args.allow_unverified))
    if result.unverified_signatures:
        print(f"WARNING: signature algorithm(s) {list(result.unverified_signatures)} were NOT verified.",
              file=sys.stderr)
    if result.protection == PROTECTION_FILE and args.file:
        actual = hashlib.sha256(read_limited(args.file, 1 << 40)).digest()
        if actual != result.file_hash:
            raise SystemExit("Ciphertext SHA-256 does not match the hash recorded in the shares. "
                             "This is not the file this backup protects.")
    return result


def cmd_verify(args: argparse.Namespace) -> int:
    result = _recover(args)
    identity = "verified against the supplied ID" if result.identity_verified else "not independently verified"
    print(f"Recovery OK ({result.kind}, {len(result.data)} bytes). Backup ID {result.backup_id}, {identity}.")
    if result.protection == PROTECTION_FILE:
        print(f"Protects ciphertext sha256 {result.file_hash.hex()}"
              + (" (matches the supplied file)." if args.file else "; pass --file to check a file."))
    return 0


def cmd_combine(args: argparse.Namespace) -> int:
    result = _recover(args)
    if result.protection == PROTECTION_FILE:
        if not args.file:
            raise SystemExit("These shares protect an encrypted file; pass --file CIPHERTEXT.")
        if not args.out:
            raise SystemExit("Pass --out PATH for the recovered age identity file.")
        identity = agefmt.identity_from_key(result.data)
        write_private(args.out, (identity + "\n").encode("ascii"))
        print(f"Wrote age identity to {args.out}. Decrypt with:")
        print(f"  age -d -i {args.out} -o RECOVERED_FILE {args.file}")
        if args.decrypt:
            tools = agefmt.find_age()
            if tools is None:
                raise SystemExit("age is not installed; run the command above where it is.")
            subprocess.run([tools[0], "-d", "-i", args.out, "-o", args.decrypt, args.file], check=True)
            print(f"Decrypted to {args.decrypt}.")
        print("Delete the identity file when you are done with it.")
        return 0
    if args.stdout:
        sys.stdout.buffer.write(result.data)
        sys.stdout.buffer.flush()
        return 0
    if not args.out:
        raise SystemExit("Pass --out PATH, or --stdout to print the secret.")
    write_private(args.out, result.data)
    print(f"Wrote {len(result.data)} bytes to {args.out}.")
    return 0


def cmd_legacy(args: argparse.Namespace) -> int:
    result = legacy.recover_secret(_load_shares(args.shares), format=args.format, prime=args.prime,
                                   original_length=args.original_length, expected_sha256=args.expected_sha256)
    if not result.verified and not args.accept_unverified:
        raise SystemExit("Legacy candidate is UNVERIFIED (no independent digest matched). "
                         "Pass --expected-sha256, or --accept-unverified to export anyway.")
    note = "verified" if result.verified else "UNVERIFIED"
    if result.inferred_prime:
        note += ", prime guessed historically (may be wrong)"
    if args.stdout:
        sys.stdout.write(result.secret)
        sys.stdout.flush()
        return 0
    if not args.out:
        raise SystemExit("Pass --out PATH, or --stdout to print the candidate.")
    write_private(args.out, result.secret.encode("utf-8"))
    print(f"Wrote legacy candidate ({note}) to {args.out}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretsharing", description="Offline threshold secret backups (protocol v1).")
    sub = parser.add_subparsers(dest="command", required=True)

    def counts(p):
        p.add_argument("--threshold", type=int, required=True, help="shares needed to recover")
        p.add_argument("--shares", type=int, required=True, help="total shares to create")
        p.add_argument("--out", required=True, help="new directory for share files")
        p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    def recovery(p):
        p.add_argument("shares", nargs="*", help="share files; omit to paste shares on stdin")
        p.add_argument("--expected-backup-id", help="independently recorded 64-hex backup ID")
        p.add_argument("--allow-unverified", metavar="ALGS",
                       help="comma-separated signature algorithm IDs to leave unverified (labels the result)")
        p.add_argument("--file", help="ciphertext to check against a file-key backup")

    p = sub.add_parser("create", help="split text (hidden prompt) or a file's bytes")
    counts(p)
    p.add_argument("--input", help="binary file to split exactly; omit for a hidden text prompt")
    p.add_argument("--capacity", type=int, choices=(0, *PAD_CHOICES), metavar="N",
                   help="pad to N bytes to hide the exact length (power of two 32..65536; 0 = off)")
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("create-file", help="encrypt a large file with age and split its key")
    counts(p)
    p.add_argument("--file", required=True, help="file to encrypt")
    p.set_defaults(func=cmd_create_file)

    p = sub.add_parser("inspect", help="show public metadata; never reconstructs")
    p.add_argument("shares", nargs="+")
    p.add_argument("--allow-unverified", metavar="ALGS")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("verify", help="check that recovery works without writing the secret")
    recovery(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("combine", help="recover the secret to a new file, or an age identity for file backups")
    recovery(p)
    p.add_argument("--out", help="new output path (secret bytes, or age identity for file backups)")
    p.add_argument("--stdout", action="store_true", help="print the secret bytes instead of writing a file")
    p.add_argument("--decrypt", metavar="PATH", help="file backups: also run age to decrypt to PATH")
    p.set_defaults(func=cmd_combine)

    p = sub.add_parser("legacy", help="explicit recovery of unversioned (v0) shares")
    legacy_sub = p.add_subparsers(dest="legacy_command", required=True)
    p = legacy_sub.add_parser("recover")
    p.add_argument("shares", nargs="*")
    p.add_argument("--format", default="hex", choices=sorted(legacy.FORMATS))
    p.add_argument("--prime", type=int, help="original field prime, if known")
    p.add_argument("--original-length", type=int, help="original string length, if known")
    p.add_argument("--expected-sha256", help="independent SHA-256 hex of the exact original string")
    p.add_argument("--accept-unverified", action="store_true")
    p.add_argument("--out")
    p.add_argument("--stdout", action="store_true")
    p.set_defaults(func=cmd_legacy)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ShareError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except FileExistsError as error:
        print(f"error: refusing to overwrite {error.filename}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
