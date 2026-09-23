"""secretsharing-files: create and recover backups with in-process age encryption and ML-DSA-65."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from secretsharing.errors import ShareError
from secretsharing.files import read_share, write_private

from . import create_backup, recover, recover_file


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secretsharing-files")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create", help="split a file directly if small, or encrypt it and split the key")
    p.add_argument("--file", required=True)
    p.add_argument("--threshold", type=int, required=True)
    p.add_argument("--shares", type=int, required=True)
    p.add_argument("--out", required=True, help="new directory")
    p.add_argument("--protection", choices=("auto", "direct", "file"), default="auto")
    p.add_argument("--signed", action="store_true", help="add an Ed25519 signature to every share")
    p.add_argument("--post-quantum", action="store_true", help="also add ML-DSA-65 (implies --signed)")
    p.add_argument("--qr", action="store_true", help="write an SVG QR copy of each share (needs qrcode)")
    p = sub.add_parser(
        "combine", help="recover a secret, or decrypt an age-encrypted file from its key shares"
    )
    p.add_argument("shares", nargs="+", help="share files")
    p.add_argument("--file", help="the .age ciphertext (file backups)")
    p.add_argument("--out", required=True, help="new output path")
    p.add_argument("--expected-backup-id")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            backup = create_backup(
                args.file,
                threshold=args.threshold,
                shares=args.shares,
                out=args.out,
                protection=args.protection,
                signed=args.signed,
                post_quantum=args.post_quantum,
                qr=args.qr,
            )
            kind = "encrypted file + key shares" if backup.protection == 2 else "direct shares"
            print(f"Backup ID: {backup.backup_id}\nWrote {kind} to {args.out}")
            if args.qr:
                shares_dir = Path(args.out) / "shares" if backup.protection == 2 else Path(args.out)
                if len(list(shares_dir.glob("*.svg"))) < backup.count:
                    print("Some shares were too large for a single QR symbol; no SVG written for them.")
            return 0
        shares = [read_share(s) for s in args.shares]
        if args.file:
            path = recover_file(shares, args.file, args.out, expected_backup_id=args.expected_backup_id)
            print(f"Decrypted to {path}")
            return 0
        result = recover(shares, expected_backup_id=args.expected_backup_id)
        if result.protection == 2:
            raise SystemExit("These shares protect an encrypted file; pass --file CIPHERTEXT.")
        write_private(args.out, result.data)
        print(f"Wrote {len(result.data)} bytes to {args.out}")
        return 0
    except ShareError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except FileExistsError as error:
        print(f"error: refusing to overwrite {error.filename}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
