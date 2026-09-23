"""secretsharing-files: create and recover backups with in-process age encryption."""

import argparse
import sys
from collections.abc import Sequence

from secretsharing.errors import ShareError
from secretsharing.files import read_share

from . import create_backup, recover_file


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secretsharing-files")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create", help="split a file directly if small, or encrypt it and split the key")
    p.add_argument("--file", required=True)
    p.add_argument("--threshold", type=int, required=True)
    p.add_argument("--shares", type=int, required=True)
    p.add_argument("--out", required=True, help="new directory")
    p.add_argument("--protection", choices=("auto", "direct", "file"), default="auto")
    p = sub.add_parser("combine", help="decrypt an age-encrypted file from its key shares")
    p.add_argument("shares", nargs="+", help="share files")
    p.add_argument("--file", required=True, help="the .age ciphertext")
    p.add_argument("--out", required=True, help="new plaintext path")
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
            )
            kind = "encrypted file + key shares" if backup.protection == 2 else "direct shares"
            print(f"Backup ID: {backup.backup_id}\nWrote {kind} to {args.out}")
        else:
            path = recover_file(
                [read_share(s) for s in args.shares],
                args.file,
                args.out,
                expected_backup_id=args.expected_backup_id,
            )
            print(f"Decrypted to {path}")
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
