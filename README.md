# Secret Sharing

Offline, self-contained threshold backups for short text and binary secrets. Any chosen threshold of distinct shares recovers the exact original bytes. Each share includes its recovery settings and encrypted payload, so no separate encrypted recovery file is required.

**This development checkout declares package version 1.0.0rc1 and currently emits the SS2 development format**, initially called protocol v2. It introduces breaking API changes and is not an independently audited production release. See [PROTOCOL.md](PROTOCOL.md) for the implemented format and [legacy recovery](#legacy-recovery) for existing backups.

The [protocol v1 design draft](PROTOCOL-V1-DRAFT.md) defines the direction for the first stable versioned protocol: direct sharing, configurable hybrid protection, and extensible signature algorithms. The original unversioned format is called **legacy v0** (historical package releases were 0.x, including 0.2.6). The planned v1 features are not implemented; the API and examples below describe the current SS2 development implementation. Existing SS2 tokens retain their encoding and recovery behavior.

## Install

Requires Python 3.11 or newer. From this checkout:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[qr]'
python examples/01_quickstart.py
```

The `[qr]` extra enables SVG QR export; use `-e .` if you do not need it. Activate `.venv` in each new terminal, or run `.venv/bin/python` directly. Examples can also load this checkout without installing the package if its dependencies are already available in the selected Python environment. Missing dependencies produce setup instructions, rather than an import traceback.

## Try it with sample data

Start with the [runnable examples](examples/README.md). They use synthetic secrets, run offline, and are exercised by the test suite:

```sh
python examples/01_quickstart.py          # Exact text and binary recovery
python examples/02_modes_and_padding.py   # Compare modes, padding, and sizes
python examples/03_profiles_and_files.py  # Profiles, labeled files, renamed recovery
python examples/04_expected_failures.py   # Learn the error types
python examples/05_legacy_migration.py    # Verify an old backup before migration
python examples/06_cli_walkthrough.py     # Run the actual CLI end-to-end
```

File examples clean up temporary demo output by default. Use `python examples/03_profiles_and_files.py --out ./demo-backup --qr` to keep a sample backup and QR copies. Editable [sample profiles](examples/profiles.toml) cover all supported creation settings.

## Python API

```python
from secretsharing import split_text, combine, inspect_share

backup = split_text("00my secret\n", threshold=2, shares=3)
# Store these separately. Each is an SS2: string.
share_a, share_b, share_c = backup.shares

info = inspect_share(share_a)  # Public metadata, without recovering the secret
result = combine([share_c, share_a], expected_backup_id=backup.backup_id)
assert result.text() == "00my secret\n"
```

Use `split_bytes(data, threshold=..., shares=...)` for arbitrary bytes and `result.data` after recovery. Text uses UTF-8 without normalization; leading zeros, whitespace, and newlines survive exactly. Empty secrets are supported. The maximum secret size is 4096 **bytes**. Threshold and count must satisfy `2 <= threshold <= shares <= 255`.

### Settings

| Setting | Default | Options |
|---|---|---|
| Threshold, share count | Explicit in the API | Wizard suggests 2-of-3 |
| `mode` | `"standard"` | `"signed"` adds individual-share signatures |
| `pad_to` | `None` (off) | 32, 64, 128, 256, 512, 1024, 2048, 4096 |
| Public filename label | None | Explicit ASCII label, up to 48 characters |
| Export | Text files | Optional SVG QR copies |

Padding works in **either** mode. The secret must fit the selected capacity. Without padding, share size exposes the secret's byte length; padding hides that length within the selected capacity. The algorithm, randomness, key sizes, authentication tags, and verification rules are fixed by the protocol.

```python
backup = split_text(
    "short password", threshold=3, shares=5,
    mode="signed", pad_to=256,
)
```

Standard uses a typo checksum and authenticated recovery. Signed also verifies individual shares against the backup's embedded signing key. Standard cannot generally identify a maliciously altered share whose checksum was recomputed, but recovery authentication will reject an incorrect reconstruction. A checksum passing is **not** proof of authenticity.

| 32-byte secret | Binary bytes/share | Base32 characters including `SS2:` |
|---|---:|---:|
| Standard, no padding | 108 | 177 |
| Signed, no padding | 200 | 324 |
| Signed, padded to 256 bytes | 424 | 683 |

Formatting separators are additional. `estimate_share_size(length, mode=..., pad_to=...)` returns the binary size.

### Identity and failures

`Backup.backup_id` is a full SHA-256 identifier of the encrypted envelope. Save it independently if you want to verify that a recovered backup is the one you originally created. An embedded signing key establishes consistency within a backup; it does not independently identify its creator. Without an expected ID, `combine` still verifies recovery but returns `identity_verified=False`.

`inspect_share` returns `ShareInfo` with version, mode, backup ID, threshold, count, index, capacity, and `verification` (`checksum_passed` or `signature_verified`). It never reconstructs the secret.

`combine` checks **all** supplied shares. It rejects invalid input, mixed backups/modes and duplicate indices. It uses the lowest-index threshold subset after validation and never silently searches for a working combination after authentication fails. Catch the public `ShareError` subclasses (`InvalidShare`, `InvalidChecksum`, `InvalidSignature`, `DuplicateShare`, `MixedBackups`, `InsufficientShares`, `IdentityMismatch`, `RecoveryError`). Secret bytes and full shares are omitted from object representations and error messages.

## Offline CLI

All commands also work as `python -m secretsharing`.

```sh
# Hidden text prompts, with a wizard suggesting 2-of-3:
secretsharing create --out ./backup

# Exact binary file input; Standard and no padding are defaults:
secretsharing create --input ./secret.bin --out ./backup \
  --threshold 2 --shares 3

# Individual-share verification and length padding:
secretsharing create --input ./secret.bin --out ./signed-backup \
  --threshold 3 --shares 5 --mode signed --pad-to 256 \
  --label family-backup --qr
```

The CLI displays effective settings and share sizes before generation. In a terminal it requests confirmation (`--yes` skips it). Scripts must supply threshold/count directly or through an explicitly selected profile. Text prompts disable echo; binary files are never trimmed or decoded. Original source filenames are **never** automatically exposed in share names.

Creation performs an authenticated recovery self-check, writes each share separately, reads the files back, and emits a nonsecret `backup-id.json` card. A filename looks like:

```text
family-backup--7e3a91bf20cd--share01-of05--need03--standard.ss2
```

Without a label, it starts with the shortened ID. The shortened ID is a display aid; only the full ID is used for identity verification. Labels are outside the encoded share. **Renaming files or copying just an SS2: string cannot change recovery.**

```sh
secretsharing inspect ./backup/*.ss2

# Check actual recovery without writing the secret:
secretsharing verify ./backup/*.ss2 --card ./backup/backup-id.json

# Write the authenticated original bytes to a new file:
secretsharing combine ./backup/*.ss2 \
  --card ./backup/backup-id.json --out ./recovered.bin

# Or enter shares through hidden, single-line paste prompts:
secretsharing combine --out ./recovered.bin
```

Keep the identification card independently if using it as an identity reference. `--expected-backup-id FULL_HEX_ID` is an alternative to `--card`. Neither is required for recovery. There are no recovery configuration profiles: each share contains the necessary protocol settings.

Interactive recovery checks each share and reports progress. Identical duplicates do not count twice; conflicting duplicates stop recovery. Batch recovery fails if any supplied share is invalid. Output files are created only after authentication succeeds and existing files are never overwritten. Plaintext stdout output requires explicit `--stdout`.

Files use private POSIX permissions (directories 0700, files 0600). Distribute shares to separate locations after export; leaving the full set together removes the benefit of the threshold. No telemetry, networking, automatic clipboard handling, or automatic deletion is performed. A failed export may leave a partial private directory; check the error and use a new destination when retrying.

QR exports are copies of complete shares, generated locally at error-correction level M. Shares too large for one QR remain available as text files; the CLI reports the skipped QR copies.

### Saved profiles

Profiles are TOML files that you explicitly select; nothing is automatically loaded from the working directory or home directory.

```toml
[profiles.personal]
threshold = 2
shares = 3
mode = "standard"
qr = false

[profiles.custody]
threshold = 3
shares = 5
mode = "signed"
pad_to = 256
label = "family-backup" # PUBLIC filename label
qr = true
```

```sh
secretsharing create --input ./secret.bin --out ./backup \
  --profile-file ./profiles.toml --profile custody \
  --threshold 2 --shares 3 --mode standard --no-padding --no-label --no-qr
```

Precedence is **explicit arguments → selected profile → built-in defaults**. Unknown options and invalid types are rejected. Use `pad_to = 0` in TOML to disable padding. Use `--no-padding`, `--no-label`, and `--no-qr` to clear profile values explicitly.

Python callers can use `load_profile` and `resolve_options` from `secretsharing.profiles`, then pass their resolved options to `split_bytes`/`split_text`. Use `export_backup` from `secretsharing.files` for labeled files and an identification card.

## Legacy recovery

The old `SecretSharer` classes, raw point APIs, and mutable charset settings are replaced by the current development API. Old unversioned shares (legacy v0) are read only through `secretsharing.legacy`; new legacy shares cannot be created. SS2 errors never trigger legacy fallback.

```python
from secretsharing.legacy import recover_secret

candidate = recover_secret(
    ["1-2", "2-0"], prime=7, original_length=4,
)
assert candidate.secret == "0004"
assert not candidate.verified
```

Supported formats: `hex`, `text` (historical `string.printable`), `bitcoin-b58`, `bitcoin-b32`, and `bitcoin-zb32`. Python callers may supply explicit `share_charset` and `secret_charset` instead. Legacy recovery is bounded to 255 shares and fields of at most 1280 bits.

When no original prime is provided, the historical prime guess is preserved and `inferred_prime=True`. This may recover the **wrong** secret. Even with the original prime, legacy shares cannot authenticate the result. Original string lengths may also have been lost. Supply `original_length` only when known.

An independently known SHA-256 digest of the exact UTF-8 original string can be passed as `expected_sha256` to verify a candidate. A mismatch is an error. Never calculate this reference from the candidate itself.

```sh
secretsharing legacy recover old-share-1.txt old-share-2.txt \
  --format hex --prime 7 --original-length 4 \
  --expected-sha256 YOUR_INDEPENDENT_64_CHARACTER_DIGEST --out recovered.txt
```

Without an independent digest, CLI export requires deliberate `--accept-unverified` and is labeled unverified. To try migration with this development build, independently verify the recovered string first, then create an SS2 backup using `split_text`; use binary file creation only if you intentionally want a bytes payload. Retain original shares until replacement recovery is verified. Missing legacy field/length information cannot always be repaired.

## Development

```sh
python -m pip install -r requirements-dev.txt
python -m pip install -e '.[qr]'
python -m pytest
# Measure branches and include subprocess CLI executions:
python -m coverage erase
python -m coverage run -m pytest
python -m coverage combine
python -m coverage report
python -m build
```

Tests cover all small-set threshold subsets, maximum counts, independent field reconstruction, fixed synthetic vectors, corruption, recomputed malicious checksums, signature stripping, legacy ambiguity, configuration precedence, renamed files, private permissions, and no-overwrite behavior. Hypothesis generates additional binary/Unicode secrets, settings, subsets, malformed encodings, and fragment forgeries. Failure-path tests exercise hidden-input refusal, cancellations, randomness failure, missing QR dependencies, invalid identity cards, and export readback failures. Every runnable example is tested.

CI tests Python 3.11–3.14, enforces at least 90% combined line-and-branch coverage across the library and CLI (including subprocesses), builds distributions, and runs the CLI example against an installed wheel outside the checkout. Coverage measures exercised code, not cryptographic security. Independent protocol review and real-world recovery drills remain necessary before relying on this release for high-value backups; see [PROTOCOL.md](PROTOCOL.md) and [SECURITY.md](SECURITY.md).
