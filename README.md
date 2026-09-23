# Secret Sharing

Offline, self-describing threshold backups for secrets. Split a password, key, seed, or document into `n` shares so that any `k` of them recover the exact original bytes, and fewer than `k` reveal nothing. Every share carries its own recovery settings, so no side file, profile, or filename is needed to recover.

This repository holds the [protocol v1 specification](PROTOCOL.md) and two Python packages:

| Package | Depends on | Purpose |
|---|---|---|
| `secretsharing` | standard library only | Direct Shamir sharing up to 64 KiB, Ed25519 share signatures, share files, CLI, explicit legacy recovery |
| `secretsharing-files` | `secretsharing`, `cryptography` | In-process [age](https://age-encryption.org) encryption for large files, automatic mode selection, ML-DSA-65 signatures |

The core has no third-party dependencies on purpose: a reader written against the spec in any language, or this package on a bare Python install, will still work in twenty years. Large-file backups use age, which has independent Go and Rust implementations, so decryption never depends on this project.

**Status:** protocol v1 is new and has not been independently reviewed. See [SECURITY.md](SECURITY.md).

## How it works

- **Direct sharing (protection 1).** The secret itself is Shamir-shared byte-wise over GF(2^8). Fewer than `k` shares carry no information about it. A 16-byte digest inside the shared payload catches wrong or damaged shares after reconstruction, and a 4-byte checksum on each share catches typos before it.
- **File backups (protection 2).** Files above 64 KiB are encrypted with age to a fresh X25519 identity, and the 32-byte identity is shared instead. Shares record the ciphertext's SHA-256, so recovery knows which file they protect. You need the encrypted file *and* `k` shares.
- **Shares are text:** `SS:V1:B32:` followed by Base32, wrapped for printing and QR-friendly. Filenames are cosmetic.
- **Optional signatures.** Ed25519 per share in the core; ML-DSA-65 post-quantum signatures via the extension.

## Install

Requires Python 3.11 or newer.

```sh
pip install secretsharing          # core, no dependencies
pip install 'secretsharing[qr]'    # optional SVG QR export
pip install secretsharing-files    # optional: in-process age encryption, ML-DSA-65
```

From this checkout, with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run secretsharing --help
```

## Command line

Create shares from a hidden text prompt or from a file's exact bytes:

```sh
secretsharing create --threshold 2 --shares 3 --out ./backup
secretsharing create --input ./seed.bin --threshold 3 --shares 5 --out ./backup --capacity 64
```

`--capacity N` pads the payload to `N` bytes (a power of two from 32 to 65536) so the share size does not reveal the secret's exact length. The command prints the **backup ID**. Write it down somewhere separate: it is public, and it lets you confirm later that a recovered secret is the one you created.

Share files look like `7e3a91bf20cd--share01--2of3.ss.txt`. Rename or move them freely.

```sh
secretsharing inspect ./backup/*.ss.txt                          # metadata only, never reconstructs
secretsharing verify  ./backup/*.ss.txt --expected-backup-id ID  # proves recovery works, writes nothing
secretsharing combine ./backup/*.ss.txt --out ./recovered.bin    # writes the secret to a new file
secretsharing combine --stdout                                   # paste shares on stdin, print the secret
```

Recovery uses the lowest-index `k` shares after validating all of them. It rejects mixed backups, duplicate indices, and shares whose checksum fails, and it returns nothing if the reconstructed payload fails its digest.

### Large files

With the `age` and `age-keygen` binaries installed, the core CLI encrypts the file and splits the key:

```sh
secretsharing create-file --file ./archive.tar --threshold 2 --shares 3 --out ./backup
# writes ./backup/archive.tar.age and ./backup/shares/*.ss.txt

secretsharing combine ./backup/shares/*.ss.txt --file ./backup/archive.tar.age \
    --out ./identity.txt --decrypt ./archive.tar
```

Without `--decrypt` the command writes the age identity and prints the `age -d` command to run. With `secretsharing-files` installed, everything happens in-process and mode selection is automatic:

```sh
secretsharing-files create --file ./anything --threshold 2 --shares 3 --out ./backup
secretsharing-files combine ./backup/shares/*.ss.txt --file ./backup/anything.age --out ./anything
```

Keep copies of the encrypted file. The shares alone cannot recover it.

## Python API

```python
from secretsharing import split_text, split_bytes, combine, inspect_share

backup = split_text("00my secret\n", threshold=2, shares=3)
backup.shares  # three "SS:V1:B32:..." strings; store them separately
backup.backup_id  # public 64-hex identifier; record it independently

info = inspect_share(backup.shares[0])  # threshold, count, index, capacity, backup_id
result = combine(backup.shares[1:], expected_backup_id=backup.backup_id)
assert result.text() == "00my secret\n"
assert result.identity_verified
```

`split_bytes` takes arbitrary bytes; use `result.data` afterwards. Text is UTF-8 without normalization, so leading zeros and newlines survive. Empty secrets are valid. Both accept `capacity=` for padding.

Errors are subclasses of `secretsharing.ShareError`: `InvalidShare`, `UnsupportedVersion`, `InvalidChecksum`, `UnsupportedSignature`, `MixedBackups`, `DuplicateShare`, `InsufficientShares`, `IdentityMismatch`, `RecoveryError`. Messages and `repr` never include secret bytes or share text.

For file backups: `split_file_key(key, threshold=, shares=, file_format=1, file_hash=)` in the core, and `create_file_backup`, `create_backup`, `recover_file` in `secretsharing_files`.

### Signatures

`--signed` (API: `signed=True`) adds a per-share Ed25519 signature so that an altered share is identified before reconstruction rather than only detected afterwards. The implementation is pure Python (RFC 8032, cross-checked against pyca) and the signing key is generated per backup, used once, and discarded. Signatures cost 97 bytes per share.

`secretsharing-files create --post-quantum` adds ML-DSA-65 alongside Ed25519; both must verify. Those shares are about 5 KiB each, so they suit files rather than paper. The core alone cannot verify ML-DSA-65: it refuses such shares unless you pass `--allow-unverified 2`, and then labels the result as not fully verified. Signatures are never skipped silently.

### QR copies

`--qr` writes an SVG QR code beside each share (`pip install 'secretsharing[qr]'`). Upper-case Base32 fits QR's alphanumeric mode, so a 32-byte secret is a comfortable symbol. Shares that exceed one symbol are reported and skipped.

| 32-byte secret | Bytes per share | Base32 characters |
|---|---:|---:|
| unsigned | 81 | 130 |
| signed (Ed25519) | 178 | 285 |
| signed + ML-DSA-65 | 5,440 | 8,704 |

## Legacy shares (v0)

Shares from the 0.x releases (`x-y` strings) did not record their field or the original string length, so some cannot be uniquely recovered. Recovery is explicit and returns an unverified candidate unless you supply an independently known SHA-256 of the original.

```sh
secretsharing legacy recover old1.txt old2.txt --format hex --prime 7 --original-length 4 \
    --expected-sha256 INDEPENDENT_DIGEST --out recovered.txt
```

Formats: `hex`, `text`, `bitcoin-b58`, `bitcoin-b32`, `bitcoin-zb32`. Without `--prime`, the historical guess is used and may be wrong. Verify a candidate independently before creating a v1 backup from it, and keep the old shares.

If your secret is a wallet seed, prefer [SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) with hardware wallet support. This project targets general small secrets and files.

## Development

```sh
uv sync
uv run pytest
uv run ruff check .
uv run python spec/generate_vectors.py   # after an intentional wire change only
```

Layout: `packages/secretsharing` (core), `packages/secretsharing-files` (extension), `spec/vectors/v1.json` (shared test vectors both packages must reproduce), `PROTOCOL.md` (the wire format). Interop tests against the reference `age` binary run when it is installed.
