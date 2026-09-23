# Secret Sharing protocol v1

Status: wire specification for the first stable versioned format. Package versions are independent of this wire version. The original unversioned share format is called **legacy v0** and is described only in the reference library's `legacy` module.

Design goals, in priority order: a reader can be reimplemented from this document alone with no third-party code; the core needs only a CSPRNG, SHA-256, and Base32; shares are self-describing; recovery never guesses.

## 1. Overview

A backup is a set of `count` shares. Any `threshold` distinct shares recover the exact original bytes. Shares are self-contained: no side file, profile, or filename is needed for recovery.

Two **protections** exist:

| ID | Name | What is shared |
|---:|---|---|
| 1 | direct | the secret itself (text or bytes, up to 65,535 bytes) |
| 2 | external file | a 32-byte key for a file encrypted with a registered external format |

Confidentiality in protection 1 is information-theoretic given uniformly random coefficients; in practice the coefficients come from the operating system CSPRNG. Protection 2 confidentiality is that of the external format.

Integrity comes from a 16-byte digest **inside** the shared payload, so it is hidden by the sharing and checked after reconstruction. A 4-byte per-share checksum detects transcription errors before reconstruction. Optional per-share signatures are defined for attribution; the reference core implements none and treats them per section 8.

## 2. Notation

All integers are unsigned big-endian. `u8` is one byte, `u16` two bytes. `||` is concatenation. `SHA256(x)[:n]` is the first `n` bytes of the SHA-256 digest. Domain strings are ASCII followed by a single zero byte:

```
DIGEST_DOMAIN = "secretsharing/v1/digest" || 0x00
CHECK_DOMAIN  = "secretsharing/v1/check"  || 0x00
ID_DOMAIN     = "secretsharing/v1/id"     || 0x00
SIGN_DOMAIN   = "secretsharing/v1/sign"   || 0x00
```

## 3. Field arithmetic

Sharing is byte-wise over GF(2^8) with the Rijndael reduction polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b). Addition is XOR. This is the same field as AES, SLIP-39, and HashiCorp Vault.

For each byte position `b` of the payload `P`, the creator picks `threshold - 1` uniformly random coefficient bytes `c_1 .. c_{k-1}` and evaluates

```
f_b(x) = P[b] + c_1·x + c_2·x^2 + ... + c_{k-1}·x^(k-1)
```

The share with index `i` (1..255) has `Y[b] = f_b(i)`. The secret is `f_b(0)`. Coefficients are independent across byte positions and across coefficient positions. Coefficients may be zero. Do not use the `ssss` extra `x^k` term.

Recovery with `k` distinct indices `x_1..x_k` computes, per byte,

```
P[b] = Σ_j Y_j[b] · λ_j        λ_j = Π_{m≠j} x_m / (x_m + x_j)
```

with all arithmetic in GF(2^8). Two shares with the same index are invalid input, never a second share.

## 4. Descriptor

Every share of a backup carries the identical descriptor `D`:

```
D = "SS"                 (2 bytes, 0x53 0x53)
 || version    : u8      = 1
 || protection : u8      1 or 2
 || sig_count  : u8      0..255
 || threshold  : u8      2..count
 || count      : u8      threshold..255
 || capacity   : u16     payload data capacity in bytes
 || set_id     : 16 bytes, uniformly random per backup, independent of the secret
 || [protection 2 only]  file_format : u8 || file_hash : 32 bytes
 || sig_count × ( alg : u8 || public_key : PK_LEN[alg] bytes )
```

Constraints: `2 <= threshold <= count <= 255`. Protection 1: `capacity <= 65535`. Protection 2: `capacity = 32`. Every `alg` must be in the signature registry (section 8) or the share cannot be parsed. `set_id` must come from the CSPRNG and must not be derived from the secret.

The **backup ID** is `SHA256(ID_DOMAIN || D)` rendered as 64 lowercase hex digits. It depends on no secret material. The first 12 hex digits are used in filenames as a display aid only.

## 5. Payload

The shared payload `P` has length `3 + capacity + 16`:

```
P = kind   : u8      0 = bytes, 1 = UTF-8 text
 || length : u16     actual data length, <= capacity
 || data   : length bytes
 || zeros  : capacity - length bytes
 || digest : 16 bytes = SHA256(DIGEST_DOMAIN || D || P[0 : 3 + capacity])[:16]
```

The digest covers the descriptor and the whole data area including padding. Protection 2 uses `kind = 0`, `length = 32`, `capacity = 32`, and `data` is the external-file key.

Text is UTF-8 without normalization. Leading zeros, whitespace, and newlines are preserved exactly. Empty data is valid. `capacity` may exceed `length` to hide the exact length; the creator chooses it, and the reference library offers powers of two from 32 to 65,536 capped at 65,535.

## 6. Share

```
S = D
 || index : u8            1..count
 || Y     : len(P) bytes  share of P at x = index
 || check : 4 bytes       SHA256(CHECK_DOMAIN || D || index || Y)[:4]
 || sig_count × signature_i : SIG_LEN[alg_i] bytes
```

Signature `i` is over `SIGN_DOMAIN || D || index || Y` using algorithm `alg_i` and public key `i` from `D`, in descriptor order. Signatures are excluded from every hash and from each other.

Share length is fully determined by `D`, so a parser computes the expected length before reading anything else and rejects any other length.

## 7. Text representation

```
SS:V1:B32:<Base32>
```

`Base32` is RFC 4648 upper-case Base32 of `S` with `=` padding removed. Writers emit one line for QR copies, or the prefix on its own line followed by the body in groups of eight characters joined by `-`, eight groups per line, for text files.

Readers accept only ASCII. Within the body, readers ignore `-`, space, tab, CR, and LF, and accept lower-case letters. Readers reject `=`, any other character, non-canonical trailing bits, and any body that does not re-encode to itself. The prefix comparison is case-insensitive. Readers must not accept other encodings under this prefix; a future encoding gets a different third field.

Filenames, directories, and labels are outside the format. The reference filename is `<first 12 hex of backup ID>--share<index, two digits>--<threshold>of<count>.ss.txt`. Renaming cannot affect recovery.

## 8. Signature registry

| alg | Algorithm | PK_LEN | SIG_LEN | Binding |
|---:|---|---:|---:|---|
| 1 | Ed25519 | 32 | 64 | PureEd25519 per RFC 8032, no context, no prehash |
| 2 | ML-DSA-65 | 1952 | 3309 | FIPS 204 pure ML-DSA, empty context |
| 3..127 | reserved | | | assigned only by a revision of this document |
| 128..255 | private use | | | never assigned; not interoperable |

IDs are immutable. Lengths are fixed by the ID; there are no length fields. The reference core implements algorithm 1 in pure Python; algorithm 2 is provided by the `secretsharing-files` package. A creator that adds algorithm 2 must also include algorithm 1. A reader that does not know an `alg` cannot compute the share length and must reject the share.

Verification policy is **all**: every listed signature must verify. A reader that knows an algorithm's lengths but has no verifier for it must refuse recovery by default. It may offer an explicit, non-default override that proceeds without verifying the unsupported algorithms; the result must then be labeled with the unverified algorithm IDs. A reader must never silently skip a signature, and must always verify every algorithm it supports.

Signatures from an honest creator detect altered shares and identify which share was altered. They do not prove that a malicious creator issued consistent shares, and they do not identify the creator: the public keys are per backup and live in the shares. Detecting replacement of a whole backup by another valid one requires the backup ID to be recorded independently.

## 9. External file formats (protection 2)

| file_format | Format | Shared key material |
|---:|---|---|
| 1 | age v1, X25519 recipient | the 32-byte age identity scalar |
| 2 | reserved for a chunked AES-256-GCM format | |
| 3..127 | reserved | |
| 128..255 | private use | |

`file_hash` is SHA-256 of the complete encrypted file. Recovery yields the key; readers should verify the ciphertext hash before attempting decryption and must report a mismatch.

For format 1, the identity string is bech32 (BIP-173 checksum, constant 1) with human-readable part `age-secret-key-` over the 32 bytes, rendered in upper case. The recipient is the corresponding X25519 public key in age's `age1...` encoding. Encrypt with `age -r <recipient>`; decrypt with `age -d -i <identity file>`. The reference core writes the identity file and prints the command; it does not implement X25519 or ChaCha20-Poly1305.

## 10. Creation

1. Validate inputs: `2 <= threshold <= count <= 255`, data length `<= capacity <= 65535` (protection 1) or exactly 32 (protection 2).
2. Draw `set_id` (16 bytes) from the CSPRNG, then any Ed25519 signing seed (32 bytes). Build `D`.
3. Build `P` per section 5.
4. Draw `(threshold - 1) × len(P)` coefficient bytes from the CSPRNG. Compute `Y` for every index `1..count`.
5. Assemble each `S`, compute its checksum, then any signatures.
6. Self-check: parse every share and recover from the lowest-index `threshold` shares; the result must equal the input. Emit nothing on failure.

## 11. Recovery

1. Decode text and bound its size before any other work.
2. Parse `D`, compute the expected share length, and reject a mismatch. Validate every field range. Verify the checksum. Verify every signature per section 8.
3. Require identical `D` across all supplied shares (otherwise **mixed backups**) and distinct indices (otherwise **duplicate share**). Duplicates never count toward the threshold.
4. If an independent backup ID was supplied, require it to match.
5. Require at least `threshold` shares. Interpolate from the `threshold` lowest indices. Do not search other subsets after a failure.
6. Verify the digest. On mismatch return nothing: one or more shares are wrong.
7. Check `kind ∈ {0, 1}`, `length <= capacity`, zero padding, and UTF-8 validity for text. Return exactly `data[0:length]`.

## 12. Limits

| Item | Limit |
|---|---:|
| protection 1 data and capacity | 65,535 bytes |
| shares per backup | 255 |
| shares supplied to recovery | 255 |
| share text | 262,144 bytes |
| signatures per share | 255, subject to the text limit |

## 13. Security notes

Public metadata: version, protection, threshold, count, capacity, set ID, signature algorithms and keys, share index, and, for protection 2, the file format and ciphertext hash. Hidden: kind, exact length, data, digest.

A per-share checksum is computed over data the share holder already possesses and reveals nothing to anyone else. The payload digest is deterministic in the secret but is itself shared, so fewer than `threshold` shares reveal nothing about it. A below-threshold party cannot make a reconstruction pass the digest except with probability 2^-128 per attempt, because interpolation is linear and the party does not know the secret.

The reference implementation is pure Python. Table-driven GF(2^8) arithmetic is not constant-time; the threat model is an offline operation on a machine the user controls. Python cannot guarantee erasure of secrets from memory.

## 14. Test vectors

`spec/vectors/v1.json` contains complete shares for fixed inputs generated with a deterministic test-only coefficient source, along with expected backup IDs, payload digests, and recovery results. Production code must never expose a deterministic coefficient source. Implementations must reproduce the vectors exactly.
