# Security

## Status

Protocol v1 and this implementation are new. They have not been independently reviewed. Do not treat passing tests as a security proof. Report issues privately to the maintainer before disclosure.

## What is protected

- **Confidentiality (direct sharing).** Fewer than `threshold` shares are statistically independent of the secret, given uniformly random coefficients. The coefficients come from the operating system CSPRNG, so the practical assumption is that the CSPRNG is sound. No cipher is involved.
- **Confidentiality (file backups).** Rests on age's X25519 + ChaCha20-Poly1305 construction and on the sharing of the identity as above.
- **Integrity.** A 16-byte digest inside the shared payload rejects wrong reconstructions. A party with fewer than `threshold` shares cannot forge a passing reconstruction except with probability 2^-128 per attempt. A 4-byte per-share checksum catches transcription errors.
- **Attribution (optional).** With `--signed`, each share carries an Ed25519 signature under a per-backup key, so an altered share is identified before reconstruction. This does not identify the creator and does not detect a malicious creator's inconsistent shares.
- **Identity.** The backup ID is a hash of public metadata and a random set ID. Recorded independently, it detects wholesale replacement of a backup. Nothing in a share identifies who created it.

## What is not protected

- A coalition holding `threshold` shares knows the secret; that is the design.
- A malicious creator can issue inconsistent shares. Nothing here is verifiable secret sharing.
- Share size reveals the payload capacity. Use `--capacity` to pad.
- Threshold, count, index, capacity, set ID, and (for file backups) the ciphertext hash are public.
- Pure-Python GF(2^8) table lookups are not constant-time. The threat model is an offline operation on a machine the user controls.
- Python cannot guarantee that secrets are erased from memory or swap.
- Ed25519 is implemented in pure Python. Signing keys are per backup and single-use, so timing leakage of the signing key has no lasting value; verification handles only public data. ML-DSA-65 lives in the extension. A reader lacking a verifier refuses the share unless the user explicitly allows the unverified algorithm, and the result is labeled.

## Operational rules

- Everything runs offline. There is no networking, telemetry, or clipboard access.
- Share files and recovered secrets are created with mode 0600 in 0700 directories and never overwrite existing paths.
- Plaintext reaches stdout only with `--stdout`. Text secrets are entered through hidden prompts.
- Distribute shares to separate places immediately. A full set in one location has no threshold.
- Keep copies of `.age` ciphertexts for file backups. Shares alone cannot recover the file.
- Legacy v0 recovery returns an unverified candidate unless an independent digest matches. Do not discard old shares on the strength of a plausible-looking result.

## Review priorities

Coefficient independence per byte and per share; exact descriptor and payload framing; the digest covering descriptor and padding; checksum and digest domain separation; parser bounds before any arithmetic; refusal paths for unknown IDs; the age implementation's header MAC, stanza handling, and STREAM last-chunk rules; file-creation atomicity and permissions.
