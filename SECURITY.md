# Security and release status

The SS2 development format (wire version 2) in package 1.0.0rc1 is a new composition of established primitives. It has not been independently audited. Independent review of the format, implementation, and test vectors is needed before describing it as a production-reviewed protocol. The [stable protocol v1 draft](PROTOCOL-V1-DRAFT.md) is a separate, unimplemented design; the guarantees below describe the running SS2 implementation.

## Guarantees and assumptions

Both Standard and Signed use AES-256-GCM and split a fresh random encryption key. Confidentiality of the encrypted secret is computational, not information-theoretic. Recovery authenticates the plaintext before returning it. No hash of the original password/secret is exposed for offline guessing.

The trusted creator must use an uncompromised machine and functioning operating-system randomness. Recovery must also happen on a trusted machine. This package provides no constant-time guarantee for Python Shamir arithmetic, memory-zeroization guarantee, malicious-dealer consistency proofs, or protection against a participant withholding shares. It does not provide post-quantum signatures. The 16-byte tag and Ed25519 signatures provide at most approximately 128-bit classical integrity strength; AES key size is not a claim of 256-bit security for every part of the protocol.

Standard's CRC32 detects copying errors, not deliberate manipulation. GCM detects a wrong reconstructed key or altered encrypted envelope. Signed additionally permits individual-share signature checks relative to the embedded signing key. Neither mode establishes the original backup's external identity unless a separately trusted full backup ID is checked.

Without padding, byte length is public. Padding hides the precise byte length within the explicitly selected capacity. Threshold, count, suite, capacity, and share index remain public. Public filename labels are opt-in.

## Operational behavior

All operations are local/offline. Secret text is read through hidden prompts; plaintext output to stdout is explicit. Share collections and recovered data are excluded from object representations and deliberate error messages. Callers remain responsible for their own logging and exception handling.

Export creates a new directory and separate files with private POSIX permissions. It never overwrites existing paths, including symlinks. An interrupted export can leave a partial directory; preserve original material until replacement recovery has been verified. Python and general-purpose filesystems cannot promise secure deletion. No file names from a share are used to choose a recovered output path.

## Legacy limitations

Unversioned shares omitted their field and original string length. Some cannot be uniquely reconstructed. Legacy recovery preserves historical inference only in an explicit legacy API and returns an unverified candidate. An original prime/length helps with correctness but is not authentication. Only an independent reference can verify the candidate. Do not replace old backups based solely on a successful-looking legacy interpolation.

## Review priorities

Review independent coefficient generation for both key halves; byte/field interoperability; exact framing, domains and lengths; authentication before output; signature verification and its identity boundary; downgrade resistance; checksum versus authentication UX; entropy failures; resource limits; legacy boundaries; filesystem behavior; and CLI/profile precedence.

Do not infer protocol security solely from passing tests or the absence of known dependency advisories.
