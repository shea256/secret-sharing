# secretsharing

Offline, self-describing threshold secret sharing with **no third-party dependencies**. Split a password, key, or document of up to 64 KiB into `n` shares so that any `k` recover the exact bytes and fewer than `k` reveal nothing (Shamir over GF(2^8), information-theoretic). Every share carries its own settings; recovery never needs a side file, profile, or filename.

```sh
pip install secretsharing            # core
pip install 'secretsharing[qr]'      # optional SVG QR export

secretsharing create --threshold 2 --shares 3 --out ./backup        # hidden text prompt
secretsharing create --input seed.bin --threshold 3 --shares 5 --out ./backup --signed
secretsharing inspect ./backup/*.ss.txt
secretsharing verify  ./backup/*.ss.txt --expected-backup-id <ID>
secretsharing combine ./backup/*.ss.txt --out recovered.bin
```

```python
from secretsharing import split_text, combine

backup = split_text("00my secret\n", threshold=2, shares=3)
assert combine(backup.shares[1:], expected_backup_id=backup.backup_id).text() == "00my secret\n"
```

- A 16-byte digest inside the shared payload rejects wrong reconstructions; a 4-byte per-share checksum catches typos first.
- `--signed` adds a per-share Ed25519 signature (pure Python, RFC 8032) so an altered share is identified before reconstruction.
- Large files: `create-file` encrypts with the `age` binary and shares the 32-byte identity, or install `secretsharing-files` for in-process encryption and ML-DSA-65 post-quantum signatures.
- Legacy 0.x `x-y` shares: `secretsharing legacy recover`, explicit and clearly labeled unverified unless an independent digest matches.

Wire format: [PROTOCOL.md](https://github.com/shea256/secret-sharing/blob/master/PROTOCOL.md). Security notes: [SECURITY.md](https://github.com/shea256/secret-sharing/blob/master/SECURITY.md). Protocol v1 has not been independently reviewed.
