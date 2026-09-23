# secretsharing-files

Extension for [`secretsharing`](https://pypi.org/project/secretsharing/) that adds, via `cryptography`:

- **In-process age encryption** for large-file backups (protocol v1, protection 2): encrypt a file to a fresh X25519 identity, share the identity, record the ciphertext hash in the shares. Interoperable with the reference `age` tool in both directions.
- **Automatic mode selection**: files up to 64 KiB are shared directly, larger ones are encrypted and key-shared.
- **ML-DSA-65 post-quantum signatures** (algorithm 2), always paired with Ed25519; both must verify.

```sh
pip install secretsharing-files

secretsharing-files create --file archive.tar --threshold 2 --shares 3 --out ./backup --post-quantum
secretsharing-files combine ./backup/shares/*.ss.txt --file ./backup/archive.tar.age --out archive.tar
```

```python
from secretsharing_files import create_backup, recover_file

backup = create_backup("archive.tar", threshold=2, shares=3, out="backup")
recover_file(shares, "backup/archive.tar.age", "archive.tar", expected_backup_id=backup.backup_id)
```

The core package alone can always recover the key shares and hand you an age identity file; this package is only needed to avoid the `age` binary, or to create and verify ML-DSA-65 signatures.
