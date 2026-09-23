import hashlib
import secrets
import subprocess
import sys

from secretsharing import inspect_share
from secretsharing.files import read_share
from secretsharing_files import create_backup, create_file_backup, recover_file


def test_file_backup_round_trip(tmp_path):
    source = tmp_path / "doc.pdf"
    source.write_bytes(secrets.token_bytes(100_000))
    out = tmp_path / "out"
    backup = create_file_backup(source, threshold=2, shares=3, out=out)
    ciphertext = out / "doc.pdf.age"
    shares = [read_share(p) for p in sorted((out / "shares").glob("*.ss.txt"))]
    info = inspect_share(shares[0])
    assert (backup.protection, info.file_format, info.file_hash) == (
        2,
        1,
        hashlib.sha256(ciphertext.read_bytes()).digest(),
    )
    recovered = recover_file(
        shares[1:], ciphertext, tmp_path / "doc.recovered", expected_backup_id=backup.backup_id
    )
    assert recovered.read_bytes() == source.read_bytes()


def test_auto_selection_boundary(tmp_path):
    small = tmp_path / "small.bin"
    small.write_bytes(b"x" * 65535)
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 65536)
    assert create_backup(small, threshold=2, shares=2, out=tmp_path / "a").protection == 1
    assert create_backup(big, threshold=2, shares=2, out=tmp_path / "b").protection == 2
    assert create_backup(small, threshold=2, shares=2, out=tmp_path / "c", protection="file").protection == 2


def test_cli(tmp_path):
    source = tmp_path / "big.bin"
    source.write_bytes(secrets.token_bytes(70_000))
    out = tmp_path / "out"

    def run(*a):
        return subprocess.run(
            [sys.executable, "-m", "secretsharing_files", *map(str, a)], capture_output=True, text=True
        )

    created = run("create", "--file", source, "--threshold", "2", "--shares", "3", "--out", out)
    assert created.returncode == 0 and "encrypted file" in created.stdout
    shares = sorted((out / "shares").glob("*.ss.txt"))
    plain = tmp_path / "plain.bin"
    combined = run("combine", shares[0], shares[2], "--file", out / "big.bin.age", "--out", plain)
    assert combined.returncode == 0, combined.stderr
    assert plain.read_bytes() == source.read_bytes()
    wrong = tmp_path / "wrong.age"
    wrong.write_bytes(b"nope")
    assert run("combine", shares[0], shares[1], "--file", wrong, "--out", tmp_path / "x").returncode == 1
