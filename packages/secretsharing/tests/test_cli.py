import hashlib
import secrets
import stat
import subprocess
import sys

import pytest
from secretsharing import agefmt, split_text
from secretsharing.encoding import format_lines


def run(*args, stdin=None, check=True):
    result = subprocess.run(
        [sys.executable, "-m", "secretsharing", *map(str, args)],
        capture_output=True,
        input=stdin,
        text=stdin is None or isinstance(stdin, str),
    )
    if check and result.returncode != 0:
        raise AssertionError(f"exit {result.returncode}: {result.stderr}")
    return result


def test_file_round_trip_permissions_and_rename(tmp_path):
    secret = bytes([0, 0, 255]) + secrets.token_bytes(40)
    source = tmp_path / "secret.bin"
    source.write_bytes(secret)
    out = tmp_path / "backup"
    result = run("create", "--input", source, "--threshold", "2", "--shares", "3", "--out", out, "--yes")
    backup_id = next(line.split()[-1] for line in result.stdout.splitlines() if line.startswith("Backup ID"))
    files = sorted(out.glob("*.ss.txt"))
    assert (
        len(files) == 3
        and files[0].name.startswith(backup_id[:12])
        and files[0].name.endswith("--2of3.ss.txt")
    )
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    renamed = tmp_path / "anything.txt"
    files[2].rename(renamed)
    assert "share 3 of 3" in run("inspect", renamed).stdout
    assert "Recovery OK" in run("verify", renamed, files[0], "--expected-backup-id", backup_id).stdout
    recovered = tmp_path / "recovered.bin"
    run("combine", files[0], renamed, "--out", recovered)
    assert recovered.read_bytes() == secret
    assert run("combine", files[0], renamed, "--stdout", stdin=b"", check=True).stdout == secret
    assert run("combine", files[0], renamed, "--out", recovered, check=False).returncode == 1  # no overwrite
    assert (
        run(
            "create",
            "--input",
            source,
            "--threshold",
            "2",
            "--shares",
            "3",
            "--out",
            out,
            "--yes",
            check=False,
        ).returncode
        == 1
    )
    assert run("combine", files[0], check=False).returncode == 2
    assert run("combine", files[0], files[1], check=False).returncode == 1  # needs --out or --stdout


def test_stdin_shares_and_wrong_id(tmp_path):
    backup = split_text("00hello\n", threshold=2, shares=2)
    pasted = "\n".join(backup.shares) + "\n\n"
    result = run("combine", "--stdout", stdin=pasted)
    assert result.stdout == "00hello\n"
    bad = run("verify", "--expected-backup-id", "0" * 64, stdin=pasted, check=False)
    assert bad.returncode == 2 and "does not match" in bad.stderr


def test_text_create_requires_terminal(tmp_path):
    result = run(
        "create", "--threshold", "2", "--shares", "2", "--out", tmp_path / "x", stdin="", check=False
    )
    assert result.returncode == 1 and "hidden terminal prompt" in result.stderr


def test_legacy_recover(tmp_path):
    out = tmp_path / "legacy.txt"
    digest = hashlib.sha256(b"0004").hexdigest()
    run(
        "legacy",
        "recover",
        "--prime",
        "7",
        "--original-length",
        "4",
        "--expected-sha256",
        digest,
        "--out",
        out,
        stdin="1-2\n2-0\n\n",
    )
    assert out.read_text() == "0004"
    unverified = run("legacy", "recover", "--prime", "7", "--stdout", stdin="1-2\n2-0\n\n", check=False)
    assert unverified.returncode == 1 and "UNVERIFIED" in unverified.stderr
    assert (
        run(
            "legacy", "recover", "--prime", "7", "--stdout", "--accept-unverified", stdin="1-2\n2-0\n\n"
        ).stdout
        == "4"
    )


@pytest.mark.skipif(agefmt.find_age() is None, reason="age binaries not installed")
def test_create_file_and_decrypt(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(secrets.token_bytes(200_000))
    out = tmp_path / "filebackup"
    result = run("create-file", "--file", big, "--threshold", "2", "--shares", "3", "--out", out, "--yes")
    ciphertext = out / "big.bin.age"
    assert ciphertext.exists() and hashlib.sha256(ciphertext.read_bytes()).hexdigest() in result.stdout
    shares = sorted((out / "shares").glob("*.ss.txt"))
    assert "protection 2" in run("inspect", shares[0]).stdout
    assert "matches the supplied file" in run("verify", shares[0], shares[2], "--file", ciphertext).stdout
    wrong = tmp_path / "wrong.age"
    wrong.write_bytes(b"not it")
    assert run("verify", shares[0], shares[1], "--file", wrong, check=False).returncode == 1
    identity = tmp_path / "identity.txt"
    plain = tmp_path / "plain.bin"
    assert (
        run("combine", shares[1], shares[2], "--file", wrong, "--out", identity, check=False).returncode == 1
    )
    assert not identity.exists()
    run("combine", shares[1], shares[2], "--file", ciphertext, "--out", identity, "--decrypt", plain)
    assert plain.read_bytes() == big.read_bytes()
    assert identity.read_text().startswith("AGE-SECRET-KEY-1")


def test_export_readback_and_format(tmp_path):
    backup = split_text("x", threshold=2, shares=2)
    text = format_lines(backup.shares[0])
    path = tmp_path / "s.ss.txt"
    path.write_text(text)
    assert run("inspect", path).stdout.startswith("s.ss.txt: share 1 of 2")
