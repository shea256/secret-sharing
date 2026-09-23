import secrets
import subprocess

import pytest
from secretsharing.agefmt import find_age, identity_from_key, recipient_from_identity
from secretsharing_files import age

AGE = find_age()


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 200_000])
def test_round_trip(size):
    key = secrets.token_bytes(32)
    plaintext = secrets.token_bytes(size)
    ciphertext = age.encrypt(plaintext, age.recipient_string(key))
    assert ciphertext.startswith(b"age-encryption.org/v1\n-> X25519 ")
    assert age.decrypt(ciphertext, key) == plaintext


def test_tamper_detection():
    key = secrets.token_bytes(32)
    ciphertext = bytearray(age.encrypt(b"hello", age.recipient_string(key)))
    header_end = ciphertext.index(b"--- ")
    ciphertext[header_end + 5] ^= 0x01  # header MAC
    with pytest.raises(age.AgeError):
        age.decrypt(bytes(ciphertext), key)
    ciphertext = bytearray(age.encrypt(b"hello", age.recipient_string(key)))
    ciphertext[-1] ^= 0x01
    with pytest.raises(age.AgeError):
        age.decrypt(bytes(ciphertext), key)
    with pytest.raises(age.AgeError):
        age.decrypt(age.encrypt(b"x", age.recipient_string(key)), secrets.token_bytes(32))
    with pytest.raises(age.AgeError):
        age.decrypt(b"not age", key)


@pytest.mark.skipif(AGE is None, reason="age binaries not installed")
@pytest.mark.parametrize("size", [0, 5, 65536, 150_000])
def test_interop_with_reference_age(tmp_path, size):
    key = secrets.token_bytes(32)
    identity = identity_from_key(key)
    assert age.recipient_string(key) == recipient_from_identity(identity)
    identity_file = tmp_path / "id.txt"
    identity_file.write_text(identity + "\n")
    plaintext = secrets.token_bytes(size)
    ours = tmp_path / "ours.age"
    ours.write_bytes(age.encrypt(plaintext, age.recipient_string(key)))
    decrypted = subprocess.run(
        [AGE[0], "-d", "-i", str(identity_file), str(ours)], capture_output=True, check=True
    )
    assert decrypted.stdout == plaintext
    theirs = subprocess.run(
        [AGE[0], "-r", age.recipient_string(key)], input=plaintext, capture_output=True, check=True
    )
    assert age.decrypt(theirs.stdout, key) == plaintext
