"""Regenerate spec/vectors/v1.json.

The coefficient source is a SHA-256 counter stream seeded with a fixed string.
It exists only to make vectors reproducible; production code never exposes it.
Run: uv run python spec/generate_vectors.py
"""

import hashlib
import json
import sys
from pathlib import Path

from secretsharing import protocol
from secretsharing.encoding import decode

OUT = Path(__file__).with_name("vectors") / "v1.json"


def counter_stream(seed: str):
    counter = 0

    def draw(n: int) -> bytes:
        nonlocal counter
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed.encode() + counter.to_bytes(8, "big")).digest()
            counter += 1
        return out[:n]

    return draw


CASES = [
    {"name": "text-2of3-cap32", "seed": "vector-1", "kind": "text", "secret": "00demo café 🔑\n",
     "threshold": 2, "shares": 3, "capacity": 32},
    {"name": "bytes-3of5-nopad", "seed": "vector-2", "kind": "bytes", "secret_hex": "0001ff",
     "threshold": 3, "shares": 5, "capacity": None},
    {"name": "empty-2of2", "seed": "vector-3", "kind": "bytes", "secret_hex": "",
     "threshold": 2, "shares": 2, "capacity": None},
    {"name": "file-key-2of3-age", "seed": "vector-4", "kind": "file-key",
     "key_hex": "0f" * 32, "file_format": 1, "file_hash_hex": hashlib.sha256(b"ciphertext").hexdigest(),
     "threshold": 2, "shares": 3},
]


def build(case: dict) -> dict:
    rng = counter_stream(case["seed"])
    if case["kind"] == "text":
        backup = protocol.split_text(case["secret"], threshold=case["threshold"], shares=case["shares"],
                                     capacity=case["capacity"], _rng=rng)
    elif case["kind"] == "bytes":
        backup = protocol.split_bytes(bytes.fromhex(case["secret_hex"]), threshold=case["threshold"],
                                      shares=case["shares"], capacity=case["capacity"], _rng=rng)
    else:
        backup = protocol.split_file_key(bytes.fromhex(case["key_hex"]), threshold=case["threshold"],
                                         shares=case["shares"], file_format=case["file_format"],
                                         file_hash=bytes.fromhex(case["file_hash_hex"]), _rng=rng)
    raw = decode(backup.shares[0])
    descriptor_length = len(raw) - 1 - (backup.capacity + protocol.PAYLOAD_OVERHEAD) - protocol.CHECK_LENGTH
    return {**case, "descriptor_hex": raw[:descriptor_length].hex(), "backup_id": backup.backup_id,
            "share_bytes": len(raw), "shares_text": list(backup.shares)}


def main() -> int:
    document = {"protocol": "secretsharing v1", "note": "Deterministic test vectors; see PROTOCOL.md §14.",
                "cases": [build(case) for case in CASES]}
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        return 0 if OUT.read_text(encoding="utf-8") == text else 1
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
