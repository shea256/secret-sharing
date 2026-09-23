import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

from secretsharing import combine, inspect_share
from secretsharing.encoding import decode

ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "spec" / "vectors" / "v1.json").read_text(encoding="utf-8"))


def test_vectors_file_is_current():
    result = subprocess.run([sys.executable, str(ROOT / "spec" / "generate_vectors.py"), "--check"])
    assert result.returncode == 0, "run: uv run python spec/generate_vectors.py"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vector_recovers(case):
    shares = case["shares_text"]
    for share in shares:
        info = inspect_share(share)
        assert info.backup_id == case["backup_id"]
        raw = decode(share)
        assert raw.startswith(bytes.fromhex(case["descriptor_hex"]))
        assert len(raw) == case["share_bytes"]
    for subset in itertools.combinations(shares, case["threshold"]):
        result = combine(subset, expected_backup_id=case["backup_id"])
        if case["kind"] == "text":
            assert result.text() == case["secret"]
        elif case["kind"] == "bytes":
            assert result.data == bytes.fromhex(case["secret_hex"])
        else:
            assert result.data == bytes.fromhex(case["key_hex"])
            assert result.file_format == case["file_format"]
            assert result.file_hash == bytes.fromhex(case["file_hash_hex"])
