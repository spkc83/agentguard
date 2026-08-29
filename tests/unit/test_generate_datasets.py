"""Tests for scripts/generate_datasets.py — reproducibility guarantees.

The script advertises deterministic regeneration. That claim is only true if
the per-dataset seed offset is stable across processes, which rules out the
PYTHONHASHSEED-randomised builtin ``hash()``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "generate_datasets.py"


def _run(out_dir: Path, hash_seed: str) -> None:
    """Run the generator into ``out_dir`` with an explicit PYTHONHASHSEED."""
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(_SCRIPT),
            "--dataset",
            "applications",
            "--size",
            "50",
            "--out",
            str(out_dir),
        ],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr


def test_regeneration_is_stable_across_pythonhashseed(tmp_path: Path) -> None:
    """Two runs under different PYTHONHASHSEED values must be byte-identical.

    Covers both the generated rows and the recorded per-dataset seed, since
    the seed offset is what the salted builtin ``hash`` used to randomise.
    """
    a = tmp_path / "a"
    b = tmp_path / "b"
    _run(a, "1")
    _run(b, "2")

    dataset = "synthetic_credit_applications_v1"
    jsonl_a = a / dataset / "data.jsonl"
    jsonl_b = b / dataset / "data.jsonl"
    assert jsonl_a.exists()
    assert jsonl_b.exists()
    assert jsonl_a.read_bytes() == jsonl_b.read_bytes()

    meta_a = (a / dataset / "metadata.json").read_bytes()
    meta_b = (b / dataset / "metadata.json").read_bytes()
    assert meta_a == meta_b
