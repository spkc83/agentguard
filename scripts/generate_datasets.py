"""Generate on-demand synthetic credit datasets.

The repository does not ship pre-materialized parquet files — datasets are
regenerated deterministically from `SyntheticCreditGenerator` so that
checked-in binaries and real PII never collide. This script writes JSONL (and
parquet when `pyarrow` is installed) into `datasets/` with reproducible seeds.

Usage:
    python scripts/generate_datasets.py                  # defaults: all sets
    python scripts/generate_datasets.py --size 50000 --seed 1
    python scripts/generate_datasets.py --dataset applications
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentguard.domains.finance.synthetic.generators import SyntheticCreditGenerator

DATASETS = {
    "applications": {
        "dir": "synthetic_credit_applications_v1",
        "default_rate": 0.08,
        "description": "Consumer loan applications with synthetic demographic proxies.",
    },
    "performance": {
        "dir": "synthetic_loan_performance_v1",
        "default_rate": 0.12,
        "description": "Loan-level performance with higher default rate for vintage analysis.",
    },
    "compliance_eval": {
        "dir": "credit_agent_compliance_eval_v1",
        "default_rate": 0.35,
        "description": "Decision scenarios biased toward edge/adverse cases for policy testing.",
    },
}


def _write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def _try_write_parquet(records: list[dict[str, Any]], path: Path) -> bool:
    try:
        import pandas as pd
    except ImportError:
        return False
    try:
        pd.DataFrame(records).to_parquet(path, index=False)
        return True
    except (ImportError, ValueError):
        return False


def _generate_one(name: str, size: int, seed: int, root: Path) -> Path:
    spec = DATASETS[name]
    generator = SyntheticCreditGenerator(seed=seed, default_rate=spec["default_rate"])
    records = generator.generate(n_samples=size)

    target_dir = root / spec["dir"]
    target_dir.mkdir(parents=True, exist_ok=True)

    jsonl_path = target_dir / "data.jsonl"
    _write_jsonl(records, jsonl_path)

    parquet_path = target_dir / "data.parquet"
    wrote_parquet = _try_write_parquet(records, parquet_path)

    meta = {
        "dataset": spec["dir"],
        "description": spec["description"],
        "size": size,
        "seed": seed,
        "default_rate_target": spec["default_rate"],
        "formats": ["jsonl"] + (["parquet"] if wrote_parquet else []),
    }
    (target_dir / "metadata.json").write_text(json.dumps(meta, indent=2))
    return target_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        choices=[*DATASETS.keys(), "all"],
        default="all",
        help="Which dataset to regenerate (default: all).",
    )
    parser.add_argument("--size", type=int, default=10000, help="Rows per dataset.")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("datasets"),
        help="Output root (default: ./datasets).",
    )
    args = parser.parse_args()

    names = list(DATASETS) if args.dataset == "all" else [args.dataset]
    for name in names:
        path = _generate_one(name, args.size, args.seed + hash(name) % 1000, args.out)
        print(f"Wrote {name} -> {path}")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
