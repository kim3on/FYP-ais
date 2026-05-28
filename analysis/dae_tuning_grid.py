"""Tune denoising-autoencoder representations for AIS-Detect.

This is an offline ablation runner. It does not update production artifacts.

Example:

    .venv\\Scripts\\python.exe analysis\\dae_tuning_grid.py ^
        --dataset datasets\\cicids2017\\Portscan-Friday-no-metadata.parquet ^
        --target-fpr 0.13
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

ANALYSIS_DIR = Path(__file__).resolve().parent
ROOT = ANALYSIS_DIR.parents[0]
if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dae_ablation_experiment import (  # noqa: E402
    ExperimentConfig,
    _clean_records,
    _evaluate_representation,
    _fit_dae_features,
    _fit_pca_features,
    _pct,
    _prepare_data,
)


def _parse_ints(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def _parse_floats(value: str) -> list[float]:
    return [float(part.strip()) for part in value.split(",") if part.strip()]


def _metric(run: dict[str, Any], name: str) -> float:
    value = run["metrics"].get(name)
    return float(value or 0.0)


def _best_feasible(runs: list[dict[str, Any]], fpr_limit: float) -> dict[str, Any] | None:
    feasible = [run for run in runs if _metric(run, "false_positive_rate") <= fpr_limit]
    if not feasible:
        return None
    return max(
        feasible,
        key=lambda run: (
            _metric(run, "recall"),
            _metric(run, "f1"),
            -_metric(run, "false_positive_rate"),
        ),
    )


def _run_dataset(args, dataset: Path) -> dict[str, Any]:
    started = time.perf_counter()
    data = _prepare_data(
        dataset,
        benign_limit=args.benign_limit,
        attack_limit=args.attack_limit,
        random_state=args.random_state,
    )

    base_config = ExperimentConfig(
        dataset=str(dataset),
        benign_limit=args.benign_limit,
        attack_limit=args.attack_limit,
        target_fpr=args.target_fpr,
        max_detectors=args.max_detectors,
        max_attempts=args.max_attempts,
        latent_dim="grid",
        dae_noise_std=0.0,
        dae_hidden_width=args.dae_hidden_width,
        dae_max_iter=args.dae_max_iter,
        random_state=args.random_state,
    )

    pca_features = _fit_pca_features(data, random_state=args.random_state)
    baseline = _evaluate_representation(pca_features, data, base_config)
    baseline["grid"] = {
        "representation": "pca",
        "latent_dim": baseline["latent_dim"],
        "noise_std": None,
        "hidden_width": None,
    }

    dae_runs: list[dict[str, Any]] = []
    latent_dims = _parse_ints(args.latent_dims)
    noise_stds = _parse_floats(args.noise_stds)
    total = len(latent_dims) * len(noise_stds)
    current = 0
    for latent_dim in latent_dims:
        for noise_std in noise_stds:
            current += 1
            print(
                f"[{dataset.stem}] DAE grid {current}/{total}: "
                f"latent_dim={latent_dim}, noise_std={noise_std}"
            )
            config = ExperimentConfig(
                dataset=str(dataset),
                benign_limit=args.benign_limit,
                attack_limit=args.attack_limit,
                target_fpr=args.target_fpr,
                max_detectors=args.max_detectors,
                max_attempts=args.max_attempts,
                latent_dim=str(latent_dim),
                dae_noise_std=float(noise_std),
                dae_hidden_width=args.dae_hidden_width,
                dae_max_iter=args.dae_max_iter,
                random_state=args.random_state,
            )
            features = _fit_dae_features(data, latent_dim=latent_dim, config=config)
            run = _evaluate_representation(features, data, config)
            run["grid"] = {
                "representation": "dae",
                "latent_dim": int(latent_dim),
                "noise_std": float(noise_std),
                "hidden_width": int(args.dae_hidden_width),
            }
            dae_runs.append(run)

    fpr_limit = args.target_fpr + args.fpr_tolerance
    best_dae_feasible = _best_feasible(dae_runs, fpr_limit)
    best_dae_overall = max(
        dae_runs,
        key=lambda run: (
            _metric(run, "recall"),
            _metric(run, "f1"),
            -_metric(run, "false_positive_rate"),
        ),
    )

    decision = {
        "target_fpr": args.target_fpr,
        "fpr_limit": fpr_limit,
        "baseline": baseline["name"],
        "best_feasible_dae": best_dae_feasible["name"] if best_dae_feasible else None,
        "best_feasible_grid": best_dae_feasible.get("grid") if best_dae_feasible else None,
        "best_overall_dae_grid": best_dae_overall.get("grid"),
    }
    if best_dae_feasible is None:
        decision["winner"] = "PCA + NSA"
        decision["reason"] = "No DAE configuration stayed within the FPR limit."
    elif (
        _metric(best_dae_feasible, "recall") > _metric(baseline, "recall")
        and _metric(best_dae_feasible, "f1") > _metric(baseline, "f1")
    ):
        decision["winner"] = "Denoising AE latent + NSA"
        decision["reason"] = (
            "Best feasible DAE improved both Recall and F1 while staying within "
            f"FPR <= {fpr_limit * 100:.2f}%."
        )
    else:
        decision["winner"] = "PCA + NSA"
        decision["reason"] = (
            "Best feasible DAE did not beat PCA on both Recall and F1."
        )

    all_runs = [baseline] + sorted(
        dae_runs,
        key=lambda run: (
            _metric(run, "false_positive_rate") > fpr_limit,
            -_metric(run, "recall"),
            -_metric(run, "f1"),
            _metric(run, "false_positive_rate"),
        ),
    )
    return _clean_records({
        "dataset": str(dataset),
        "config": {
            "baseline": asdict(base_config),
            "latent_dims": latent_dims,
            "noise_stds": noise_stds,
            "fpr_limit": fpr_limit,
        },
        "data_counts": data["counts"],
        "decision": decision,
        "runs": all_runs,
        "total_seconds": round(time.perf_counter() - started, 3),
    })


def _run_row(run: dict[str, Any]) -> str:
    grid = run.get("grid", {})
    m = run["metrics"]
    cfg = "PCA" if grid.get("representation") == "pca" else (
        f"dim={grid.get('latent_dim')}, noise={grid.get('noise_std')}"
    )
    return (
        f"| {run['name']} | {cfg} | {_pct(m.get('recall'))} | "
        f"{_pct(m.get('false_negative_rate'))} | {_pct(m.get('false_positive_rate'))} | "
        f"{_pct(m.get('precision'))} | {_pct(m.get('f1'))} | "
        f"{m.get('tp')} | {m.get('fn')} | {m.get('fp')} | {m.get('tn')} |"
    )


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# DAE Tuning Grid Result",
        "",
        "## Dataset",
        "",
        f"- File: `{result['dataset']}`",
    ]
    for key, value in result["data_counts"].items():
        lines.append(f"- {key}: {value:,}" if isinstance(value, int) else f"- {key}: {value}")
    decision = result["decision"]
    lines.extend([
        "",
        "## Decision",
        "",
        f"- Winner: **{decision['winner']}**",
        f"- Reason: {decision['reason']}",
        f"- Target FPR: {decision['target_fpr'] * 100:.2f}%",
        f"- Accepted FPR limit: {decision['fpr_limit'] * 100:.2f}%",
        "",
        "## Results",
        "",
        "| Model | Config | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for run in result["runs"]:
        lines.append(_run_row(run))
    lines.extend([
        "",
        "## Notes",
        "",
        "- Autoencoder training uses BENIGN training rows only.",
        "- Labels are used only after prediction for metrics.",
        "- This is an offline experiment and does not update deployed artifacts.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--target-fpr", type=float, default=0.13)
    parser.add_argument("--fpr-tolerance", type=float, default=0.005)
    parser.add_argument("--benign-limit", type=int, default=60_000)
    parser.add_argument("--attack-limit", type=int, default=5_000)
    parser.add_argument("--latent-dims", default="8,16,24")
    parser.add_argument("--noise-stds", default="0.03,0.05,0.08")
    parser.add_argument("--dae-hidden-width", type=int, default=64)
    parser.add_argument("--dae-max-iter", type=int, default=50)
    parser.add_argument("--max-detectors", type=int, default=1_000)
    parser.add_argument("--max-attempts", type=int, default=40_000)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--out-dir", default="analysis/autoencoder_results/tuning_grid")
    args = parser.parse_args()

    dataset = Path(args.dataset)
    if not dataset.exists():
        raise FileNotFoundError(dataset)

    result = _run_dataset(args, dataset)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = dataset.stem.replace(" ", "_")
    json_path = out_dir / f"{stem}_dae_tuning_grid.json"
    md_path = out_dir / f"{stem}_dae_tuning_grid.md"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(result), encoding="utf-8")

    print(_render_markdown(result))
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
