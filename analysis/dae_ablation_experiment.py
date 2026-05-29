"""Compare PCA latent features against a denoising-autoencoder latent space.

This script is intentionally an analysis harness, not production code. It keeps
the existing AIS-Detect unsupervised rule:

    BENIGN train only -> fit preprocessing/latent model/NSA/calibration
    labelled attack rows -> used only after prediction for metrics

Run from the repository root, for example:

    .venv\\Scripts\\python.exe analysis\\dae_ablation_experiment.py ^
        --dataset datasets\\cicids2017\\Portscan-Friday-no-metadata.parquet
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.exceptions import ConvergenceWarning
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPRegressor
import warnings

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.evaluator import evaluate_model, threshold_analysis
from app.core.preprocessor import CICIDSPreprocessor
from app.models.nsa import NegativeSelectionDetector


@dataclass
class ExperimentConfig:
    dataset: str
    benign_limit: int
    attack_limit: int
    target_fpr: float
    max_detectors: int
    max_attempts: int
    latent_dim: str
    dae_noise_std: float
    dae_hidden_width: int
    dae_max_iter: int
    random_state: int


def _pct(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.2f}%"


def _clean_records(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _clean_records(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_records(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean_records(v) for v in obj]
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def _prepare_data(
    dataset: Path,
    benign_limit: int,
    attack_limit: int,
    random_state: int,
):
    prep = CICIDSPreprocessor(n_pca_components=None)
    df_raw = prep._load(dataset, filename=dataset.name)
    df_raw, label_col = prep._find_label_col(df_raw)

    num_cols = df_raw.select_dtypes(include=[np.number]).columns
    df_raw[num_cols] = df_raw[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    df_raw, y_all = prep._encode_labels(df_raw, label_col)
    df_benign = df_raw.loc[y_all == 0].reset_index(drop=True)
    df_attack = df_raw.loc[y_all != 0].reset_index(drop=True)

    if benign_limit and len(df_benign) > benign_limit:
        df_benign = df_benign.sample(n=benign_limit, random_state=random_state).reset_index(drop=True)
    if attack_limit and len(df_attack) > attack_limit:
        df_attack = df_attack.sample(n=attack_limit, random_state=random_state).reset_index(drop=True)

    df_train_raw, df_holdout_raw = train_test_split(
        df_benign,
        test_size=0.40,
        random_state=random_state,
        shuffle=True,
    )
    df_cal_raw, df_test_raw = train_test_split(
        df_holdout_raw,
        test_size=0.50,
        random_state=random_state,
        shuffle=True,
    )

    prep.fit(df_train_raw)
    X_train, _ = prep.transform_df(df_train_raw)
    X_cal, _ = prep.transform_df(df_cal_raw)
    X_test, df_test_meta = prep.transform_df(df_test_raw)

    df_eval_raw = pd.concat([df_test_raw, df_attack], ignore_index=True)
    X_eval, df_eval_meta = prep.transform_df(df_eval_raw)
    y_eval = (
        df_eval_meta["attack_category"]
        .fillna("Unknown")
        .astype(str)
        .str.lower()
        .ne("normal")
        .astype(int)
        .to_numpy()
    )

    return {
        "preprocessor": prep,
        "X_train": X_train,
        "X_cal": X_cal,
        "X_test": X_test,
        "X_eval": X_eval,
        "y_eval": y_eval,
        "df_eval_meta": df_eval_meta,
        "counts": {
            "total_rows": int(len(df_raw)),
            "benign_rows_available": int((y_all == 0).sum()),
            "attack_rows_available": int((y_all != 0).sum()),
            "benign_rows_used": int(len(df_benign)),
            "attack_rows_used": int(len(df_attack)),
            "benign_train": int(len(df_train_raw)),
            "benign_calibration": int(len(df_cal_raw)),
            "benign_test": int(len(df_test_raw)),
            "eval_rows": int(len(df_eval_raw)),
        },
    }


def _activation(values: np.ndarray, name: str) -> np.ndarray:
    if name == "identity":
        return values
    if name == "logistic":
        return 1.0 / (1.0 + np.exp(-values))
    if name == "tanh":
        return np.tanh(values)
    if name == "relu":
        return np.maximum(values, 0.0)
    raise ValueError(f"Unsupported MLP activation: {name}")


def _hidden_output(model: MLPRegressor, X: np.ndarray, hidden_layer_index: int) -> np.ndarray:
    out = np.asarray(X, dtype=np.float32)
    for idx in range(hidden_layer_index + 1):
        out = out @ model.coefs_[idx] + model.intercepts_[idx]
        out = _activation(out, model.activation)
    return out.astype(np.float32)


def _fit_pca_features(data: dict[str, Any], random_state: int):
    pca = PCA(n_components=0.95, whiten=True, svd_solver="full", random_state=random_state)
    X_train = pca.fit_transform(data["X_train"]).astype(np.float32)
    return {
        "name": "PCA + NSA",
        "transformer": pca,
        "latent_dim": int(pca.n_components_),
        "X_train": X_train,
        "X_cal": pca.transform(data["X_cal"]).astype(np.float32),
        "X_eval": pca.transform(data["X_eval"]).astype(np.float32),
        "extra": {
            "explained_variance_ratio_sum": float(np.sum(pca.explained_variance_ratio_)),
        },
    }


def _fit_dae_features(data: dict[str, Any], latent_dim: int, config: ExperimentConfig):
    rng = np.random.default_rng(config.random_state)
    X_train = np.asarray(data["X_train"], dtype=np.float32)
    noisy_train = X_train + rng.normal(0.0, config.dae_noise_std, size=X_train.shape).astype(np.float32)

    hidden_layers = (
        int(config.dae_hidden_width),
        int(latent_dim),
        int(config.dae_hidden_width),
    )
    dae = MLPRegressor(
        hidden_layer_sizes=hidden_layers,
        activation="tanh",
        solver="adam",
        alpha=1e-4,
        batch_size=256,
        learning_rate_init=1e-3,
        max_iter=int(config.dae_max_iter),
        early_stopping=True,
        validation_fraction=0.10,
        n_iter_no_change=8,
        random_state=config.random_state,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ConvergenceWarning)
        dae.fit(noisy_train, X_train)

    train_recon = dae.predict(X_train)
    cal_recon = dae.predict(data["X_cal"])
    return {
        "name": "Denoising AE latent + NSA",
        "transformer": dae,
        "latent_dim": int(latent_dim),
        "X_train": _hidden_output(dae, data["X_train"], hidden_layer_index=1),
        "X_cal": _hidden_output(dae, data["X_cal"], hidden_layer_index=1),
        "X_eval": _hidden_output(dae, data["X_eval"], hidden_layer_index=1),
        "extra": {
            "hidden_layers": list(hidden_layers),
            "activation": dae.activation,
            "noise_std": config.dae_noise_std,
            "n_iter": int(dae.n_iter_),
            "final_loss": float(dae.loss_),
            "train_reconstruction_mse": float(np.mean((train_recon - data["X_train"]) ** 2)),
            "cal_reconstruction_mse": float(np.mean((cal_recon - data["X_cal"]) ** 2)),
        },
    }


def _evaluate_representation(features: dict[str, Any], data: dict[str, Any], config: ExperimentConfig):
    started = time.perf_counter()
    nsa = NegativeSelectionDetector(
        max_detectors=config.max_detectors,
        max_attempts=config.max_attempts,
        random_state=config.random_state,
    )
    nsa.fit(features["X_train"])
    calibration = nsa.calibrate_threshold(features["X_cal"], target_fpr=config.target_fpr)
    labels, confidence = nsa.predict_with_scores(features["X_eval"])
    raw_scores = nsa.anomaly_scores(features["X_eval"])
    components = nsa.decision_components(features["X_eval"])
    metrics = evaluate_model(
        data["y_eval"],
        labels.astype(int),
        features["name"],
        data["df_eval_meta"],
    ).to_dict()
    metrics["threshold_analysis"] = threshold_analysis(
        data["y_eval"],
        raw_scores,
        model_name=f"{features['name']} threshold analysis",
        target_fpr=(0.0, config.target_fpr),
        forced_positive_mask=np.asarray(components.get("v_detector_match"), dtype=bool),
    )
    metrics["confidence_mean_anomaly"] = (
        float(np.mean(confidence[labels == 1])) if int(labels.sum()) else None
    )
    return {
        "name": features["name"],
        "latent_dim": features["latent_dim"],
        "training_seconds": round(time.perf_counter() - started, 3),
        "nsa_summary": nsa.summary(),
        "nsa_calibration": calibration,
        "representation": features["extra"],
        "metrics": metrics,
    }


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Denoising Autoencoder Ablation Result",
        "",
        "## Dataset",
        "",
        f"- File: `{result['config']['dataset']}`",
    ]
    for key, value in result["data_counts"].items():
        lines.append(f"- {key}: {value:,}" if isinstance(value, int) else f"- {key}: {value}")

    lines.extend([
        "",
        "## Comparison",
        "",
        "| Representation | Latent Dim | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for run in result["runs"]:
        m = run["metrics"]
        lines.append(
            "| {name} | {dim} | {recall} | {fnr} | {fpr} | {precision} | {f1} | {tp} | {fn} | {fp} | {tn} |".format(
                name=run["name"],
                dim=run["latent_dim"],
                recall=_pct(m.get("recall")),
                fnr=_pct(m.get("false_negative_rate")),
                fpr=_pct(m.get("false_positive_rate")),
                precision=_pct(m.get("precision")),
                f1=_pct(m.get("f1")),
                tp=m.get("tp"),
                fn=m.get("fn"),
                fp=m.get("fp"),
                tn=m.get("tn"),
            )
        )

    winner = result["decision"]["winner"]
    lines.extend([
        "",
        "## Decision",
        "",
        f"- Winner: **{winner}**",
        f"- Reason: {result['decision']['reason']}",
        "",
        "## Notes",
        "",
        "- Labels are used only after prediction for metrics.",
        "- The denoising autoencoder is trained on BENIGN training rows only.",
        "- This script does not modify production model artifacts.",
    ])
    return "\n".join(lines) + "\n"


def _decide(runs: list[dict[str, Any]]) -> dict[str, str]:
    by_name = {run["name"]: run for run in runs}
    pca = by_name["PCA + NSA"]["metrics"]
    dae = by_name["Denoising AE latent + NSA"]["metrics"]

    pca_recall = pca.get("recall") or 0.0
    dae_recall = dae.get("recall") or 0.0
    pca_fpr = pca.get("false_positive_rate") or 0.0
    dae_fpr = dae.get("false_positive_rate") or 0.0
    pca_f1 = pca.get("f1") or 0.0
    dae_f1 = dae.get("f1") or 0.0

    recall_gain = dae_recall - pca_recall
    fpr_increase = dae_fpr - pca_fpr
    f1_gain = dae_f1 - pca_f1

    if recall_gain >= 0.05 and fpr_increase <= 0.03:
        return {
            "winner": "Denoising AE latent + NSA",
            "reason": (
                f"Recall improved by {recall_gain * 100:.2f} percentage points "
                f"while FPR increased by only {fpr_increase * 100:.2f} points."
            ),
        }
    if f1_gain >= 0.03 and fpr_increase <= 0.03:
        return {
            "winner": "Denoising AE latent + NSA",
            "reason": (
                f"F1 improved by {f1_gain * 100:.2f} percentage points "
                f"without a large FPR increase."
            ),
        }
    return {
        "winner": "PCA + NSA",
        "reason": (
            "Denoising AE did not produce a strong recall/F1 gain under the "
            "configured FPR tolerance."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="CIC-IDS-2017 CSV/Parquet file")
    parser.add_argument("--benign-limit", type=int, default=60_000)
    parser.add_argument("--attack-limit", type=int, default=5_000)
    parser.add_argument("--target-fpr", type=float, default=0.10)
    parser.add_argument("--max-detectors", type=int, default=1_000)
    parser.add_argument("--max-attempts", type=int, default=40_000)
    parser.add_argument("--latent-dim", default="pca", help="'pca' or explicit integer")
    parser.add_argument("--dae-noise-std", type=float, default=0.05)
    parser.add_argument("--dae-hidden-width", type=int, default=64)
    parser.add_argument("--dae-max-iter", type=int, default=60)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--out-dir", default="analysis/autoencoder_results")
    args = parser.parse_args()

    dataset = Path(args.dataset)
    if not dataset.exists():
        raise FileNotFoundError(dataset)

    config = ExperimentConfig(
        dataset=str(dataset),
        benign_limit=args.benign_limit,
        attack_limit=args.attack_limit,
        target_fpr=args.target_fpr,
        max_detectors=args.max_detectors,
        max_attempts=args.max_attempts,
        latent_dim=args.latent_dim,
        dae_noise_std=args.dae_noise_std,
        dae_hidden_width=args.dae_hidden_width,
        dae_max_iter=args.dae_max_iter,
        random_state=args.random_state,
    )

    started = time.perf_counter()
    data = _prepare_data(
        dataset,
        benign_limit=config.benign_limit,
        attack_limit=config.attack_limit,
        random_state=config.random_state,
    )
    pca_features = _fit_pca_features(data, random_state=config.random_state)
    if config.latent_dim == "pca":
        dae_latent_dim = pca_features["latent_dim"]
    else:
        dae_latent_dim = int(config.latent_dim)
    dae_features = _fit_dae_features(data, latent_dim=dae_latent_dim, config=config)

    runs = [
        _evaluate_representation(pca_features, data, config),
        _evaluate_representation(dae_features, data, config),
    ]
    result = {
        "config": asdict(config),
        "data_counts": data["counts"],
        "runs": runs,
        "decision": _decide(runs),
        "total_seconds": round(time.perf_counter() - started, 3),
    }
    result = _clean_records(result)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = dataset.stem.replace(" ", "_")
    json_path = out_dir / f"{stem}_dae_ablation.json"
    md_path = out_dir / f"{stem}_dae_ablation.md"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(result), encoding="utf-8")

    print(_render_markdown(result))
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
