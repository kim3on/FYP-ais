"""
Dataset profile helpers for AIS-Detect.

The system supports CICIDS2017 as the live-compatible dataset and NSL-KDD as
an offline batch benchmark.  Each dataset keeps its own model artifacts because
the feature schemas are not interchangeable.
"""

from __future__ import annotations

from dataclasses import dataclass
import os


DATASET_CICIDS2017 = "cicids2017"
DATASET_NSL_KDD = "nsl_kdd"
SUPPORTED_DATASETS = {DATASET_CICIDS2017, DATASET_NSL_KDD}

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
ARTEFACT_DIR = os.path.join(BASE_DIR, "artefacts")


@dataclass(frozen=True)
class ArtifactPaths:
    root: str
    nsa: str
    iso: str
    preprocessor: str
    self_boundary: str
    pca_self_boundary: str
    results: str


def normalize_dataset_type(dataset_type: str | None) -> str:
    value = (dataset_type or DATASET_CICIDS2017).strip().lower().replace("-", "_")
    aliases = {
        "cicids": DATASET_CICIDS2017,
        "cic_ids_2017": DATASET_CICIDS2017,
        "cicids_2017": DATASET_CICIDS2017,
        "nslkdd": DATASET_NSL_KDD,
        "nsl_kdd": DATASET_NSL_KDD,
    }
    value = aliases.get(value, value)
    if value not in SUPPORTED_DATASETS:
        raise ValueError(
            f"Unsupported dataset_type '{dataset_type}'. "
            f"Use one of: {', '.join(sorted(SUPPORTED_DATASETS))}."
        )
    return value


def artifact_paths(dataset_type: str | None = DATASET_CICIDS2017) -> ArtifactPaths:
    dataset = normalize_dataset_type(dataset_type)
    root = os.path.join(ARTEFACT_DIR, dataset)
    return ArtifactPaths(
        root=root,
        nsa=os.path.join(root, "nsa_model.pkl"),
        iso=os.path.join(root, "iso_model.pkl"),
        preprocessor=os.path.join(root, "preprocessor.pkl"),
        self_boundary=os.path.join(root, "self_boundary.pkl"),
        pca_self_boundary=os.path.join(root, "pca_self_boundary.pkl"),
        results=os.path.join(root, "last_train_result.json"),
    )


def legacy_cicids_paths() -> ArtifactPaths:
    """Root-level paths used before dataset-specific artifact folders existed."""
    return ArtifactPaths(
        root=ARTEFACT_DIR,
        nsa=os.path.join(ARTEFACT_DIR, "nsa_model.pkl"),
        iso=os.path.join(ARTEFACT_DIR, "iso_model.pkl"),
        preprocessor=os.path.join(ARTEFACT_DIR, "preprocessor.pkl"),
        self_boundary=os.path.join(ARTEFACT_DIR, "self_boundary.pkl"),
        pca_self_boundary=os.path.join(ARTEFACT_DIR, "pca_self_boundary.pkl"),
        results=os.path.join(ARTEFACT_DIR, "last_train_result.json"),
    )


def dataset_display_name(dataset_type: str | None) -> str:
    dataset = normalize_dataset_type(dataset_type)
    return {
        DATASET_CICIDS2017: "CIC-IDS-2017",
        DATASET_NSL_KDD: "NSL-KDD Benchmark",
    }[dataset]

