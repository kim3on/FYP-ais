"""
NSL-KDD CSV preprocessor for offline AIS benchmark experiments.

NSL-KDD is not live-capture compatible with the CICFlowMeter feature schema.
This preprocessor keeps the same public methods as CICIDSPreprocessor so the
existing training and detection pipeline can run batch-only NSL-KDD experiments.
"""

from __future__ import annotations

import io
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, RobustScaler


NSL_KDD_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

NSL_KDD_CATEGORICAL = ["protocol_type", "service", "flag"]
NSL_KDD_NUMERIC = [c for c in NSL_KDD_FEATURES if c not in NSL_KDD_CATEGORICAL]
LABEL_VARIANTS = ["label", "labels", "class", "attack", "attack_type"]
NORMAL_LABEL = "normal"

DOS_ATTACKS = {
    "back", "land", "neptune", "pod", "smurf", "teardrop",
    "apache2", "mailbomb", "processtable", "udpstorm", "worm",
}
PROBE_ATTACKS = {"ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"}
R2L_ATTACKS = {
    "ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy",
    "warezclient", "warezmaster", "named", "sendmail", "snmpgetattack",
    "snmpguess", "xlock", "xsnoop", "httptunnel",
}
U2R_ATTACKS = {"buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm"}


def _make_one_hot_encoder() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float32)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False, dtype=np.float32)


class NSLKDDPreprocessor:
    """Preprocess NSL-KDD CSV-with-header files for unsupervised AIS training."""

    dataset_type = "nsl_kdd"

    def __init__(self, n_pca_components: float | int | None = 0.95):
        self.n_pca_components = n_pca_components
        self.pca_ = None
        self.scaler_: RobustScaler | None = None
        self.encoder_: OneHotEncoder | None = None
        self.numeric_columns_: list[str] = list(NSL_KDD_NUMERIC)
        self.categorical_columns_: list[str] = list(NSL_KDD_CATEGORICAL)
        self.category_feature_names_: list[str] = []
        self.feature_columns_: list[str] | None = None
        self.numeric_medians_: pd.Series | None = None
        self.is_fitted_: bool = False

    def fit_transform(
        self,
        source,
        label_col=None,
        filename: str = "",
        allow_unsafe_full_dataset_fit: bool = False,
    ):
        df = self._load(source, filename=filename)
        df, label_col = self._find_label_col(df, label_col)
        df, y = self._encode_labels(df, label_col)
        if not allow_unsafe_full_dataset_fit and len(np.unique(y)) > 1:
            raise ValueError(
                "Unsafe mixed labelled fit_transform() blocked. Split NSL-KDD first, "
                "fit preprocessing on normal/self rows only, then transform holdout rows."
            )
        self.fit(df)
        X, df_meta = self.transform_df(df)
        return X[y == 0], y, df_meta

    def fit_transform_unsafe_single_dataset(self, source, label_col=None, filename: str = ""):
        return self.fit_transform(
            source,
            label_col=label_col,
            filename=filename,
            allow_unsafe_full_dataset_fit=True,
        )

    def fit(self, df: pd.DataFrame, label_col: str | None = None):
        df = self._normalise_columns(df.copy())
        if label_col:
            df, _ = self._encode_labels(df, label_col)
        self._validate_feature_columns(df)

        numeric = self._numeric_frame(df, fit=True)
        categorical = self._categorical_frame(df)

        self.scaler_ = RobustScaler()
        numeric_scaled = self.scaler_.fit_transform(numeric.values.astype(np.float32))

        self.encoder_ = _make_one_hot_encoder()
        categorical_encoded = self.encoder_.fit_transform(categorical)
        self.category_feature_names_ = self._encoder_feature_names()

        X = np.hstack([numeric_scaled, categorical_encoded]).astype(np.float32)
        self.feature_columns_ = self.numeric_columns_ + self.category_feature_names_

        if self.n_pca_components:
            from sklearn.decomposition import PCA
            max_components = min(X.shape[0], X.shape[1])
            n_components = self.n_pca_components
            if isinstance(n_components, int):
                n_components = max(1, min(int(n_components), max_components))
            self.pca_ = PCA(
                n_components=n_components,
                random_state=42,
                svd_solver="full",
                whiten=True,
            )
            self.pca_.fit(X)

        self.is_fitted_ = True
        return self

    def transform_df(self, df: pd.DataFrame):
        self._check_fitted()
        df = self._normalise_columns(df.copy())
        df, label_col = self._find_label_col(df, required=False)
        if label_col:
            df, _ = self._encode_labels(df, label_col)

        meta = {}
        if "attack_category" in df.columns:
            meta["attack_category"] = df["attack_category"].reset_index(drop=True)
        if "label_text" in df.columns:
            meta["label_text"] = df["label_text"].reset_index(drop=True)

        X = self._transform_matrix(df)
        df_features = self.clean_feature_frame(df)
        for col, series in meta.items():
            df_features[col] = series.values
        return X, df_features

    def transform(self, source, filename: str = ""):
        df = self._load(source, filename=filename)
        return self.transform_df(df)

    def transform_with_raw(self, source, filename: str = ""):
        df = self._load(source, filename=filename)
        X, df_meta = self.transform_df(df)
        df_raw_features = self.clean_feature_frame(df)
        return X, df_meta, df_raw_features

    def transform_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self._transform_matrix(df)

    def clean_feature_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        self._check_fitted()
        df = self._normalise_columns(df.copy())
        self._validate_feature_columns(df)
        numeric = self._numeric_frame(df, fit=False)
        categorical = self._categorical_frame(df)
        cat_encoded = self.encoder_.transform(categorical)
        cat_df = pd.DataFrame(cat_encoded, columns=self.category_feature_names_, index=df.index)
        combined = pd.concat([numeric.reset_index(drop=True), cat_df.reset_index(drop=True)], axis=1)
        for col in self.feature_columns_ or []:
            if col not in combined.columns:
                combined[col] = 0.0
        return combined[self.feature_columns_].astype(np.float32)

    def pca_feature_names(self, n_components: int | None = None) -> list[str]:
        if n_components is None:
            if self.pca_ is not None:
                n_components = int(getattr(self.pca_, "n_components_", 0) or 0)
            elif self.feature_columns_ is not None:
                n_components = len(self.feature_columns_)
            else:
                n_components = 0
        return [f"PC_{i + 1:03d}" for i in range(int(n_components))]

    def pca_dataframe(self, X_pca: np.ndarray) -> pd.DataFrame:
        X = np.asarray(X_pca, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return pd.DataFrame(X, columns=self.pca_feature_names(X.shape[1]))

    def _transform_matrix(self, df: pd.DataFrame) -> np.ndarray:
        df = self._normalise_columns(df.copy())
        self._validate_feature_columns(df)
        numeric = self._numeric_frame(df, fit=False)
        categorical = self._categorical_frame(df)
        numeric_scaled = self.scaler_.transform(numeric.values.astype(np.float32))
        categorical_encoded = self.encoder_.transform(categorical)
        X = np.hstack([numeric_scaled, categorical_encoded]).astype(np.float32)
        if self.pca_ is not None:
            X = self.pca_.transform(X).astype(np.float32)
        return X

    def _load(self, source, filename: str = "") -> pd.DataFrame:
        if isinstance(source, (str, os.PathLike)):
            try:
                df = pd.read_csv(source, encoding="utf-8", low_memory=False)
            except UnicodeDecodeError:
                df = pd.read_csv(source, encoding="latin-1", low_memory=False)
        elif isinstance(source, bytes):
            try:
                df = pd.read_csv(io.BytesIO(source), encoding="utf-8", low_memory=False)
            except UnicodeDecodeError:
                df = pd.read_csv(io.BytesIO(source), encoding="latin-1", low_memory=False)
        else:
            try:
                df = pd.read_csv(source, encoding="utf-8", low_memory=False)
            except UnicodeDecodeError:
                source.seek(0)
                df = pd.read_csv(source, encoding="latin-1", low_memory=False)
        return self._normalise_columns(df)

    def _normalise_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df.columns = [str(c).strip().lower() for c in df.columns]
        return df

    def _find_label_col(self, df: pd.DataFrame, hint=None, required: bool = True):
        df = self._normalise_columns(df)
        if hint:
            key = str(hint).strip().lower()
            if key in df.columns:
                return df, key
        for candidate in LABEL_VARIANTS:
            if candidate in df.columns:
                return df, candidate
        if required:
            raise ValueError(
                "NSL-KDD label column not found. Expected one of "
                f"{LABEL_VARIANTS}; columns seen: {list(df.columns[:15])}"
            )
        return df, None

    def _encode_labels(self, df: pd.DataFrame, label_col: str):
        df = self._normalise_columns(df)
        if label_col not in df.columns:
            raise ValueError(f"NSL-KDD label column '{label_col}' not found")
        raw_labels = (
            df[label_col]
            .astype(str)
            .str.strip()
            .str.lower()
            .str.rstrip(".")
        )
        y = raw_labels.ne(NORMAL_LABEL).astype(int).to_numpy()
        df = df.copy()
        df["label_text"] = raw_labels
        df["attack_category"] = raw_labels.map(self._attack_category).fillna("Unknown Attack")
        df = df.drop(columns=[label_col], errors="ignore")
        return df, y

    @staticmethod
    def _attack_category(label: str) -> str:
        if label == NORMAL_LABEL:
            return "normal"
        if label in DOS_ATTACKS:
            return "DoS"
        if label in PROBE_ATTACKS:
            return "Probe"
        if label in R2L_ATTACKS:
            return "R2L"
        if label in U2R_ATTACKS:
            return "U2R"
        return "Unknown Attack"

    def _validate_feature_columns(self, df: pd.DataFrame) -> None:
        missing = [c for c in NSL_KDD_FEATURES if c not in df.columns]
        if missing:
            raise ValueError(
                "NSL-KDD CSV is missing required feature columns: "
                f"{missing[:10]}{'...' if len(missing) > 10 else ''}"
            )

    def _numeric_frame(self, df: pd.DataFrame, fit: bool) -> pd.DataFrame:
        numeric = df[self.numeric_columns_].apply(pd.to_numeric, errors="coerce")
        numeric = numeric.replace([np.inf, -np.inf], np.nan)
        if fit:
            self.numeric_medians_ = numeric.median(axis=0).fillna(0.0)
        numeric = numeric.fillna(self.numeric_medians_)
        numeric = numeric.fillna(0.0)
        return numeric.astype(np.float32)

    def _categorical_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        categorical = df[self.categorical_columns_].copy()
        for col in self.categorical_columns_:
            categorical[col] = categorical[col].astype(str).str.strip().str.lower().replace({"nan": "unknown"})
        return categorical

    def _encoder_feature_names(self) -> list[str]:
        if self.encoder_ is None:
            return []
        try:
            return list(self.encoder_.get_feature_names_out(self.categorical_columns_))
        except AttributeError:
            return list(self.encoder_.get_feature_names(self.categorical_columns_))

    def _check_fitted(self) -> None:
        if not self.is_fitted_:
            raise RuntimeError("NSLKDDPreprocessor not fitted. Call fit() first.")

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str):
        return joblib.load(path)

    def validation_stats(self, y: np.ndarray, df: pd.DataFrame) -> dict:
        total = len(y)
        n_normal = int((y == 0).sum())
        n_attack = int((y == 1).sum())
        category_counts = {}
        if "attack_category" in df.columns:
            category_counts = {
                str(k): int(v)
                for k, v in df["attack_category"].value_counts().items()
            }
        return {
            "total_records": total,
            "normal_records": n_normal,
            "attack_records": n_attack,
            "normal_pct": round(n_normal / total * 100, 1) if total else 0,
            "attack_pct": round(n_attack / total * 100, 1) if total else 0,
            "n_features": len(self.feature_columns_) if self.feature_columns_ else 0,
            "attack_categories": category_counts,
            "dataset": "NSL-KDD",
        }
