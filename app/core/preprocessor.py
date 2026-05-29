"""
CIC-IDS-2017 Dataset Preprocessor
====================================
Replaces the NSL-KDD preprocessor.  Handles the full CIC-IDS-2017
MachineLearningCSV format produced by CICFlowMeter.

Key differences from NSL-KDD
------------------------------
- CSV files already have a header row  (no column-name injection needed)
- All 78 features are NUMERIC — no one-hot encoding required
- Label column is named ' Label'  (note the leading space) or 'Label'
- Normal label is 'BENIGN'  (not 'normal')
- Known data-quality issues that must be fixed:
    * Infinite values (+-inf) from division-by-zero in CICFlowMeter
    * NaN values
    * Duplicate column: 'Fwd Header Length' appears twice -> drop second
    * Column names have leading/trailing spaces -> strip them
    * Some rows have extreme overflow values -> clip to 1e12

Dataset files (8 CSVs, ~2.8 M rows total)
-------------------------------------------
Monday-WorkingHours.pcap_ISCX.csv          -- BENIGN only
Tuesday-WorkingHours.pcap_ISCX.csv         -- BENIGN + FTP-Patator + SSH-Patator
Wednesday-WorkingHours.pcap_ISCX.csv       -- BENIGN + DoS variants
Thursday-WorkingHours-Morning-WebAttacks   -- BENIGN + Web Attacks
Thursday-WorkingHours-Afternoon-Infiltration -- BENIGN + Infiltration
Friday-WorkingHours-Morning.pcap_ISCX.csv  -- BENIGN + Botnet ARES
Friday-WorkingHours-Afternoon-DDos         -- BENIGN + DDoS
Friday-WorkingHours-Afternoon-PortScan     -- BENIGN + PortScan

Download: https://www.unb.ca/cic/datasets/ids-2017.html
"""

import io
import os
import warnings
import numpy as np
import pandas as pd
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import RobustScaler
import joblib


# ── Label column name variants seen in the wild ───────────────────────
_LABEL_VARIANTS = [' Label', 'Label', 'label', ' label']

# ── Normal traffic label ──────────────────────────────────────────────
NORMAL_LABEL = 'BENIGN'

# ── Representation layer options ──────────────────────────────────────
REPRESENTATION_PCA = "pca"
REPRESENTATION_DAE = "dae"
REPRESENTATION_CHOICES = {REPRESENTATION_PCA, REPRESENTATION_DAE}
DEFAULT_DAE_LATENT_DIM = 8
DEFAULT_DAE_NOISE_STD = 0.05
DEFAULT_DAE_HIDDEN_WIDTH = 64
DEFAULT_DAE_MAX_ITER = 50


def normalize_representation(value: str | None) -> str:
    """Normalize a representation-layer name for training/inference."""
    name = str(value or REPRESENTATION_PCA).strip().lower().replace("-", "_")
    aliases = {
        "pca": REPRESENTATION_PCA,
        "principal_components": REPRESENTATION_PCA,
        "dae": REPRESENTATION_DAE,
        "denoising_ae": REPRESENTATION_DAE,
        "denoising_autoencoder": REPRESENTATION_DAE,
        "autoencoder": REPRESENTATION_DAE,
    }
    normalized = aliases.get(name)
    if normalized not in REPRESENTATION_CHOICES:
        raise ValueError("representation must be 'pca' or 'dae'")
    return normalized


# ── Attack label -> dashboard category ───────────────────────────────
ATTACK_CATEGORIES = {
    'benign':                       'normal',
    'ftp-patator':                  'Brute Force',
    'ssh-patator':                  'Brute Force',
    'dos hulk':                     'DoS',
    'dos goldeneye':                'DoS',
    'dos slowloris':                'DoS',
    'dos slowhttptest':             'DoS',
    'ddos':                         'DDoS',
    'portscan':                     'Probe',
    'bot':                          'Botnet',
    'web attack - brute force':     'Web Attack',
    'web attack - xss':             'Web Attack',
    'web attack - sql injection':   'Web Attack',
    'web attack \u2013 brute force':     'Web Attack',   # em-dash variant in CSV
    'web attack \u2013 xss':             'Web Attack',
    'web attack \u2013 sql injection':   'Web Attack',
    'infiltration':                 'Infiltration',
    'heartbleed':                   'Heartbleed',
}

# ── Metadata / non-feature columns to drop ────────────────────────────
_DROP_COLS = [
    'Flow ID', 'Source IP', 'Destination IP',
    'Source Port', 'Destination Port', 'Timestamp',
    'flow id', 'source ip', 'destination ip', 'timestamp',
]


class CICIDSPreprocessor:
    """
    End-to-end preprocessor for CIC-IDS-2017 (and compatible CICFlowMeter CSVs).

    Usage -- training
    -----------------
        prep = CICIDSPreprocessor()
        X_normal, y, df = prep.fit_transform(csv_path_or_bytes)
        # X_normal  -- BENIGN rows only, cleaned + scaled to [0,1]
        # y         -- binary labels for ALL rows (0=BENIGN, 1=attack)
        # df        -- cleaned DataFrame with 'attack_category' column

    Usage -- inference
    ------------------
        X_scaled, df = prep.transform(csv_path_or_bytes)
    """

    def __init__(
        self,
        n_pca_components: float | int | None = 0.95,
        representation: str = REPRESENTATION_PCA,
        dae_latent_dim: int = DEFAULT_DAE_LATENT_DIM,
        dae_noise_std: float = DEFAULT_DAE_NOISE_STD,
        dae_hidden_width: int = DEFAULT_DAE_HIDDEN_WIDTH,
        dae_max_iter: int = DEFAULT_DAE_MAX_ITER,
        random_state: int = 42,
    ):
        self.n_pca_components = n_pca_components
        self.representation = normalize_representation(representation)
        self.dae_latent_dim = int(np.clip(dae_latent_dim, 2, 64))
        self.dae_noise_std = float(np.clip(dae_noise_std, 0.0, 0.20))
        self.dae_hidden_width = int(max(8, dae_hidden_width))
        self.dae_max_iter = int(max(1, dae_max_iter))
        self.random_state = int(random_state)
        self.pca_ = None
        self.dae_ = None
        self.scaler_: RobustScaler | None = None
        self.feature_columns_: list | None = None
        self.is_fitted_: bool = False

    # ------------------------------------------------------------------ #
    #  PUBLIC API                                                          #
    # ------------------------------------------------------------------ #

    def fit_transform(
        self,
        source,
        label_col=None,
        filename: str = '',
        allow_unsafe_full_dataset_fit: bool = False,
    ):
        """
        Legacy entry point for training.
        Warning: This fits on the provided source. In pipeline context, 
        ensure only training data is passed here to avoid leakage.
        """
        df = self._load(source, filename=filename)
        df, label_col = self._find_label_col(df, label_col)

        # Clean inf/NaN
        num_cols = df.select_dtypes(include=[np.number]).columns
        df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

        df, y = self._encode_labels(df, label_col)
        if (
            not allow_unsafe_full_dataset_fit
            and len(np.unique(y)) > 1
        ):
            raise ValueError(
                "Unsafe mixed labelled fit_transform() blocked. Split the data first, "
                "fit preprocessing on training BENIGN rows only, then transform "
                "calibration/test rows. For legacy tests only, call "
                "fit_transform_unsafe_single_dataset()."
            )
        
        # Save attack_category before numeric clean
        attack_cat = df['attack_category'].copy() if 'attack_category' in df.columns else None

        df_clean = self._clean(df) # Sets self.feature_columns_
        
        # Re-attach
        if attack_cat is not None:
            df_clean = df_clean.copy()
            df_clean['attack_category'] = attack_cat.values

        X_all = df_clean[self.feature_columns_].values.astype(np.float32)
        self.scaler_ = RobustScaler()
        X_all_scaled = self.scaler_.fit_transform(X_all)
        X_all_scaled = self._fit_transform_representation(X_all_scaled)

        self.is_fitted_ = True
        return X_all_scaled[y == 0], y, df_clean

    def fit_transform_unsafe_single_dataset(self, source, label_col=None, filename: str = ''):
        """
        Compatibility helper for old tests/demos that intentionally fit on one
        complete labelled dataset. Do not use for honest train/test evaluation.
        """
        return self.fit_transform(
            source,
            label_col=label_col,
            filename=filename,
            allow_unsafe_full_dataset_fit=True,
        )

    def fit(self, df: pd.DataFrame, label_col: str = None):
        """Fit preprocessor on a training DataFrame."""
        df = df.copy()
        if label_col:
            df, _ = self._encode_labels(df, label_col)
        
        df_clean = self._clean(df, inference=False) # registers feature_columns_
        X = df_clean[self.feature_columns_].values.astype(np.float32)
        
        self.scaler_ = RobustScaler()
        X_scaled = self.scaler_.fit_transform(X)
        self._fit_representation(X_scaled)

        self.is_fitted_ = True
        return self

    def transform_df(self, df: pd.DataFrame):
        """Transform a DataFrame using fitted state."""
        self._check_fitted()
        df = df.copy()
        # Find and encode labels if present (for attack_category extraction)
        df, label_col = self._find_label_col(df, required=False)
        if label_col:
            df, _ = self._encode_labels(df, label_col)

        # Preserve forensic metadata before _clean() strips them
        _FORENSIC_COLS = ['attack_category', 'Destination Port',
                          'Source IP', 'Destination IP', 'Protocol',
                          'Source Port', 'Timestamp']
        preserved = {}
        for col in _FORENSIC_COLS:
            for candidate in [col, col.strip()]:
                if candidate in df.columns:
                    preserved[col] = df[candidate].copy()
                    break

        df_numeric = self._clean(df, inference=True)

        if preserved:
            df_numeric = df_numeric.copy()
            for col, series in preserved.items():
                df_numeric[col] = series.values

        X = df_numeric[self.feature_columns_].values.astype(np.float32)
        X_scaled = self.scaler_.transform(X)
        X_scaled = self._transform_representation(X_scaled)
        return X_scaled, df_numeric

    def transform_with_raw(self, source, filename: str = ''):
        """
        Transform and return both PCA features AND raw pre-PCA features.

        Used by the two-layer detection architecture:
        - PCA features feed the NSA V-Detector (Layer 1a)
        - Raw features feed the SelfBoundaryDetector (Layer 1b)

        Returns
        -------
        X_pca : ndarray
            PCA-transformed features for NSA.
        df_meta : DataFrame
            Cleaned DataFrame with forensic metadata columns preserved.
        df_raw_features : DataFrame
            Raw numeric features (pre-scaling, pre-PCA) for self-boundary scoring.
        """
        self._check_fitted()
        df = self._load(source, filename=filename)
        df, label_col = self._find_label_col(df, required=False)
        num_cols = df.select_dtypes(include=[np.number]).columns
        df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
        if label_col:
            df, _ = self._encode_labels(df, label_col)

        _FORENSIC_COLS = ['attack_category', 'Destination Port',
                          'Source IP', 'Destination IP', 'Protocol',
                          'Source Port', 'Timestamp']
        preserved = {}
        for col in _FORENSIC_COLS:
            for candidate in [col, col.strip()]:
                if candidate in df.columns:
                    preserved[col] = df[candidate].copy()
                    break

        df = self._clean(df, inference=True)

        if preserved:
            df = df.copy()
            for col, series in preserved.items():
                df[col] = series.values

        # Raw features before scaling/PCA — for self-boundary detector
        df_raw_features = df[self.feature_columns_].copy()

        X = df[self.feature_columns_].values.astype(np.float32)
        X_scaled = self.scaler_.transform(X)
        X_scaled = self._transform_representation(X_scaled)
        return X_scaled, df, df_raw_features



    def transform(self, source, filename: str = ''):

        """Transform new data using the already-fitted scaler."""
        self._check_fitted()
        df = self._load(source, filename=filename)
        df, label_col = self._find_label_col(df, required=False)
        # Clean inf/NaN in numeric columns before any processing
        num_cols = df.select_dtypes(include=[np.number]).columns
        df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
        if label_col:
            df, _ = self._encode_labels(df, label_col)

        # Preserve forensic metadata before _clean() strips them.
        # These are needed by the detection engine's heuristic classifier
        # (e.g. Destination Port distinguishes brute-force from DDoS).
        _FORENSIC_COLS = ['attack_category', 'Destination Port',
                          'Source IP', 'Destination IP', 'Protocol',
                          'Source Port', 'Timestamp']
        preserved = {}
        for col in _FORENSIC_COLS:
            # Try exact match and stripped version
            for candidate in [col, col.strip()]:
                if candidate in df.columns:
                    preserved[col] = df[candidate].copy()
                    break

        df = self._clean(df, inference=True)

        # Re-attach preserved metadata
        if preserved:
            df = df.copy()
            for col, series in preserved.items():
                df[col] = series.values

        X = df[self.feature_columns_].values.astype(np.float32)
        X_scaled = self.scaler_.transform(X)
        X_scaled = self._transform_representation(X_scaled)
        return X_scaled, df


    def transform_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        """Transform a pre-loaded DataFrame (for real-time single-sample detection)."""
        self._check_fitted()
        df = self._clean(df.copy(), inference=True)
        for col in self.feature_columns_:
            if col not in df.columns:
                df[col] = 0.0
        X = df[self.feature_columns_].values.astype(np.float32)
        X_scaled = self.scaler_.transform(X)
        X_scaled = self._transform_representation(X_scaled)
        return X_scaled

    def clean_feature_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Return numeric raw feature columns aligned to the fitted training schema.

        Used by live detection and raw self-boundary evidence. This applies the
        same inf/NaN handling, metadata dropping, clipping, and missing-column
        fill policy as normal inference preprocessing, but does not scale or PCA
        transform the values.
        """
        self._check_fitted()
        return self._clean(df.copy(), inference=True)

    def pca_feature_names(self, n_components: int | None = None) -> list[str]:
        """Return stable names for representation-space feature columns."""
        if n_components is None:
            if self._representation_name() == REPRESENTATION_DAE and self.dae_ is not None:
                n_components = int(getattr(self, "dae_latent_dim", DEFAULT_DAE_LATENT_DIM) or 0)
            elif self.pca_ is not None:
                n_components = int(getattr(self.pca_, "n_components_", 0) or 0)
            elif self.feature_columns_ is not None:
                n_components = len(self.feature_columns_)
            else:
                n_components = 0
        prefix = "AE" if self._representation_name() == REPRESENTATION_DAE else "PC"
        return [f"{prefix}_{i + 1:03d}" for i in range(int(n_components))]

    def pca_dataframe(self, X_pca: np.ndarray) -> pd.DataFrame:
        """Wrap representation-space features in a DataFrame for self-boundary."""
        X = np.asarray(X_pca, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return pd.DataFrame(X, columns=self.pca_feature_names(X.shape[1]))

    def representation_feature_names(self, n_components: int | None = None) -> list[str]:
        """Explicit alias for representation-space feature names."""
        return self.pca_feature_names(n_components)

    def representation_dataframe(self, X_representation: np.ndarray) -> pd.DataFrame:
        """Explicit alias for representation-space self-boundary input."""
        return self.pca_dataframe(X_representation)

    def representation_display_name(self) -> str:
        name = self._representation_name()
        if name == REPRESENTATION_DAE:
            return "Denoising Autoencoder"
        return "PCA"

    def representation_summary(self) -> dict:
        """Return metadata for the saved feature representation layer."""
        name = self._representation_name()
        n_components = None
        if name == REPRESENTATION_DAE:
            n_components = int(getattr(self, "dae_latent_dim", DEFAULT_DAE_LATENT_DIM))
        elif self.pca_ is not None:
            n_components = int(getattr(self.pca_, "n_components_", 0) or 0)
        elif self.feature_columns_ is not None:
            n_components = len(self.feature_columns_)
        summary = {
            "name": name,
            "display_name": self.representation_display_name(),
            "component_count": int(n_components or 0),
            "scaler": "RobustScaler",
            "fitted": bool(getattr(self, "is_fitted_", False)),
        }
        if name == REPRESENTATION_PCA:
            summary.update({
                "pca_components": summary["component_count"],
                "pca_whiten": True,
                "n_pca_components_config": getattr(self, "n_pca_components", None),
            })
        else:
            dae = getattr(self, "dae_", None)
            summary.update({
                "dae_latent_dim": int(getattr(self, "dae_latent_dim", DEFAULT_DAE_LATENT_DIM)),
                "dae_noise_std": float(getattr(self, "dae_noise_std", DEFAULT_DAE_NOISE_STD)),
                "dae_hidden_width": int(getattr(self, "dae_hidden_width", DEFAULT_DAE_HIDDEN_WIDTH)),
                "dae_max_iter": int(getattr(self, "dae_max_iter", DEFAULT_DAE_MAX_ITER)),
                "dae_n_iter": int(getattr(dae, "n_iter_", 0) or 0) if dae is not None else None,
                "experimental": True,
            })
        return summary

    # ------------------------------------------------------------------ #
    #  INTERNAL                                                            #
    # ------------------------------------------------------------------ #

    def _representation_name(self) -> str:
        try:
            return normalize_representation(getattr(self, "representation", REPRESENTATION_PCA))
        except ValueError:
            return REPRESENTATION_PCA

    def _fit_transform_representation(self, X_scaled: np.ndarray) -> np.ndarray:
        self._fit_representation(X_scaled)
        return self._transform_representation(X_scaled)

    def _fit_representation(self, X_scaled: np.ndarray):
        X_scaled = np.asarray(X_scaled, dtype=np.float32)
        self.pca_ = None
        self.dae_ = None

        if self._representation_name() == REPRESENTATION_DAE:
            self._fit_dae(X_scaled)
            return

        if self.n_pca_components:
            from sklearn.decomposition import PCA
            self.pca_ = PCA(
                n_components=self.n_pca_components,
                random_state=getattr(self, "random_state", 42),
                svd_solver='full',
                whiten=True,
            )
            self.pca_.fit(X_scaled)

    def _fit_dae(self, X_scaled: np.ndarray):
        X_scaled = np.asarray(X_scaled, dtype=np.float32)
        if X_scaled.ndim != 2 or X_scaled.shape[1] == 0:
            raise ValueError("DAE representation requires a 2D numeric feature matrix")

        n_features = int(X_scaled.shape[1])
        latent_dim = int(np.clip(getattr(self, "dae_latent_dim", DEFAULT_DAE_LATENT_DIM), 2, min(64, max(2, n_features))))
        self.dae_latent_dim = latent_dim
        hidden_width = int(max(getattr(self, "dae_hidden_width", DEFAULT_DAE_HIDDEN_WIDTH), latent_dim * 2))
        self.dae_hidden_width = hidden_width

        rng = np.random.default_rng(getattr(self, "random_state", 42))
        noise_std = float(np.clip(getattr(self, "dae_noise_std", DEFAULT_DAE_NOISE_STD), 0.0, 0.20))
        self.dae_noise_std = noise_std
        if noise_std > 0:
            X_noisy = X_scaled + rng.normal(0.0, noise_std, size=X_scaled.shape).astype(np.float32)
        else:
            X_noisy = X_scaled.copy()

        early_stopping = len(X_scaled) >= 80
        model = MLPRegressor(
            hidden_layer_sizes=(hidden_width, latent_dim, hidden_width),
            activation="tanh",
            solver="adam",
            alpha=1e-4,
            batch_size="auto",
            learning_rate_init=1e-3,
            max_iter=int(getattr(self, "dae_max_iter", DEFAULT_DAE_MAX_ITER)),
            early_stopping=early_stopping,
            validation_fraction=0.10,
            n_iter_no_change=8,
            random_state=getattr(self, "random_state", 42),
        )
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=ConvergenceWarning)
            model.fit(X_noisy, X_scaled)
        self.dae_ = model

    def _transform_representation(self, X_scaled: np.ndarray) -> np.ndarray:
        X_scaled = np.asarray(X_scaled, dtype=np.float32)
        if self._representation_name() == REPRESENTATION_DAE:
            if getattr(self, "dae_", None) is None:
                raise RuntimeError("DAE representation selected but the autoencoder is not fitted")
            return self._dae_encode(X_scaled)

        if self.pca_ is not None:
            return self.pca_.transform(X_scaled).astype(np.float32)
        return X_scaled.astype(np.float32)

    def _dae_encode(self, X_scaled: np.ndarray) -> np.ndarray:
        model = getattr(self, "dae_", None)
        if model is None:
            raise RuntimeError("DAE model is not fitted")
        if len(getattr(model, "coefs_", [])) < 2:
            raise RuntimeError("DAE model does not expose an encoder layer")

        layer = np.asarray(X_scaled, dtype=np.float32)
        for idx in range(2):
            layer = np.matmul(layer, model.coefs_[idx]) + model.intercepts_[idx]
            layer = self._dae_activation(layer, getattr(model, "activation", "tanh"))
        return layer.astype(np.float32)

    @staticmethod
    def _dae_activation(values: np.ndarray, activation: str) -> np.ndarray:
        if activation == "identity":
            return values
        if activation == "logistic":
            return 1.0 / (1.0 + np.exp(-values))
        if activation == "relu":
            return np.maximum(values, 0.0)
        return np.tanh(values)

    def _load(self, source, filename: str = '') -> pd.DataFrame:
        """
        Load data from CSV or Parquet — accepts file path, bytes, or file-like.
        Format detection priority:
          1. File path  — by extension
          2. Bytes      — by PAR1 magic bytes at offset 0 (most reliable)
          3. File-like  — by PAR1 magic bytes after seek(0)
        CSV fallback tries UTF-8 then latin-1.
        """
        # ── File path: detect by extension ────────────────────────────
        if isinstance(source, (str, os.PathLike)):
            ext = str(source).lower()
            if ext.endswith('.parquet') or ext.endswith('.pq'):
                df = pd.read_parquet(source)
            else:
                try:
                    df = pd.read_csv(source, encoding='utf-8', low_memory=False)
                except UnicodeDecodeError:
                    df = pd.read_csv(source, encoding='latin-1', low_memory=False)

        # ── Bytes: detect format by magic bytes ────────────────────────
        elif isinstance(source, bytes):
            # Parquet files begin with b'PAR1' (magic number)
            is_parquet = source[:4] == b'PAR1'

            # Also honour the filename hint (e.g. passed from the upload handler)
            if not is_parquet and filename:
                fn_lower = filename.lower()
                is_parquet = fn_lower.endswith('.parquet') or fn_lower.endswith('.pq')

            if is_parquet:
                try:
                    df = pd.read_parquet(io.BytesIO(source))
                except Exception as exc:
                    raise ValueError(
                        f"Failed to read Parquet file: {exc}. "
                        "Ensure pyarrow is installed: pip install pyarrow"
                    ) from exc
            else:
                # CSV — try UTF-8 first, fall back to latin-1
                try:
                    df = pd.read_csv(io.BytesIO(source), encoding='utf-8', low_memory=False)
                except UnicodeDecodeError:
                    df = pd.read_csv(io.BytesIO(source), encoding='latin-1', low_memory=False)

        # ── File-like object ───────────────────────────────────────────
        else:
            try:
                magic = source.read(4)
                source.seek(0)
                if magic == b'PAR1':
                    try:
                        df = pd.read_parquet(source)
                    except Exception as exc:
                        raise ValueError(
                            f"Failed to read Parquet file: {exc}. "
                            "Ensure pyarrow is installed: pip install pyarrow"
                        ) from exc
                else:
                    try:
                        df = pd.read_csv(source, encoding='utf-8', low_memory=False)
                    except UnicodeDecodeError:
                        source.seek(0)
                        df = pd.read_csv(source, encoding='latin-1', low_memory=False)
            except (AttributeError, OSError):
                try:
                    df = pd.read_csv(source, encoding='utf-8', low_memory=False)
                except UnicodeDecodeError:
                    df = pd.read_csv(source, encoding='latin-1', low_memory=False)

        # Strip column name whitespace immediately
        df.columns = [c.strip() for c in df.columns]
        return df

    def _find_label_col(self, df: pd.DataFrame, hint=None, required: bool = True):
        """Locate the label column among known variants."""
        df.columns = [c.strip() for c in df.columns]
        if hint:
            stripped = hint.strip()
            if stripped in df.columns:
                return df, stripped

        for v in _LABEL_VARIANTS:
            v = v.strip()
            if v in df.columns:
                return df, v

        if required:
            raise ValueError(
                f"Label column not found. Columns seen: {list(df.columns[:15])}"
            )
        return df, None

    def _encode_labels(self, df: pd.DataFrame, label_col: str):
        """
        Convert text labels -> binary (0=BENIGN, 1=attack).
        Attaches 'attack_category' for per-category dashboard stats.
        Removes the label column from the feature set.
        """
        raw_labels = df[label_col].astype(str).str.strip()

        # Binary encoding
        y = (raw_labels.str.upper() != NORMAL_LABEL.upper()).astype(int).values

        # Dashboard category. Some CIC-IDS-2017 Web Attack labels contain
        # mojibake/replacement characters; normalize separators before mapping.
        category_labels = (
            raw_labels.str.lower()
            .str.replace("\u2013", " - ", regex=False)
            .str.replace("\ufffd", " - ", regex=False)
            .str.replace(r"\s+", " ", regex=True)
            .str.strip()
        )
        df = df.copy()
        df['attack_category'] = (
            category_labels
            .map(ATTACK_CATEGORIES)
            .fillna('Unknown')
        )
        df = df.drop(columns=[label_col], errors='ignore')
        return df, y

    def _clean(self, df: pd.DataFrame, inference: bool = False) -> pd.DataFrame:
        """
        Apply all CIC-IDS-2017 data quality fixes:
          1. Drop metadata / identification columns
          2. Remove duplicate 'Fwd Header Length' column
          3. Replace +-inf with NaN, fill NaN with 0
          4. Select only numeric columns
          5. Clip extreme CICFlowMeter overflow values
          6. Store / align feature schema
        """
        df = df.copy()
        df.columns = [c.strip() for c in df.columns]

        # 1. Drop metadata columns and attack_category helper
        to_drop = [c for c in _DROP_COLS if c in df.columns]
        to_drop += [c for c in ['attack_category'] if c in df.columns]
        df = df.drop(columns=to_drop, errors='ignore')

        # 2. Remove duplicate Fwd Header Length (keep first occurrence only)
        cols = list(df.columns)
        seen_cols = {}
        unique_cols = []
        for c in cols:
            if c not in seen_cols:
                seen_cols[c] = True
                unique_cols.append(c)
        df = df[unique_cols]

        # 3. Handle inf and NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)

        # 4. Keep only numeric columns
        df = df.select_dtypes(include=[np.number])

        # 5. Clip CICFlowMeter overflow artefacts
        df = df.clip(-1e12, 1e12)

        # 6. Store or align feature schema
        if not inference:
            self.feature_columns_ = list(df.columns)
        else:
            if self.feature_columns_:
                for col in self.feature_columns_:
                    if col not in df.columns:
                        df[col] = 0.0
                df = df[self.feature_columns_]

        return df

    def _check_fitted(self):
        if not self.is_fitted_:
            raise RuntimeError("Preprocessor not fitted. Call fit_transform() first.")

    # ------------------------------------------------------------------ #
    #  PERSISTENCE                                                         #
    # ------------------------------------------------------------------ #

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str):
        return joblib.load(path)

    # ------------------------------------------------------------------ #
    #  VALIDATION STATS (dashboard display)                               #
    # ------------------------------------------------------------------ #

    def validation_stats(self, y: np.ndarray, df: pd.DataFrame) -> dict:
        total    = len(y)
        n_normal = int((y == 0).sum())
        n_attack = int((y == 1).sum())

        category_counts = {}
        if 'attack_category' in df.columns:
            category_counts = {
                str(k): int(v)
                for k, v in df['attack_category'].value_counts().items()
            }

        return {
            'total_records':     total,
            'normal_records':    n_normal,
            'attack_records':    n_attack,
            'normal_pct':        round(n_normal / total * 100, 1) if total else 0,
            'attack_pct':        round(n_attack / total * 100, 1) if total else 0,
            'n_features':        len(self.feature_columns_) if self.feature_columns_ else 0,
            'attack_categories': category_counts,
            'dataset':           'CIC-IDS-2017',
        }
