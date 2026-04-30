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
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import joblib


# ── Label column name variants seen in the wild ───────────────────────
_LABEL_VARIANTS = [' Label', 'Label', 'label', ' label']

# ── Normal traffic label ──────────────────────────────────────────────
NORMAL_LABEL = 'BENIGN'

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

    def __init__(self):
        self.scaler_: MinMaxScaler | None = None
        self.feature_columns_: list | None = None
        self.is_fitted_: bool = False

    # ------------------------------------------------------------------ #
    #  PUBLIC API                                                          #
    # ------------------------------------------------------------------ #

    def fit_transform(self, source, label_col=None, filename: str = ''):
        """
        Load, clean and scale the dataset.

        Returns
        -------
        X_normal : ndarray -- BENIGN rows normalised to [0,1]  (fed to NSA)
        y        : ndarray -- binary labels for ALL rows
        df       : DataFrame -- cleaned data with 'attack_category' column
        """
        df = self._load(source, filename=filename)
        df, label_col = self._find_label_col(df, label_col)

        # Clean inf/NaN in numeric columns BEFORE any further processing
        num_cols = df.select_dtypes(include=[np.number]).columns
        df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

        # Encode labels — adds 'attack_category', drops label column
        df, y = self._encode_labels(df, label_col)

        # Save attack_category BEFORE _clean() strips non-numeric columns
        attack_cat = df['attack_category'].copy() if 'attack_category' in df.columns else None

        # Clean numeric features
        df_clean = self._clean(df)

        # Re-attach attack_category to the returned DataFrame so callers can
        # use it for per-category stats and dashboard display
        if attack_cat is not None:
            df_clean = df_clean.copy()
            df_clean['attack_category'] = attack_cat.values

        X_all = df_clean[self.feature_columns_].values.astype(np.float32)
        self.scaler_ = MinMaxScaler()
        X_all_scaled = self.scaler_.fit_transform(X_all)

        self.is_fitted_ = True

        X_normal = X_all_scaled[y == 0]
        return X_normal, y, df_clean


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
        # Preserve attack_category before numeric-only clean
        attack_cat = df['attack_category'].copy() if 'attack_category' in df.columns else None
        df = self._clean(df, inference=True)
        if attack_cat is not None:
            df = df.copy()
            df['attack_category'] = attack_cat.values
        X = df[self.feature_columns_].values.astype(np.float32)
        return self.scaler_.transform(X), df


    def transform_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        """Transform a pre-loaded DataFrame (for real-time single-sample detection)."""
        self._check_fitted()
        df = self._clean(df.copy(), inference=True)
        for col in self.feature_columns_:
            if col not in df.columns:
                df[col] = 0.0
        X = df[self.feature_columns_].values.astype(np.float32)
        return self.scaler_.transform(X)

    # ------------------------------------------------------------------ #
    #  INTERNAL                                                            #
    # ------------------------------------------------------------------ #

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

        # Dashboard category
        df = df.copy()
        df['attack_category'] = (
            raw_labels.str.lower()
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
