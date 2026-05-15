"""
AIS-Detect application package bootstrap.

Set process defaults before scikit-learn/joblib imports. On newer Windows
installs, joblib's CPU detection can try the removed `wmic` command and emit
noisy subprocess decoding errors. Providing LOKY_MAX_CPU_COUNT skips that path.
"""

import os

os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(os.cpu_count() or 1))

