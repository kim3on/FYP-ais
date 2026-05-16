"""
AIS-Detect application package bootstrap.

Set process defaults before scikit-learn/joblib imports. On newer Windows
installs, joblib's CPU detection can try the removed `wmic` command and emit
noisy subprocess decoding errors. Providing LOKY_MAX_CPU_COUNT skips that path.
"""

import os

_cpu_count = os.cpu_count() or 1
_loky_default = max(1, min(_cpu_count - 1, 8))
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(_loky_default))
