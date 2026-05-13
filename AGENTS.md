# AGENTS.md

## Project context
This repository is an academic FYP system called AIS-Detect: a web-based network anomaly detection tool using FastAPI, React, SQLite, Scapy, CIC-IDS-2017 preprocessing, a custom Negative Selection Algorithm/V-Detector model, and Isolation Forest.

## Review guidelines
- Prioritize serious security, correctness, ML integrity, and operational reliability issues.
- Treat authentication bypass, unsafe JWT handling, plaintext secrets, unsafe deserialization, route exposure, and unauthenticated WebSockets as P1 issues.
- Verify that preprocessing follows split-before-fit and does not leak test data into training.
- Verify that RobustScaler and PCA are fitted only on training data.
- Verify that NSA detector generation happens in PCA-whitened space and never assumes [0,1] bounds after PCA.
- Verify that NSA inference uses mature V-detectors as the primary anomaly mechanism, with self-gap fallback as secondary.
- Flag any code that makes metrics misleading under class imbalance.
- Flag any live-capture logic likely to cause packet loss, blocking, race conditions, or SQLite write contention.
- Flag any claim or code path that makes the system look production SOC-ready when it is only suitable as an academic prototype.
- Do not focus on style unless it affects maintainability or correctness.
