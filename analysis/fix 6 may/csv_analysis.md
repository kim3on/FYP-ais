# Alert Summary CSV Export

## Purpose

The alert CSV export is a triage-oriented summary report for FYP evaluation and analyst review. It is intentionally not a raw dump of every alert field. The report groups stored alerts into readable sections so Excel or Google Sheets users can understand the selected alert window quickly.

## Backend Endpoint

Primary endpoint:

```text
GET /api/alerts/export.csv
```

Supported filters:

```text
from
to
severity
attack_type
include_false_positive
zero_day_only
```

The export is generated from `AlertDB`, not frontend state or `_state["alerts"]`. This makes the file reproducible, avoids pagination gaps, and keeps the export consistent with backend filtering and authentication.

The endpoint path remains unchanged for compatibility, but the downloaded filename now uses:

```text
alerts_summary_YYYYMMDD_HHMMSS.csv
```

## CSV Layout

The file is a sectioned CSV. Each section starts with a `# Section Name` row, followed by its own headers and rows.

```text
# Report Overview
metric,value

# Severity Summary
severity,count,percentage

# Attack Family Summary
attack_family,count,percentage

# Top Sources
src_ip,alert_count,unique_targets,top_attack_family,max_severity,max_risk_score

# Top Targets
dst_ip,alert_count,unique_sources,top_attack_family,max_severity,max_risk_score

# Repeated Endpoint Pairs
src_ip,dst_ip,dst_port,protocol,count,first_seen,last_seen,max_severity,max_risk_score

# Priority Incidents
priority_rank,alert_id,timestamp,severity,attack_family,attack_type,risk_score,src_ip,dst_ip,dst_port,action_code

# Action Legend
action_code,explanation
```

## Analysis Rules

`attack_family` groups detailed attack names into broader categories:

```text
DoS
DDoS
Brute Force
Reconnaissance
Web Attack
Botnet
Infiltration
Heartbleed
Unknown / Novel
Unknown
```

`risk_score` is capped at `100` and combines:

```text
severity base score
confidence
zero-day flag
endpoint repetition
false-positive status
```

False positives remain counted in overview and rollup sections when included by filter, but their operational `risk_score` is `0` and they are excluded from the Priority Incidents section.

Repeated endpoint pairs are shown only when the same source, destination, port, and protocol appear at least three times in the selected export window. This helps identify campaign-like repetition without flooding the report.

Priority incidents are capped to the top 15 non-false-positive alerts, sorted by risk score and newest timestamp.

Text cells are protected against Excel formula injection by escaping values that begin with `=`, `+`, `-`, or `@`.

## Frontend Behavior

The Alerts page export button calls the backend export endpoint. The active dashboard filter is mapped to backend export filters:

```text
Critical -> severity=critical
High     -> severity=high
Zero-Day -> zero_day_only=true
All      -> no severity / zero-day filter
```

The button label is `Export Summary` to reflect that the downloaded file is a triage report rather than a full raw alert table.

## Validation

The export is considered correct when:

```text
The file opens cleanly in Excel or Google Sheets.
The filename starts with alerts_summary_.
The file contains section headers and per-section columns.
Severity and zero-day filters affect the exported file.
Attack families are normalized from detailed attack types.
Top source and target sections are sorted by count and risk.
Repeated endpoint pairs only include count >= 3.
Priority incidents contain at most 15 rows.
Priority incidents exclude false positives.
Empty result sets still return a Report Overview section with a note.
Unauthenticated users cannot access the endpoint.
Administrator and analyst users can export the file.
```
