# Alert CSV Analysis Export

## Purpose

The alert CSV export should support FYP evaluation and analyst review. It should not only download the visible alert table. It should export database-backed alert records with derived analysis fields that explain incident context, severity, repetition, zero-day status, and recommended action.

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

## CSV Columns

The export contains these columns:

```text
exported_at
analysis_window_start
analysis_window_end
alert_id
timestamp
date
hour
attack_type
attack_family
severity
severity_rank
confidence
confidence_pct
risk_score
src_ip
dst_ip
dst_port
protocol
endpoint_pair
is_zero_day
is_false_positive
review_status
repeat_count_src_ip
repeat_count_dst_ip
repeat_count_attack_type
repeat_count_endpoint_pair
recommended_action
analysis_note
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

`severity_rank` gives sortable numerical severity:

```text
critical = 4
high     = 3
medium   = 2
low      = 1
```

`risk_score` is capped at `100` and combines:

```text
severity base score
confidence
zero-day flag
endpoint repetition
false-positive status
```

False positives remain exportable for audit, but their operational `risk_score` is `0`.

`repeat_count_*` values are calculated inside the selected export window. These fields help identify repeated sources, repeated targets, repeated attack types, and repeated endpoint pairs.

`recommended_action` gives an analyst-facing action such as immediate investigation, brute-force log review, exposed-service review, DoS rate limiting, web log review, or monitoring.

`analysis_note` gives a short row-level explanation of why the alert matters.

## Frontend Behavior

The Alerts page keeps the existing export button, but the button calls the backend export endpoint instead of constructing CSV from visible rows. The active dashboard filter is mapped to backend export filters:

```text
Critical -> severity=critical
High     -> severity=high
Zero-Day -> zero_day_only=true
All      -> no severity / zero-day filter
```

## Validation

The export is considered correct when:

```text
CSV headers match the documented analytical schema.
Rows are exported from the database, not only the visible frontend page.
Severity and zero-day filters affect the exported file.
Attack families are normalized from detailed attack types.
Repeat counts are calculated within the export result set.
Risk scores are between 0 and 100.
False positives are clearly marked.
The file opens cleanly in Excel or Google Sheets.
Unauthenticated users cannot access the endpoint.
Administrator and analyst users can export the file.
```
