# Dashboard Metric Cards — Redesign Plan

Replace the existing 7 plain stat cards with **4 rich metric cards** matching the bento-card style in the reference image.

---

## The 4 Cards

| # | Card | Top-left Icon | Top-right Badge | Value | Bottom text |
|---|---|---|---|---|---|
| 1 | **Total Packets** | List/stream icon (blue) | Trending-up arrow (green) | `displayPkts` if live, else `captureStatus?.packets_captured ?? 0` | `"From live capture session"` |
| 2 | **Anomalies Detected** | Warning triangle | Dynamic severity pill | `liveAnomalyCount` if live, else `totalAlerts` | `"From live capture session"` |
| 3 | **Active Antibodies** | Shield icon (blue) | Checkmark circle (green) | `dashStats?.active_antibodies ?? 0` | `"Generated via Negative Selection"` |
| 4 | **Zero-Day Candidates** | Hexagon/cell icon (purple/iris) | Static or none | `zeroDayCount` | `"Novel threats with no detector match"` |

---

## Dynamic Severity Badge (Card 2 — Anomalies Detected)

The top-right badge will reflect the **highest current severity** present in the alerts list:

| Condition | Badge Label | Colour |
|---|---|---|
| No anomalies / `totalAlerts === 0` | `NONE` | `var(--accent)` blue |
| Highest severity is `medium` | `MEDIUM` | `var(--warning)` yellow |
| Highest severity is `high` | `HIGH` | orange (`#f97316`) |
| Any `critical` alert exists | `CRITICAL` | `var(--danger)` red |

Logic (priority order): critical → high → medium → none.

---

## Card Visual Anatomy (per reference image)

```
┌─────────────────────────────────────────┐
│  [Icon]                      [Badge/Arrow] │
│                                           │
│  Label text (small, muted)                │
│  VALUE  (large bold number)              │
│                                           │
│  subtitle text (small, coloured)         │
└─────────────────────────────────────────┘
```

- Card background: `var(--bg-surface)` with `1px solid var(--border)` border
- Border-radius: `var(--radius)`
- Icon: inline SVG, 20×20, coloured per card
- Value: ~28px, `JetBrains Mono`, bold, `var(--text-primary)`
- Label: 11px, muted, uppercase mono
- Bottom text: 11px, coloured (green for normal, red for anomaly, accent for NSA)
- Grid: `grid-template-columns: repeat(4, 1fr)` — drops to 2-col on narrow screens

---

## Data Mapping

| Card | Data Source | Idle state |
|---|---|---|
| Total Packets | `captureRunning ? livePktCount : (captureStatus?.packets_captured ?? 0)` | Shows `0` (not `—`) |
| Anomalies Detected | `captureRunning ? liveAnomalyCount : totalAlerts` | Shows stored alert count |
| Active Antibodies | `dashStats?.active_antibodies ?? 0` | `0` until model trained |
| Zero-Day Candidates | `zeroDayCount` (already computed from `alerts`) | `0` |

---

## Files to Change

### [MODIFY] `frontend/src/pages/Dashboard.jsx`
- Remove the old 7-card `stat-grid` block (lines 296–331)
- Add a new `StatCard` sub-component (inline, above the return) that renders the bento-style card
- Add severity badge logic helper
- Replace the grid with 4 `<StatCard>` instances

### [MODIFY] `frontend/src/pages/Dashboard.css`
- Add `.metric-grid` — 4-column grid with responsive 2-col breakpoint
- Add `.metric-card` — padding, background, border, border-radius, flex layout
- Add `.metric-badge` — pill style for severity labels
- Remove any now-unused `.stat-card` styles (currently in `Layout.css` if present)

---

## Open Questions for You

> [!NOTE]
> **Zero-Day card top-right indicator** — should it show a static purple badge (e.g. `NOVEL`) or nothing? Or a count-based badge like `CRITICAL` only when `zeroDayCount > 0`?

> [!NOTE]
> **Total Packets at idle** — I'll show `0` when there's no live session and no previous capture status. Is that acceptable, or would you prefer `—`?

---

## Verification Plan
- All 4 cards render with correct values from the existing data sources
- Severity badge cycles correctly through NONE → MEDIUM → HIGH → CRITICAL
- Grid collapses gracefully on narrow viewport
- Existing charts, alert table, and live capture controls below are unaffected
