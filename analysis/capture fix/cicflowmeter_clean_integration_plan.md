# CICFlowMeter-Based Capture Redesign Plan

## Summary
Redesign the capture path around a CICFlowMeter-compatible extractor instead of defending the custom Scapy feature implementation as the primary path. The existing AIS model, CICIDS2017 preprocessor, detection engine, dashboard, alerts, and database stay intact. The new capture layer only replaces how live/PCAP traffic becomes CICIDS2017-style flow rows.

## Key Changes
- Add a `CICFlowMeterAdapter` layer that converts `hieulw/cicflowmeter` snake_case output into CICIDS2017 column names.
- Keep the existing `on_flow_complete(features)` contract used by `app.routers.capture`.
- Archive the current Scapy aggregator under `legacy/`; it is no longer imported by the app.
- Use CICFlowMeter as the only runtime capture engine.
- Report the active capture engine in `/api/capture/status`.

## Correctness Requirements
- Convert all CICFlowMeter time fields from seconds to CICIDS2017 microseconds:
  - `flow_duration`
  - `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min`
  - `fwd_iat_tot`, `fwd_iat_mean`, `fwd_iat_std`, `fwd_iat_max`, `fwd_iat_min`
  - `bwd_iat_tot`, `bwd_iat_mean`, `bwd_iat_std`, `bwd_iat_max`, `bwd_iat_min`
  - `active_mean`, `active_std`, `active_max`, `active_min`
  - `idle_mean`, `idle_std`, `idle_max`, `idle_min`
- Drop single-packet flows before scoring; minimum packet threshold is `2`.
- Do not trust the library's `cwr_flag_count` alias. Set `CWE Flag Count` to `0` unless a verified raw-packet CWR count is added later.
- Fill missing fitted CICIDS feature columns with `0.0`, but log a warning so schema gaps are visible.

## Implementation Changes
- Add `app/core/cicflow_bridge.py`:
  - wraps `cicflowmeter.flow_session.FlowSession` by composition
  - injects a callback writer during construction
  - maps and normalizes flow rows
  - emits `_src_ip`, `_dst_ip`, `_src_port`, `_dst_port`, and `_protocol`
  - exposes `CICFlowMeterSniffer` with the same `start()`, `stop(flush=True)`, `is_running`, `packets_captured`, and `resolved_interface` surface as the legacy sniffer
- Add capture engine selection:
  - `cicflowmeter` is the only runtime engine
  - missing cicflowmeter dependency returns a clear capture error
- Update `app/routers/capture.py` to use the selector and pass the fitted CICIDS feature schema into the sniffer.
- Keep NSL-KDD blocked from live capture.

## Validation Gates
- Gate 1: PCAP/batch validation
  - compare legacy extraction vs CICFlowMeter adapter extraction
  - verify all required CICIDS columns are present after mapping/fill
  - verify bulk features are non-zero for suitable sustained flows
  - verify time fields are in microsecond scale, not second scale
  - verify at least some AIS anomaly scores differ from legacy extraction
- Gate 2: live integration
  - start live capture with the CICFlowMeter runtime path
  - confirm packet and flow counters increment
  - confirm dashboard receives live updates
  - confirm `sniffer_error` stays empty during a short capture session
  - stop capture and confirm remaining flows flush

## Test Plan
- `python -m compileall app "validate and test\test_backend.py"`
- `python "validate and test\test_backend.py"`
- `npm run build` from `frontend`
- Manual runtime check:
  - confirm no runtime imports point to the archived Scapy capture implementation
  - start capture and confirm the CICFlowMeter path works

## Assumptions
- CICIDS2017 remains the only live-compatible training schema.
- `hieulw/cicflowmeter` is treated as CICFlowMeter-compatible, not guaranteed exact parity with the original Java CICFlowMeter.
- This change must not alter NSA, Self-Boundary, Isolation Forest, thresholding, or labelled evaluation logic.
