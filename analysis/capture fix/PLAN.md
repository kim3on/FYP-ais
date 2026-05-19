# CICFlowMeter-Based Capture Redesign Plan

## Summary
Redesign the capture path around a CICFlowMeter-compatible extractor instead of defending the custom Scapy flow feature implementation as the primary path. The existing AIS model, CICIDS2017 preprocessor, detection engine, dashboard, alerts, and database stay intact. The new capture layer only replaces how live/PCAP traffic becomes CICIDS2017-style flow rows.

Target documentation file to create during implementation: `C:\Users\kimeon\Desktop\ais-backend\analysis\capture fix\cicflowmeter_clean_integration_plan.md`.

## Key Changes
- Add a new `CICFlowMeterAdapter` layer that converts `hieulw/cicflowmeter` output into the CICIDS2017 column names expected by the existing `CICIDSPreprocessor`.
- Archive the current custom Scapy capture implementation under `legacy/`; the app should not import it.
- Make `cicflowmeter` the intended default capture/extraction engine after validation.
- Preserve the existing `on_flow_complete(features)` contract used by `app.routers.capture`; the adapter must emit the same metadata keys:
  - `_src_ip`
  - `_dst_ip`
  - `_src_port`
  - `_dst_port`
  - `_protocol`
- Add a capture engine selector internally:
  - runtime engine: `cicflowmeter`
- Add capture status visibility:
  - `/api/capture/status` should include `capture_engine`.
  - frontend can display this later, but frontend changes are optional.

## Implementation Changes
- Build the integration in two gates:
  - Gate 1: PCAP/batch validation only.
  - Gate 2: live capture integration only after Gate 1 proves the adapter produces usable CICIDS-compatible rows.
- Gate 1 should add validation scripts that compare:
  - current Scapy extractor output
  - CICFlowMeter adapter output
  - missing columns
  - changed feature values
  - AIS anomaly score differences
- The adapter must handle both column rename and unit conversion:
  - CICFlowMeter snake_case names must become CICIDS2017 names.
  - duration/IAT/active/idle time fields must be converted to CICIDS-compatible microsecond units if the library returns seconds.
- The adapter must produce a complete feature row matching the fitted CICIDS schema:
  - mapped values when available
  - safe numeric defaults only for missing non-critical fields
  - explicit validation error if required flow identity or core flow statistics are missing
- Keep existing detection code unchanged:
  - `engine.detect_sample(features)` remains the scoring entry point.
  - labels are not involved in live capture.
  - NSL-KDD remains batch-only and must not use this live capture path.
- Add dependency only after Gate 1 is accepted:
  - `cicflowmeter @ git+https://github.com/hieulw/cicflowmeter.git`
  - keep a clear dependency error if the package is missing.

## Test Plan
- Static and backend tests:
  - `python -m compileall app "validate and test\test_backend.py"`
  - `python "validate and test\test_backend.py"`
- Gate 1 validation:
  - generate or load a small PCAP
  - extract flows through legacy Scapy and CICFlowMeter adapter
  - verify CICFlowMeter adapter emits all required CICIDS columns
  - verify bulk features are no longer hardcoded zero when traffic supports them
  - verify at least some anomaly scores differ from legacy extraction
- Gate 2 live validation:
  - start live capture using the CICFlowMeter runtime path
  - confirm packets and completed flows increment
  - confirm `sniffer_error` stays empty
  - confirm dashboard receives live normal/anomaly updates
  - stop capture and verify final flows flush
- Runtime validation:
  - confirm no runtime imports point to the archived Scapy capture implementation
  - confirm NSL-KDD active model still blocks live capture

## Assumptions
- The project remains CICIDS2017-based for live capture.
- `hieulw/cicflowmeter` is treated as CICFlowMeter-compatible, not guaranteed perfect parity with the original CICIDS2017 generator.
- The main FYP defense is feature consistency: training and live inference both use CICFlowMeter-style flow features.
- The custom Scapy aggregator is archived only for historical reference.
- No model, threshold, NSA, Self-Boundary, Isolation Forest, or metric logic should be changed as part of this capture redesign.
