# CICFlowMeter Integration Plan

## Goal
Replace the custom `FlowAggregator` + `FlowFeatureExtractor` in `capture.py` with the
`hieulw/cicflowmeter` library to achieve full feature parity with the CIC-IDS-2017
training dataset generator. Validate improvement before any production code change.

---

> [!IMPORTANT]
> This plan has **two gates**. Phase 1 must pass validation before Phase 2 begins.
> No production files are touched until after Phase 1 confirms improvement.

---

## Phase 1 — Validate Improvement (No production code changes)

### Objective
Prove that cicflowmeter computes measurably different (and more accurate) bulk features
compared to the current hardcoded-zero implementation, and that these differences produce
different anomaly scores from the trained model.

### What Phase 1 Does NOT Do
- Does not modify `capture.py`, `app/routers/capture.py`, or any production module
- Does not install cicflowmeter into the main venv
- Does not change the detection pipeline in any way

---

### 1.1 Environment Setup (test-only)

Create a **separate** test virtual environment for cicflowmeter to avoid polluting the
production venv during evaluation:

```powershell
# From project root
python -m venv .venv_test_cicflow
.\.venv_test_cicflow\Scripts\activate
pip install git+https://github.com/hieulw/cicflowmeter.git
pip install scapy pandas
```

> [!NOTE]
> cicflowmeter requires Scapy, which is already in production requirements.
> The test venv is isolated so any cicflowmeter dependency conflicts don't affect production.

---

### 1.2 Generate a Synthetic PCAP for Comparison

Write a one-time script `validate and test/generate_test_pcap.py` that uses Scapy to
generate a small PCAP with known traffic patterns:

- **Benign flows**: TCP HTTP-like flows with realistic payload sizes and timing
- **DDoS-like flows**: High packet rate, small packets, short duration
- **Brute force-like flows**: Many small TCP connections to port 22

This avoids dependency on raw CIC-IDS-2017 PCAP files (which the user may not have),
and gives fully controlled ground truth for comparison.

---

### 1.3 Validation Script

Write `validate and test/validate_cicflow_parity.py` that:

**Step A — Extract with current `capture.py`**
```
Synthetic PCAP → Scapy packet replay → FlowAggregator → FlowFeatureExtractor
                                                         → dict with CIC column names
```

**Step B — Extract with cicflowmeter**
```
Synthetic PCAP → cicflowmeter AsyncSniffer (offline mode) → FlowSession.get_data()
                                                           → dict with snake_case names
                                                           → rename to CIC column names
```

**Step C — Feature Comparison**
For each matched flow (matched by src_ip, dst_ip, src_port, dst_port):
- Print side-by-side values for all 77 features
- Flag features where absolute difference > 1% of the training range
- Focus report on the 6 bulk features that are currently hardcoded to 0

**Step D — Detection Score Comparison**
Load the trained `preprocessor.pkl` + `nsa.pkl` from `app/artefacts/`:
- Feed current-extractor features → get anomaly score
- Feed cicflowmeter features → get anomaly score
- Report: did the anomaly decision (flag/not flag) change for any flow?
- Report: did the anomaly score change by > 0.05 for any flow?

**Pass criteria for Phase 1:**
- At least one bulk feature has a non-zero value in cicflowmeter output (vs 0 in current)
- Score differences exist (proves the bulk features affect the model's output)
- No crashes or missing features in cicflowmeter output

If Phase 1 passes → proceed to Phase 2.
If Phase 1 shows zero difference → bulk features are irrelevant for this model; document
this and stop (the integration is not worth the risk).

---

## Phase 2 — Full Integration (After Phase 1 passes)

### Architecture

**Current:**
```
PacketSniffer (capture.py)
  └── FlowAggregator
        └── FlowFeatureExtractor
              └── on_flow_complete(dict with "Flow Duration", "Total Fwd Packets", ...)
                    └── capture router → engine.detect_sample()
```

**After integration:**
```
CICFlowMeterBridge (new file: app/core/cicflow_bridge.py)
  └── cicflowmeter.FlowSession  (subclassed, output_writer replaced with callback)
        └── on_flow_complete(dict with "Flow Duration", "Total Fwd Packets", ...)
              └── capture router → engine.detect_sample()  ← unchanged
```

> [!NOTE]
> The `on_flow()` callback in `app/routers/capture.py` does NOT change.
> Only the thing that *calls* it changes (Bridge replaces PacketSniffer).
> This is the key to a safe integration — the detection pipeline is untouched.

---

### Column Name Mapping

cicflowmeter outputs snake_case keys. Our preprocessor expects the original CICFlowMeter
column names. The bridge must rename keys before calling the callback.

Full mapping table (cicflowmeter key → CIC-IDS-2017 column name):

| cicflowmeter key | CIC column name |
|-----------------|-----------------|
| `flow_duration` | `Flow Duration` |
| `flow_byts_s` | `Flow Bytes/s` |
| `flow_pkts_s` | `Flow Packets/s` |
| `fwd_pkts_s` | `Fwd Packets/s` |
| `bwd_pkts_s` | `Bwd Packets/s` |
| `tot_fwd_pkts` | `Total Fwd Packets` |
| `tot_bwd_pkts` | `Total Backward Packets` |
| `totlen_fwd_pkts` | `Total Length of Fwd Packets` |
| `totlen_bwd_pkts` | `Total Length of Bwd Packets` |
| `fwd_pkt_len_max` | `Fwd Packet Length Max` |
| `fwd_pkt_len_min` | `Fwd Packet Length Min` |
| `fwd_pkt_len_mean` | `Fwd Packet Length Mean` |
| `fwd_pkt_len_std` | `Fwd Packet Length Std` |
| `bwd_pkt_len_max` | `Bwd Packet Length Max` |
| `bwd_pkt_len_min` | `Bwd Packet Length Min` |
| `bwd_pkt_len_mean` | `Bwd Packet Length Mean` |
| `bwd_pkt_len_std` | `Bwd Packet Length Std` |
| `pkt_len_max` | `Max Packet Length` |
| `pkt_len_min` | `Min Packet Length` |
| `pkt_len_mean` | `Packet Length Mean` |
| `pkt_len_std` | `Packet Length Std` |
| `pkt_len_var` | `Packet Length Variance` |
| `fwd_header_len` | `Fwd Header Length` |
| `bwd_header_len` | `Bwd Header Length` |
| `fwd_seg_size_min` | `min_seg_size_forward` |
| `fwd_act_data_pkts` | `act_data_pkt_fwd` |
| `flow_iat_mean` | `Flow IAT Mean` |
| `flow_iat_max` | `Flow IAT Max` |
| `flow_iat_min` | `Flow IAT Min` |
| `flow_iat_std` | `Flow IAT Std` |
| `fwd_iat_tot` | `Fwd IAT Total` |
| `fwd_iat_max` | `Fwd IAT Max` |
| `fwd_iat_min` | `Fwd IAT Min` |
| `fwd_iat_mean` | `Fwd IAT Mean` |
| `fwd_iat_std` | `Fwd IAT Std` |
| `bwd_iat_tot` | `Bwd IAT Total` |
| `bwd_iat_max` | `Bwd IAT Max` |
| `bwd_iat_min` | `Bwd IAT Min` |
| `bwd_iat_mean` | `Bwd IAT Mean` |
| `bwd_iat_std` | `Bwd IAT Std` |
| `fwd_psh_flags` | `Fwd PSH Flags` |
| `bwd_psh_flags` | `Bwd PSH Flags` |
| `fwd_urg_flags` | `Fwd URG Flags` |
| `bwd_urg_flags` | `Bwd URG Flags` |
| `fin_flag_cnt` | `FIN Flag Count` |
| `syn_flag_cnt` | `SYN Flag Count` |
| `rst_flag_cnt` | `RST Flag Count` |
| `psh_flag_cnt` | `PSH Flag Count` |
| `ack_flag_cnt` | `ACK Flag Count` |
| `urg_flag_cnt` | `URG Flag Count` |
| `ece_flag_cnt` | `ECE Flag Count` |
| `cwr_flag_count` | `CWE Flag Count` |
| `down_up_ratio` | `Down/Up Ratio` |
| `pkt_size_avg` | `Average Packet Size` |
| `fwd_seg_size_avg` | `Avg Fwd Segment Size` |
| `bwd_seg_size_avg` | `Avg Bwd Segment Size` |
| `init_fwd_win_byts` | `Init_Win_bytes_forward` |
| `init_bwd_win_byts` | `Init_Win_bytes_backward` |
| `active_max` | `Active Max` |
| `active_min` | `Active Min` |
| `active_mean` | `Active Mean` |
| `active_std` | `Active Std` |
| `idle_max` | `Idle Max` |
| `idle_min` | `Idle Min` |
| `idle_mean` | `Idle Mean` |
| `idle_std` | `Idle Std` |
| `fwd_byts_b_avg` | `Fwd Avg Bytes/Bulk` |
| `fwd_pkts_b_avg` | `Fwd Avg Packets/Bulk` |
| `bwd_byts_b_avg` | `Bwd Avg Bytes/Bulk` |
| `bwd_pkts_b_avg` | `Bwd Avg Packets/Bulk` |
| `fwd_blk_rate_avg` | `Fwd Avg Bulk Rate` |
| `bwd_blk_rate_avg` | `Bwd Avg Bulk Rate` |
| `subflow_fwd_pkts` | `Subflow Fwd Packets` |
| `subflow_bwd_pkts` | `Subflow Bwd Packets` |
| `subflow_fwd_byts` | `Subflow Fwd Bytes` |
| `subflow_bwd_byts` | `Subflow Bwd Bytes` |
| `dst_port` | `Destination Port` *(metadata, not a feature)* |
| `src_ip` | `_src_ip` *(metadata, not a feature)* |
| `dst_ip` | `_dst_ip` *(metadata, not a feature)* |
| `src_port` | `_src_port` *(metadata, not a feature)* |
| `protocol` | `_protocol` *(metadata, not a feature)* |

> [!NOTE]
> `Destination Port` exists in your training data but is dropped by `_clean()` before
> model scoring. Keep it in the renamed dict — it'll be silently dropped by the
> preprocessor just like in batch detection.

---

### 2.1 Files to Create

#### [NEW] `app/core/cicflow_bridge.py`

A thin subclass of `cicflowmeter.flow_session.FlowSession` that:
1. Overrides `output_writer` with a no-op writer
2. Instead of writing to CSV/URL, calls `self._on_flow_complete(renamed_dict)` 
3. Adds the metadata keys (`_src_ip`, `_dst_ip`, etc.) the capture router expects
4. Handles the `CWE Flag Count` bug (library aliases it to `fwd_urg_flags`; we fix it
   by computing it correctly from packet flags, or accepting the approximation)

Also contains `CICFlowMeterSniffer` class with the same `start()` / `stop(flush=True)` /
`is_running` / `packets_captured` / `resolved_interface` interface as the current
`PacketSniffer` — so the capture router needs zero changes.

#### [MOVE] `app/core/capture.py`

- Move the old custom Scapy implementation to `legacy/capture_legacy.py`.
- Do not import the archived implementation from the runtime app.

#### [MODIFY] `app/routers/capture.py` — line 57 only

```python
# Before:
from app.core.capture_factory import get_packet_sniffer_class

# After:
from app.core.cicflow_bridge import CICFlowMeterSniffer as PacketSniffer
```

That is the **only required change** to the capture router.

#### [MODIFY] `requirements.txt`

Add:
```
cicflowmeter @ git+https://github.com/hieulw/cicflowmeter.git
```

> [!WARNING]
> cicflowmeter installs from git, not PyPI. This means `pip install -r requirements.txt`
> requires internet access and git. If your exam/demo environment is air-gapped, bundle
> the wheel first: `pip wheel git+https://github.com/hieulw/cicflowmeter.git -w wheels/`

---

### 2.2 Files to NOT Change

- `app/routers/capture.py` — beyond the one import line swap
- `app/core/detection.py`
- `app/core/pipeline.py`
- `app/core/preprocessor.py`
- All model files (`nsa.py`, `self_boundary.py`, `isolation_forest.py`)
- Frontend

---

### 2.3 Known Risk: `CWE Flag Count` Bug

The library has this alias: `data["cwr_flag_count"] = data["fwd_urg_flags"]`  
This is incorrect — CWR and URG are different TCP flags.

**Mitigation in bridge**: After renaming, overwrite `CWE Flag Count` by recomputing from
the raw packet's TCP flags. The bridge's `FlowSession` subclass has access to all packets
so this is feasible.  
If raw packet access is too complex: set `CWE Flag Count = 0` (same as current behavior)
and document this as a known limitation.

---

## Verification Plan

### After Phase 1
- [ ] Run `validate_cicflow_parity.py` — confirm bulk features are non-zero
- [ ] Confirm at least some flows have different anomaly scores
- [ ] Document score difference magnitude (expected: small, < 0.05 average)

### After Phase 2
- [ ] Install cicflowmeter in production venv
- [ ] Start live capture — confirm flows complete and are scored
- [ ] Check `CWE Flag Count` value in logged features (should not equal `Fwd URG Flags`)
- [ ] Run batch detection on Friday DDoS parquet — confirm recall is unchanged or improved
  (live vs batch should now be consistent)
- [ ] Check `sniffer_error` stays `null` during 5-minute capture session
- [ ] Confirm `packets_captured` counter increments correctly

---

## Open Questions

> [!IMPORTANT]
> **Do you have any raw PCAP files from CIC-IDS-2017?**  
> If yes, we can use them directly in Phase 1 instead of generating synthetic packets.
> This gives a more realistic comparison since the PCAP traffic matches exactly what
> the dataset was built from.

> [!NOTE]
> **Windows + Npcap compatibility**: cicflowmeter uses Scapy's `AsyncSniffer` which has
> the same Windows/Npcap requirement as your current `PacketSniffer`. No additional
> driver requirements.
