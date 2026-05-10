import { useState } from 'react';
import '../components/Layout/Layout.css';

// ── SVG Icons (no emojis) ────────────────────────────────────────────────────
const IconBook   = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>;
const IconRocket = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg>;
const IconHelp    = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const IconTool    = () => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>;
const IconChevron = ({ open }) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }}><polyline points="6 9 12 15 18 9"/></svg>;

// ── Shared styles ─────────────────────────────────────────────────────────────
const S = {
  sectionTitle: {
    display: 'flex', alignItems: 'center', gap: '8px',
    fontSize: '11px', fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
    color: 'var(--text-tertiary)', textTransform: 'uppercase',
    letterSpacing: '0.08em', marginBottom: '14px',
  },
  card: {
    background: 'var(--bg-surface)', border: '1px solid var(--border)',
    borderRadius: 'var(--radius)', padding: '18px',
  },
};

// ── 1. Getting Started ────────────────────────────────────────────────────────
const STEPS = [
  { n: '01', title: 'Upload Dataset',     desc: 'Navigate to Train & Detect. Upload a CIC-IDS-2017 CSV or Parquet file using the file picker in the Training tab.' },
  { n: '02', title: 'Train the Model',    desc: 'Configure parameters (model type, threshold) then click Train. Watch the real-time log stream as the NSA builds its Self profile.' },
  { n: '03', title: 'Run Batch Detection',desc: 'Switch to the Detection tab. Upload a test CSV log file. The system will analyse every flow and flag anomalies.' },
  { n: '04', title: 'Review Alerts',      desc: 'Open the Alerts page to filter, inspect, and manage flagged flows. Mark false positives to refine the model over time.' },
];

function GettingStarted() {
  return (
    <div>
      <div style={S.sectionTitle}><IconRocket /> Getting Started</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '12px' }}>
        {STEPS.map(s => (
          <div key={s.n} style={{ ...S.card, position: 'relative', paddingTop: '22px' }}>
            <span style={{
              position: 'absolute', top: '14px', right: '14px',
              fontFamily: "'JetBrains Mono', monospace", fontSize: '24px',
              fontWeight: 800, color: 'var(--accent)', opacity: 0.18, lineHeight: 1,
            }}>{s.n}</span>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: '12px', color: 'var(--text-primary)', marginBottom: '8px' }}>
              {s.title}
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{s.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── 2. FAQ Accordion ──────────────────────────────────────────────────────────
const FAQS = [
  { q: 'What is AIS-Detect?',
    a: 'AIS-Detect is a network intrusion detection system (NIDS) inspired by biological Artificial Immune Systems. It learns what "normal" network traffic looks like and flags anything that deviates from that profile as a potential threat.' },
  { q: 'What is the Negative Selection Algorithm (NSA)?',
    a: 'The NSA mimics how the human immune system trains T-cells. During training, random detector candidates are generated and any that "react" to known normal (Self) traffic are discarded. Only detectors that ignore normal traffic survive — these are used to flag anomalies.' },
  { q: 'What dataset does AIS-Detect use?',
    a: 'AIS-Detect is designed for the CIC-IDS-2017 dataset, a benchmark intrusion detection dataset containing labelled network traffic including DoS, DDoS, Brute Force, and Botnet attacks alongside benign traffic.' },
  { q: 'What file formats can I upload for training?',
    a: 'Both CSV and Parquet formats are supported. The file must include a "Label" column containing "BENIGN" rows for the NSA to learn from. Feature columns should match the CIC-IDS-2017 schema.' },
  { q: 'How long does training take?',
    a: 'Training time depends on dataset size and your hardware. Typically 1–5 minutes for a standard CIC-IDS-2017 file on a modern CPU. The live log stream shows real-time progress including detector generation counts.' },
  { q: 'What does "Active Antibodies" mean?',
    a: '"Active Antibodies" refers to the mature V-Detectors generated by the NSA during training. Each detector patrols a region of non-self (abnormal) feature space. More detectors generally means better coverage of potential attack patterns.' },
  { q: 'What is a Zero-Day Candidate?',
    a: 'A Zero-Day Candidate is an anomaly that scores above the novelty threshold but does not match any known attack pattern in the detector repertoire. It represents potentially novel, previously unseen threats — analogous to the innate immune response.' },
  { q: 'What is the difference between NSA and Isolation Forest?',
    a: 'The NSA is a biologically-inspired model that builds explicit non-self detectors — it is interpretable and suited to novelty detection. Isolation Forest is a statistical baseline that isolates anomalies using random decision trees. It is faster but less interpretable. Both are available in Settings.' },
  { q: 'How do I mark a false positive?',
    a: 'On the Alerts page, each alert has a "Mark FP" button. Clicking it flags the alert as a false positive, removing it from the active threat count. This data can be used to refine thresholds in future training runs.' },
  { q: 'Why is my detection accuracy low?',
    a: 'Low accuracy can result from: (1) the model being trained on insufficient BENIGN data, (2) a mismatch between training and detection file schemas, or (3) a threshold set too low. Try retraining with a more balanced dataset and adjusting the Anomaly Threshold in Settings.' },
];

function FaqAccordion() {
  const [open, setOpen] = useState(null);
  return (
    <div>
      <div style={S.sectionTitle}><IconHelp /> Frequently Asked Questions</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {FAQS.map((f, i) => {
          const isOpen = open === i;
          return (
            <div key={i} style={{
              ...S.card, padding: '0',
              border: `1px solid ${isOpen ? 'var(--accent)' : 'var(--border)'}`,
              transition: 'border-color 0.15s ease',
            }}>
              <button
                onClick={() => setOpen(isOpen ? null : i)}
                aria-expanded={isOpen}
                style={{
                  width: '100%', display: 'flex', justifyContent: 'space-between',
                  alignItems: 'center', gap: '12px',
                  background: 'none', border: 'none', cursor: 'pointer',
                  padding: '14px 16px', textAlign: 'left',
                  color: isOpen ? 'var(--accent)' : 'var(--text-primary)',
                  fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', fontWeight: 600,
                  transition: 'color 0.15s ease',
                }}
              >
                <span>{f.q}</span>
                <span style={{ flexShrink: 0 }}><IconChevron open={isOpen} /></span>
              </button>
              <div style={{
                maxHeight: isOpen ? '200px' : '0',
                overflow: 'hidden',
                transition: 'max-height 0.25s ease',
              }}>
                <div style={{ padding: '0 16px 14px', borderTop: '1px solid var(--border)' }}>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.65, paddingTop: '12px' }}>{f.a}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── 4. Glossary ───────────────────────────────────────────────────────────────
const GLOSSARY = [
  { term: 'Negative Selection Algorithm',  def: 'A bio-inspired ML method that trains detectors on what is NOT normal, mirroring how the immune system filters self-reactive T-cells in the thymus.' },
  { term: 'V-Detector',                    def: 'A variant of NSA where each detector has a variable activation radius, allowing more efficient non-self space coverage.' },
  { term: 'Self Profile / Self Samples',   def: 'The set of BENIGN (normal) network flows used during training to define what the system should NOT flag.' },
  { term: 'Active Antibodies',             def: 'Mature detectors that survived negative selection. Each one covers a region of abnormal feature space and triggers on matching traffic.' },
  { term: 'Anomaly Score',                 def: 'A confidence value (0–1) representing how strongly the system believes a flow is abnormal. Higher = more confident anomaly.' },
  { term: 'Zero-Day Candidate',            def: 'An anomaly with a high novelty score that does not match known attack patterns. May indicate a new, unseen threat type.' },
  { term: 'False Positive Rate (FPR)',     def: 'The proportion of normal flows incorrectly flagged as anomalies. Lower is better. Can be tuned via the Anomaly Threshold in Settings.' },
  { term: 'Isolation Forest',              def: 'A tree-based statistical anomaly detection algorithm. Used as a performance baseline alongside the NSA.' },
  { term: 'CIC-IDS-2017',                  def: 'A publicly available benchmark dataset from the Canadian Institute for Cybersecurity containing real network attack traffic with ground-truth labels.' },
  { term: 'Benign Traffic',                def: 'Normal, non-malicious network flows. The NSA trains exclusively on these to build its Self profile.' },
  { term: 'Batch Detection',               def: 'Offline analysis of a historical log CSV file. All flows are scored in one pass. Contrast with Live Capture.' },
  { term: 'Live Capture',                  def: 'Real-time packet sniffing that aggregates flows on-the-fly and streams anomaly alerts via WebSocket. Requires admin privileges and Npcap.' },
];

function Glossary() {
  return (
    <div>
      <div style={S.sectionTitle}><IconBook /> Glossary</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '10px' }}>
        {GLOSSARY.map(g => (
          <div key={g.term} style={{ ...S.card }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', fontWeight: 700, color: 'var(--accent)', marginBottom: '6px' }}>{g.term}</div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{g.def}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── 5. Troubleshooting ────────────────────────────────────────────────────────
const ISSUES = [
  { problem: 'Training fails immediately',
    solution: 'Verify the uploaded file is CSV or Parquet with a "Label" column. Ensure the file contains at least some rows labelled "BENIGN". Check the backend log for specific error details.' },
  { problem: 'Detection returns 0 anomalies',
    solution: 'The model may be over-fitted to a very small dataset. Try retraining with more data. Also check that the Anomaly Threshold in Settings is not set too high.' },
  { problem: 'Login credentials not accepted',
    solution: 'Ensure the FastAPI backend is running on port 8000. Default credentials are set during first run. If forgotten, restart the backend — the database resets on a fresh launch.' },
  { problem: 'Live capture not working',
    solution: 'Live packet capture requires Administrator privileges (run the terminal as Admin on Windows) and Npcap must be installed. The route /api/capture/* will return 403 without these.' },
  { problem: 'Dashboard charts appear empty',
    solution: 'Charts populate from the alerts state. If no batch detection or live capture has been run, there will be no data to display. Run a detection pass first.' },
];

function Troubleshooting() {
  return (
    <div>
      <div style={S.sectionTitle}><IconTool /> Troubleshooting</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {ISSUES.map(item => (
          <div key={item.problem} style={{ ...S.card, display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: '16px', alignItems: 'start' }}>
            <div>
              <div style={{ fontSize: '9px', fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, color: 'var(--danger)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>Problem</div>
              <div style={{ fontSize: '12px', fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: 'var(--text-primary)' }}>{item.problem}</div>
            </div>
            <div>
              <div style={{ fontSize: '9px', fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, color: 'var(--success)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>Solution</div>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{item.solution}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function Accessibility() {
  return (
    <div className="page">
      {/* Header */}
      <div className="page-header">
        <h1 className="page-title">Accessibility & Help Centre</h1>
        <p className="page-subtitle">User guide, FAQ, glossary, and troubleshooting for AIS-Detect</p>
      </div>

      {/* Getting Started — full width */}
      <div style={{ marginBottom: '24px' }}>
        <GettingStarted />
      </div>

      {/* FAQ */}
      <div style={{ marginBottom: '24px' }}>
        <FaqAccordion />
      </div>

      {/* Glossary */}
      <div style={{ marginBottom: '24px' }}>
        <Glossary />
      </div>

      {/* Troubleshooting */}
      <Troubleshooting />
    </div>
  );
}
