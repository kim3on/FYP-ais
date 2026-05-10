# Accessibility & Help Page — Implementation Plan

A new **Accessibility** page combining a user help centre (FAQ, Getting Started, Glossary, Troubleshooting) with real WCAG-2.1 compliance information and app-specific keyboard navigation notes.

---

## Proposed Page Layout

```
┌─────────────────────────────────────────────────────────┐
│  ♿  Accessibility & Help Centre          [page header]  │
│  Your guide to AIS-Detect and accessibility features    │
├──────────────────────────────────┬──────────────────────┤
│  🚀 Getting Started (3-step)     │  ♿ WCAG 2.1 Status   │
│  Numbered workflow cards         │  Compliance checklist │
├──────────────────────────────────┴──────────────────────┤
│  ❓ FAQ Accordion  (full width, expandable Q&A cards)   │
├─────────────────────────────────────────────────────────┤
│  📖 Glossary Grid  (term → plain-English definition)    │
├─────────────────────────────────────────────────────────┤
│  🔧 Troubleshooting  (2-col problem → solution cards)   │
└─────────────────────────────────────────────────────────┘
```

---

## Sections & Content Detail

### 1. Getting Started — 4-step numbered workflow
| Step | Title | Description |
|---|---|---|
| 01 | Upload Dataset | Navigate to Train & Detect → upload a CIC-IDS-2017 CSV/Parquet |
| 02 | Train the Model | Configure parameters and click Train. Watch the live log stream |
| 03 | Run Batch Detection | Switch to the Detection tab → upload a log CSV → view flagged flows |
| 04 | Review Alerts | Go to the Alerts page to review, filter, and mark false positives |

### 2. WCAG 2.1 Compliance Card (right side of top row)
- **Perceivable:** high-contrast colours (Rosé Pine dark theme), text alternatives
- **Operable:** full keyboard navigation, no timed content
- **Understandable:** consistent layout, error messages, clear labels
- **Robust:** semantic HTML5, ARIA labels on interactive elements
- Keyboard shortcut reference table (Tab, Enter, Esc, Arrow keys)

### 3. FAQ Accordion (expandable, click to toggle)
Planned Q&A pairs:
1. What is AIS-Detect?
2. What is the Negative Selection Algorithm (NSA)?
3. What dataset does AIS-Detect use?
4. What file formats can I upload?
5. How long does training take?
6. What does "Active Antibodies" mean?
7. What is a Zero-Day Candidate?
8. What is the difference between NSA and Isolation Forest?
9. How do I mark a false positive?
10. Why is my detection accuracy low?

### 4. Glossary Grid (2-column card grid)
Terms to define in plain English:
- Negative Selection Algorithm (NSA)
- V-Detector
- Self Profile / Self Samples
- Active Antibodies / Detectors
- Anomaly Score / Confidence Score
- Zero-Day Candidate
- False Positive Rate (FPR)
- Isolation Forest
- CIC-IDS-2017
- Benign / Normal Traffic
- Batch Detection
- Live Capture

### 5. Troubleshooting (problem → solution pairs)
- "Training fails immediately" → check file format, ensure BENIGN rows exist
- "Detection returns 0 anomalies" → model may need retraining, check threshold
- "Login fails" → check credentials; backend must be running
- "Live capture not working" → requires admin privileges + Npcap installed
- "Charts are empty on Dashboard" → no alerts yet; run detection first

---

## Files to Change

### [NEW] `frontend/src/pages/Accessibility.jsx`
The full page component with all 5 sections. Self-contained with all inline styles matching the existing design system (`var(--bg-surface)`, `var(--font-mono)`, etc.).

### [MODIFY] `frontend/src/App.jsx`
- Import `Accessibility` page
- Add route: `<Route path="accessibility" element={<Accessibility />} />`

### [MODIFY] `frontend/src/components/Layout/Sidebar.jsx`
- Add `{ to: '/accessibility', icon: '⬡', label: 'Accessibility' }` to the `NAV` array
- Icon to use: `♿` (standard accessibility icon, Unicode U+267F)

---

## Design Decisions

- **Accordion FAQ:** State managed with `useState` — one open index at a time. Smooth height animation via `maxHeight` CSS transition.
- **WCAG card:** Displayed as a green/amber checklist with pass/partial status indicators. Uses existing `var(--success)`, `var(--warning)` tokens.
- **Glossary:** CSS Grid `repeat(auto-fill, minmax(240px, 1fr))` — adapts to screen width.
- **No new dependencies.** Everything is pure React + inline styles using existing CSS variables.
- **Font:** JetBrains Mono for all labels/values, consistent with the rest of the app.

---

## Verification Plan
- Confirm new nav item appears in sidebar with ♿ icon
- Confirm route `/accessibility` renders without errors
- Open/close each FAQ accordion item
- Verify page renders cleanly in both light and dark themes
