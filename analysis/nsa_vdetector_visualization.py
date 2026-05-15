"""
Generate a deterministic SVG visualization of AIS-Detect's V-detector NSA.

This is a 2D teaching visualization only. The production model operates in
CIC-IDS feature space after scaling/PCA, so the SVG should be used to explain
the detector geometry rather than to claim real dataset separability.
"""

from __future__ import annotations

import math
import os
import random
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.models.nsa import NegativeSelectionDetector


OUT = Path(__file__).with_suffix(".svg")
WIDTH = 1200
HEIGHT = 820
PLOT_X = 90
PLOT_Y = 92
PLOT_W = 760
PLOT_H = 640
X_MIN, X_MAX = -0.05, 1.05
Y_MIN, Y_MAX = -0.05, 1.05


def sx(x: float) -> float:
    return PLOT_X + (x - X_MIN) / (X_MAX - X_MIN) * PLOT_W


def sy(y: float) -> float:
    return PLOT_Y + (Y_MAX - y) / (Y_MAX - Y_MIN) * PLOT_H


def sr(r: float) -> float:
    return r / (X_MAX - X_MIN) * PLOT_W


def circle(cx, cy, r, fill, stroke, opacity=1.0, width=1.0, extra="") -> str:
    return (
        f'<circle cx="{sx(cx):.2f}" cy="{sy(cy):.2f}" r="{sr(r):.2f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{width}" '
        f'opacity="{opacity}" {extra}/>'
    )


def text(x, y, body, size=18, weight=400, fill="#1f2937", anchor="start") -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="Inter, Arial, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill}" '
        f'text-anchor="{anchor}">{body}</text>'
    )


def synthetic_self(seed: int = 7) -> np.ndarray:
    rng = np.random.default_rng(seed)
    blobs = [
        rng.normal([0.42, 0.58], [0.045, 0.055], size=(34, 2)),
        rng.normal([0.57, 0.47], [0.055, 0.040], size=(32, 2)),
        rng.normal([0.50, 0.67], [0.035, 0.035], size=(24, 2)),
    ]
    points = np.vstack(blobs)
    return np.clip(points, 0.18, 0.82).astype(np.float32)


def rejected_candidates(self_points: np.ndarray, r_s: float, seed: int = 13):
    rng = random.Random(seed)
    rejected = []
    accepted_probe = []
    for _ in range(220):
        p = np.array([rng.random(), rng.random()], dtype=np.float32)
        dmin = float(np.sqrt(((self_points - p) ** 2).sum(axis=1)).min())
        if dmin <= r_s and len(rejected) < 28:
            rejected.append((float(p[0]), float(p[1])))
        elif dmin > r_s and len(accepted_probe) < 16:
            accepted_probe.append((float(p[0]), float(p[1])))
        if len(rejected) >= 28 and len(accepted_probe) >= 16:
            break
    return rejected, accepted_probe


def main() -> None:
    self_points = synthetic_self()
    model = NegativeSelectionDetector(
        r=0.22,
        r_s=0.045,
        max_detectors=26,
        max_attempts=900,
        random_state=11,
        auto_threshold=False,
    )
    model.fit(self_points)

    detectors = model.detectors_
    radii = model.det_radii_
    order = np.argsort(radii)[::-1]
    detectors = detectors[order][:20]
    radii = radii[order][:20]
    rejected, accepted_probe = rejected_candidates(self_points, model.r_s)

    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="820" viewBox="0 0 1200 820">',
        '<rect width="1200" height="820" fill="#f8fafc"/>',
        text(60, 48, "Negative Selection Algorithm / V-Detector Geometry", 28, 700, "#0f172a"),
        text(
            60,
            76,
            "2D teaching view: self samples reject nearby candidates; surviving mature detectors cover non-self space.",
            15,
            400,
            "#475569",
        ),
        f'<rect x="{PLOT_X}" y="{PLOT_Y}" width="{PLOT_W}" height="{PLOT_H}" rx="8" fill="#ffffff" stroke="#cbd5e1"/>',
    ]

    for i in range(0, 12):
        gx = PLOT_X + i * PLOT_W / 11
        gy = PLOT_Y + i * PLOT_H / 11
        parts.append(f'<line x1="{gx:.2f}" y1="{PLOT_Y}" x2="{gx:.2f}" y2="{PLOT_Y + PLOT_H}" stroke="#e2e8f0"/>')
        parts.append(f'<line x1="{PLOT_X}" y1="{gy:.2f}" x2="{PLOT_X + PLOT_W}" y2="{gy:.2f}" stroke="#e2e8f0"/>')

    parts.append(
        f'<rect x="{sx(0.18):.2f}" y="{sy(0.82):.2f}" width="{sr(0.64):.2f}" '
        f'height="{sr(0.64):.2f}" fill="#f1f5f9" stroke="#94a3b8" stroke-dasharray="6 6"/>'
    )
    parts.append(text(sx(0.19), sy(0.84), "self region", 13, 600, "#64748b"))

    for cx, cy, radius in zip(detectors[:, 0], detectors[:, 1], radii):
        if X_MIN - 0.25 <= cx <= X_MAX + 0.25 and Y_MIN - 0.25 <= cy <= Y_MAX + 0.25:
            parts.append(circle(float(cx), float(cy), float(radius), "#22c55e", "#166534", 0.20, 2.0))

    for x, y in rejected:
        parts.append(circle(x, y, 0.008, "#ef4444", "#991b1b", 0.65, 1.0))

    for x, y in accepted_probe:
        parts.append(circle(x, y, 0.008, "#38bdf8", "#0369a1", 0.7, 1.0))

    for x, y in self_points:
        parts.append(circle(float(x), float(y), model.r_s, "#64748b", "#334155", 0.17, 1.0))
        parts.append(circle(float(x), float(y), 0.0065, "#334155", "#0f172a", 0.9, 1.0))

    for cx, cy, radius in zip(detectors[:, 0], detectors[:, 1], radii):
        parts.append(circle(float(cx), float(cy), 0.008, "#16a34a", "#14532d", 0.95, 1.0))

    panel_x = 890
    parts.extend(
        [
            text(panel_x, 130, "How to read it", 22, 700, "#0f172a"),
            text(panel_x, 170, "1. Grey points are BENIGN self samples.", 15, 500, "#334155"),
            text(panel_x, 205, "2. Grey halos are the self-tolerance radius r_s.", 15, 500, "#334155"),
            text(panel_x, 240, "3. Red candidates are rejected: too close to self.", 15, 500, "#334155"),
            text(panel_x, 275, "4. Green circles are mature V-detectors.", 15, 500, "#334155"),
            text(panel_x, 310, "5. A flow inside a mature detector is anomalous.", 15, 500, "#334155"),
            text(panel_x, 365, "AIS-Detect additions", 22, 700, "#0f172a"),
            text(panel_x, 405, "• Works after RobustScaler + PCA whitening", 15, 500, "#334155"),
            text(panel_x, 435, "• Uses variable detector radii", 15, 500, "#334155"),
            text(panel_x, 465, "• Calibrates benign false-positive behavior", 15, 500, "#334155"),
            text(panel_x, 495, "• Uses detector hit as primary NSA evidence", 15, 500, "#334155"),
            text(panel_x, 575, f"Self samples: {len(self_points)}", 15, 700, "#0f172a"),
            text(panel_x, 605, f"Mature detectors drawn: {len(detectors)}", 15, 700, "#0f172a"),
            text(panel_x, 635, f"r_s: {model.r_s:.3f}", 15, 700, "#0f172a"),
            text(panel_x, 665, f"largest detector radius: {float(radii.max()):.3f}", 15, 700, "#0f172a"),
        ]
    )

    legend_y = 748
    legend = [
        ("#334155", "Self sample"),
        ("#ef4444", "Rejected candidate"),
        ("#38bdf8", "Candidate outside self"),
        ("#22c55e", "Mature detector coverage"),
    ]
    lx = 95
    for color, label in legend:
        parts.append(f'<circle cx="{lx}" cy="{legend_y}" r="7" fill="{color}" opacity="0.8"/>')
        parts.append(text(lx + 16, legend_y + 5, label, 13, 600, "#334155"))
        lx += 190

    parts.append("</svg>")
    OUT.write_text("\n".join(parts), encoding="utf-8")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
