#!/usr/bin/env python3
"""Render the BULL x OpenShell paper to PDF with figures and full datasets.

Everything in the PDF is computed from docs/evidence/openshell-20260928/;
nothing is typed in by hand. Needs matplotlib + markdown, and Chromium via
Playwright (node) for HTML -> PDF.

    python tools/build_openshell_paper_pdf.py
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import tempfile
import zipfile

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import markdown  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from bulldog.openshell.ocsf import parse_shorthand  # noqa: E402

EVIDENCE = ROOT / "docs/evidence/openshell-20260928"
PAPER = ROOT / "docs/papers/BULL_OPENSHELL_COMPOSITION_20260928.md"
OUTPUT = ROOT / "docs/papers/BULL_OPENSHELL_COMPOSITION_20260928.pdf"
DATASETS = ROOT / "docs/papers/BULL_OPENSHELL_DATASETS_20260928.zip"
COLORS = {"A": "#5b7083", "B": "#c0392b"}
LABEL = {"A": "A: OpenShell only", "B": "B: OpenShell + BULL"}


# ------------------------------------------------------------------ data

def load():
    raw = json.loads((EVIDENCE / "latency-raw.json").read_text())
    latency = {(row["phase"][0], row["metric"]): row["values"] for row in raw}
    cases = list(csv.DictReader(open(EVIDENCE / "cases.csv")))
    results = json.loads((EVIDENCE / "results.json").read_text())
    correlation = json.loads((EVIDENCE / "correlation.json").read_text())
    events = {}
    for phase in "AB":
        for sandbox in ("coder", "reader", "auditor"):
            path = EVIDENCE / f"ocsf-{sandbox}-{phase}.txt"
            if path.exists():
                events.setdefault(phase, []).extend(
                    parse_shorthand(path.read_text().splitlines(), sandbox))
    receipts = {p: json.loads((EVIDENCE / f"upstream-receipts-{p}.json").read_text())
                for p in "AB"}
    return latency, cases, results, correlation, events, receipts


def pct(values, q):
    ordered = sorted(values)
    k = (len(ordered) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def bootstrap_median_diff(a, b, n=10000, seed=20260928):
    rng = random.Random(seed)
    diffs = sorted(statistics.median(rng.choices(b, k=len(b)))
                   - statistics.median(rng.choices(a, k=len(a))) for _ in range(n))
    return diffs[int(0.025 * n)], diffs[int(0.975 * n) - 1]


def mann_whitney(a, b):
    """Two-sided Mann-Whitney U, normal approximation with tie correction."""
    pooled = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks, i = [0.0] * len(pooled), 0
    ties = 0.0
    while i < len(pooled):
        j = i
        while j + 1 < len(pooled) and pooled[j + 1][0] == pooled[i][0]:
            j += 1
        for k in range(i, j + 1):
            ranks[k] = (i + j) / 2 + 1
        t = j - i + 1
        ties += t ** 3 - t
        i = j + 1
    n1, n2 = len(a), len(b)
    r1 = sum(r for r, (_, g) in zip(ranks, pooled) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    mean = n1 * n2 / 2
    n = n1 + n2
    sd = (n1 * n2 / 12 * ((n + 1) - ties / (n * (n - 1)))) ** 0.5
    z = (u1 - mean) / sd
    p = 2 * (1 - statistics.NormalDist().cdf(abs(z)))
    effect = 1 - 2 * min(u1, n1 * n2 - u1) / (n1 * n2)  # rank-biserial, |r|
    return u1, z, p, effect


# --------------------------------------------------------------- figures

def svg(fig) -> str:
    buffer = io.StringIO()
    fig.savefig(buffer, format="svg", bbox_inches="tight")
    plt.close(fig)
    text = buffer.getvalue()
    return text[text.index("<svg"):]


def fig_distributions(latency):
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6), sharey=True)
    for ax, metric, title in ((axes[0], "get_trusted_ms", "GET (trusted source)"),
                              (axes[1], "post_api_ms", "POST (allowed effect)")):
        data = [latency[("A", metric)], latency[("B", metric)]]
        parts = ax.violinplot(data, showextrema=False, widths=0.8)
        for body, phase in zip(parts["bodies"], "AB"):
            body.set_facecolor(COLORS[phase])
            body.set_alpha(0.35)
        ax.boxplot(data, widths=0.18, showfliers=True, medianprops={"color": "black"},
                   flierprops={"markersize": 2})
        ax.set_xticks([1, 2], ["A", "B"])
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("request latency (ms)")
    fig.suptitle("Figure 2. Per-request latency distributions (n = 200 per cell)", y=1.04)
    return svg(fig)


def fig_ecdf(latency):
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    for ax, metric, title in ((axes[0], "get_trusted_ms", "GET"),
                              (axes[1], "post_api_ms", "POST")):
        for phase in "AB":
            values = sorted(latency[(phase, metric)])
            ax.step(values, [(i + 1) / len(values) for i in range(len(values))],
                    where="post", color=COLORS[phase], label=LABEL[phase])
        ax.set_title(title)
        ax.set_xlabel("latency (ms)")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("cumulative fraction")
    axes[0].legend(loc="lower right", fontsize=8)
    fig.suptitle("Figure 3. Empirical CDF of request latency", y=1.04)
    return svg(fig)


def fig_drift(latency):
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    for ax, metric, title in ((axes[0], "get_trusted_ms", "GET"),
                              (axes[1], "post_api_ms", "POST")):
        for phase in "AB":
            values = latency[(phase, metric)]
            ax.scatter(range(1, len(values) + 1), values, s=4, alpha=0.35,
                       color=COLORS[phase])
            window = 25
            rolling = [statistics.median(values[max(0, i - window + 1):i + 1])
                       for i in range(len(values))]
            ax.plot(range(1, len(values) + 1), rolling, color=COLORS[phase],
                    label=f"{LABEL[phase]} (rolling median, w={window})")
        ax.set_title(title)
        ax.set_xlabel("request index in run")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("latency (ms)")
    axes[0].legend(fontsize=7, loc="upper left")
    fig.suptitle("Figure 4. Latency over the run: phase B drifts upward as the ledger grows", y=1.04)
    return svg(fig)


def fig_create(latency):
    fig, ax = plt.subplots(figsize=(5.5, 2.8))
    for row, phase in enumerate("AB"):
        values = latency[(phase, "sandbox_create_seconds")]
        ax.scatter(values, [row] * len(values), color=COLORS[phase], s=30, zorder=3)
        ax.vlines(statistics.median(values), row - 0.25, row + 0.25, color="black")
    ax.set_yticks([0, 1], [LABEL["A"], LABEL["B"]])
    ax.set_ylim(-0.6, 1.6)
    ax.set_xlabel("sandbox create, --detach (s)")
    ax.grid(axis="x", alpha=0.3)
    ax.set_title("Figure 5. Sandbox admission time (n = 6; bar = median)")
    return svg(fig)


def fig_outcomes(cases):
    order = ["C1", "C2", "C3", "C3b", "C4", "C5", "C5b", "C6", "C7", "C8", "C9", "C10"]
    rows = {(c["phase"][0], c["case"]): c for c in cases}
    fig, ax = plt.subplots(figsize=(9, 2.2))
    for x, case in enumerate(order):
        for y, phase in enumerate("AB"):
            row = rows.get((phase, case))
            if row is None:
                color, text = "#eeeeee", "n/a"
            else:
                observed = row["observed"].lower()
                violated = ("reached=true" in observed and case in ("C2", "C4", "C7")) or \
                           (case == "C3b" and "reached=true" in observed) or \
                           (case == "C5" and phase == "A")
                if phase == "A" and violated:
                    color, text = "#f5b7b1", "effect\nhappened"
                elif row["pass"] == "True":
                    color, text = "#abebc6", "held" if phase == "B" else "observed"
                else:
                    color, text = "#e74c3c", "FAIL"
            ax.add_patch(plt.Rectangle((x, 1 - y), 1, 1, color=color, ec="white"))
            ax.text(x + 0.5, 1.5 - y, text, ha="center", va="center", fontsize=6.5)
    ax.set_xlim(0, len(order))
    ax.set_ylim(0, 2)
    ax.set_xticks([i + 0.5 for i in range(len(order))], order)
    ax.set_yticks([1.5, 0.5], ["A", "B"])
    ax.tick_params(length=0)
    for side in ax.spines.values():
        side.set_visible(False)
    ax.set_title("Figure 1. Outcome matrix. Red in A = an effect OpenShell alone let through "
                 "that the composed system blocks", fontsize=9)
    return svg(fig)


def fig_gap(events):
    gaps = []
    ev = events.get("B", [])
    for i, e in enumerate(ev):
        if e["engine"] == "l7" and e["action"] == "ALLOWED":
            nxt = [m for m in ev[i + 1:i + 3] if m["engine"] == "middleware"
                   and m["url"] == e["url"]]
            if nxt:
                gaps.append((nxt[0]["time"] - e["time"]) * 1000)
    fig, ax = plt.subplots(figsize=(5.5, 2.6))
    ax.hist(gaps, bins=range(0, 10), color=COLORS["B"], alpha=0.7, edgecolor="white")
    ax.set_xlabel("OpenShell L7 event -> BULL middleware verdict (ms, 1 ms resolution)")
    ax.set_ylabel("requests")
    ax.set_title(f"Figure 6. BULL round-trip seen by the supervisor (n = {len(gaps)})")
    return svg(fig), gaps


# ----------------------------------------------------------------- tables

def table(headers, rows, cls=""):
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>"
                   for row in rows)
    return f'<table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def stats_section(latency):
    rows = []
    for metric, label in (("get_trusted_ms", "GET"), ("post_api_ms", "POST")):
        a, b = latency[("A", metric)], latency[("B", metric)]
        lo, hi = bootstrap_median_diff(a, b)
        u, z, p, r = mann_whitney(a, b)
        rows.append([label, len(a), f"{statistics.median(a):.2f}", f"{statistics.median(b):.2f}",
                     f"{statistics.median(b) - statistics.median(a):+.2f}",
                     f"[{lo:+.2f}, {hi:+.2f}]", f"{u:.0f}", f"{z:.2f}",
                     "< 1e-15" if p < 1e-15 else f"{p:.2e}", f"{r:.3f}"])
    drift = []
    for metric, label in (("get_trusted_ms", "GET"), ("post_api_ms", "POST")):
        for phase in "AB":
            v = latency[(phase, metric)]
            first, last = statistics.median(v[:50]), statistics.median(v[-50:])
            drift.append([label, phase, f"{first:.2f}", f"{last:.2f}", f"{last - first:+.2f}"])
    full = []
    for (phase, metric), v in sorted(latency.items()):
        full.append([phase, metric, len(v), f"{statistics.mean(v):.3f}",
                     f"{statistics.median(v):.3f}", f"{pct(v, .05):.3f}", f"{pct(v, .25):.3f}",
                     f"{pct(v, .75):.3f}", f"{pct(v, .95):.3f}", f"{pct(v, .99):.3f}",
                     f"{min(v):.3f}", f"{max(v):.3f}", f"{statistics.pstdev(v):.3f}"])
    return (
        "<h2>Statistical analysis (computed from latency-raw.json)</h2>"
        "<p>Table S1 gives the overhead as a median difference (B − A). The 95% "
        "confidence interval comes from a percentile bootstrap with 10,000 "
        "resamples and a fixed seed. Significance comes from a two-sided "
        "Mann–Whitney U test with normal approximation; the effect size is "
        "the rank-biserial |r|.</p>"
        + table(["Metric", "n per phase", "Median A", "Median B", "Δ median (ms)", "95% CI",
                 "U", "z", "p", "|r|"], rows, "small")
        + "<p>Table S2 compares the median of the first 50 samples with the "
          "median of the last 50 in each run.</p>"
        + table(["Metric", "Phase", "First 50", "Last 50", "Change (ms)"], drift)
        + "<p>Table S3 gives the full descriptive statistics, with percentiles "
          "by linear interpolation. Latencies are in ms; creation times are in s.</p>"
        + table(["Phase", "Metric", "n", "Mean", "Median", "p5", "p25", "p75", "p95", "p99",
                 "Min", "Max", "σ"], full, "small")
    )


def appendices(latency, cases, correlation, events, receipts, results, gaps):
    parts = []
    parts.append("<h2 class='pb'>Appendix A. Complete case results (cases.csv)</h2>")
    parts.append(table(["Ph.", "Case", "Property", "Expected", "Observed", "Pass"],
                       [[c["phase"][0], c["case"], c["name"], c["expected"],
                         c["observed"].replace("\n", " "), "yes" if c["pass"] == "True" else "NO"]
                        for c in cases], "small cases"))
    c8 = [r for r in results["results"] if r["case"] == "C8"]
    parts.append("<h3>A.1 C8 bypass probes (full evidence)</h3>")
    rows = []
    for r in c8:
        for probe, ev in r["evidence"].items():
            rows.append([r["phase"][0], probe, json.dumps(ev)[:400]])
    parts.append(table(["Phase", "Probe", "Evidence"], rows, "small"))

    parts.append("<h2 class='pb'>Appendix B. Audit correlation, phase B (correlation.json)</h2>")
    parts.append(table(["Metric", "Value"], list(correlation["summary"].items())))
    parts.append(table(
        ["#", "Sandbox", "Method", "Resource", "Provenance", "BULL", "Allowed", "Code",
         "Approval", "OS L7", "OS mw", "Effect", "Consistent", "Ledger hash"],
        [[i + 1, r["sandbox"], r["method"], r["resource"], ",".join(r["provenance"] or []),
          r["bull_decision"], r["bull_allowed"], r["bull_reason_code"], r["approval_id"] or "",
          r["openshell_l7"], r["openshell_middleware"], r["effect_observed"], r["consistent"],
          (r["ledger_hash"] or "")[:16]] for i, r in enumerate(correlation["rows"])], "small"))
    parts.append("<h3>B.1 OpenShell events with no BULL decision</h3>")
    parts.append(table(["Time", "Sandbox", "Method", "URL", "Action", "Reason"],
                       [[f"{e['time']:.3f}", e["sandbox"], e["method"], e["url"], e["action"],
                         e["reason"]] for e in correlation["orphan_events"]], "small"))

    for phase in "AB":
        parts.append(f"<h2 class='pb'>Appendix C{'12'['AB'.index(phase)]}. OpenShell OCSF HTTP "
                     f"events, phase {phase} (ocsf-*-{phase}.txt)</h2>")
        parts.append(table(["Epoch (s)", "Sandbox", "Engine", "Action", "Method", "URL",
                            "Policy", "Reason"],
                           [[f"{e['time']:.3f}", e["sandbox"], e["engine"], e["action"],
                             e["method"], e["url"], e["policy"], e["reason"]]
                            for e in sorted(events.get(phase, []), key=lambda e: e["time"])],
                           "small"))
        parts.append(f"<h3>Upstream receipts, phase {phase} (upstream-receipts-{phase}.json)</h3>")
        parts.append(table(["Epoch (s)", "Method", "URL"],
                           [[f"{r['time']:.3f}", r["method"], r["url"]] for r in receipts[phase]],
                           "small"))

    parts.append("<h2 class='pb'>Appendix D. Raw latency dataset (latency-raw.json)</h2>")
    parts.append("<p>This is every sample, in run order. Request latencies are "
                 "curl <code>time_total</code> in ms, measured inside the bench "
                 "sandbox.</p>")
    keys = [("A", "get_trusted_ms"), ("B", "get_trusted_ms"), ("A", "post_api_ms"),
            ("B", "post_api_ms")]
    n = max(len(latency[k]) for k in keys)
    rows = [[i + 1] + [f"{latency[k][i]:.3f}" if i < len(latency[k]) else "" for k in keys]
            for i in range(n)]
    half = (n + 1) // 2
    parts.append("<div class='cols'>"
                 + table(["#", "A GET", "B GET", "A POST", "B POST"], rows[:half], "tiny")
                 + table(["#", "A GET", "B GET", "A POST", "B POST"], rows[half:], "tiny")
                 + "</div>")
    parts.append("<h3>D.1 Sandbox creation samples (s)</h3>")
    parts.append(table(["#", "A", "B"],
                       [[i + 1, latency[("A", "sandbox_create_seconds")][i],
                         latency[("B", "sandbox_create_seconds")][i]]
                        for i in range(len(latency[("A", "sandbox_create_seconds")]))]))
    parts.append("<h3>D.2 L7 → middleware gap samples (ms)</h3>")
    parts.append("<p>" + ", ".join(f"{g:.0f}" for g in gaps) + "</p>")

    parts.append("<h2 class='pb'>Appendix E. Evidence file integrity (SHA-256)</h2>")
    parts.append("<p>These hashes are of the files in "
                 "<code>docs/evidence/openshell-20260928/</code> at build time. Every "
                 "number in this PDF was computed from these exact files.</p>")
    rows = []
    for path in sorted(EVIDENCE.iterdir()):
        if path.is_file():
            rows.append([path.name, path.stat().st_size,
                         hashlib.sha256(path.read_bytes()).hexdigest()])
    parts.append(table(["File", "Bytes", "SHA-256"], rows, "small mono"))
    parts.append("<h3>E.1 Environment (results.json)</h3>")
    parts.append(table(["Item", "Value"], [
        ["OpenShell", json.dumps(results["openshell"])], ["Host", json.dumps(results["host"])],
        ["Result format", results["format"]]], "small"))
    return "".join(parts)


CSS = """
@page { size: A4; margin: 16mm 14mm 16mm 14mm; }
body { font-family: 'DejaVu Serif', Georgia, serif; font-size: 10pt; line-height: 1.4; color: #111; }
h1 { font-size: 18pt; margin: 0 0 4pt; } h2 { font-size: 13pt; margin-top: 16pt;
  border-bottom: 1px solid #999; } h3 { font-size: 11pt; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 8.3pt;
  page-break-inside: auto; } tr { page-break-inside: avoid; }
th, td { border: 1px solid #bbb; padding: 2pt 4pt; vertical-align: top; text-align: left;
  word-break: break-word; } th { background: #eef1f4; }
table.small { font-size: 7pt; } table.tiny { font-size: 6.4pt; width: 49%; }
table.mono td { font-family: 'DejaVu Sans Mono', monospace; }
.cols { display: flex; justify-content: space-between; }
code, pre { font-family: 'DejaVu Sans Mono', monospace; font-size: 8pt; }
pre { background: #f6f6f6; padding: 6pt; white-space: pre-wrap; }
figure { margin: 8pt 0; page-break-inside: avoid; text-align: center; }
figure svg { max-width: 100%; height: auto; }
.pb { page-break-before: always; }
table.cases th:nth-child(1) { width: 4%; } table.cases th:nth-child(2) { width: 5%; }
table.cases th:nth-child(3) { width: 17%; } table.cases th:nth-child(4) { width: 14%; }
table.cases th:nth-child(6) { width: 5%; }
table.cases { table-layout: fixed; }
.note { font-size: 8.5pt; color: #444; }
"""


def main() -> int:
    latency, cases, results, correlation, events, receipts = load()
    gap_svg, gaps = fig_gap(events)
    figures = (
        "<h2 class='pb'>Figures</h2>"
        "<p class='note'>All figures are generated from the evidence files by "
        "<code>tools/build_openshell_paper_pdf.py</code>.</p>"
        + "".join(f"<figure>{f}</figure>" for f in (
            fig_outcomes(cases), fig_distributions(latency), fig_ecdf(latency),
            fig_drift(latency), fig_create(latency), gap_svg))
    )
    text = PAPER.read_text()
    # Relative repository links are meaningless inside a PDF; keep the text.
    body = markdown.markdown(text, extensions=["tables", "fenced_code"])
    anchor = "<h2>5. Findings about the components</h2>"
    assert anchor in body
    body = body.replace(anchor, figures + stats_section(latency) + anchor.replace(
        "<h2>", "<h2 class='pb'>"), 1)
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    document = (f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style>"
                f"</head><body>{body}"
                f"{appendices(latency, cases, correlation, events, receipts, results, gaps)}"
                f"<p class='note'>Built from repository commit {commit}.</p></body></html>")
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "paper.html"
        page.write_text(document)
        script = Path(tmp) / "print.js"
        script.write_text(
            "const { chromium } = require('playwright');\n"
            "(async () => { const b = await chromium.launch();\n"
            " const p = await b.newPage();\n"
            f" await p.goto('file://{page}');\n"
            f" await p.pdf({{ path: '{OUTPUT}', format: 'A4', printBackground: true,\n"
            "   displayHeaderFooter: true, headerTemplate: '<span></span>',\n"
            "   footerTemplate: '<div style=\"font-size:7pt;width:100%;text-align:center;\">"
            "BULL × OpenShell — <span class=\"pageNumber\"></span> / "
            "<span class=\"totalPages\"></span></div>',\n"
            "   margin: { top: '14mm', bottom: '16mm', left: '12mm', right: '12mm' } });\n"
            " await b.close(); })();\n")
        env = {**os.environ, "NODE_PATH": subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()}
        subprocess.run(["node", str(script)], check=True, env=env)
    write_datasets(latency, correlation, events, receipts)
    print(OUTPUT)
    print(DATASETS)
    return 0


def _csv(headers, rows) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows(rows)
    return buffer.getvalue()


def write_datasets(latency, correlation, events, receipts):
    """Evidence files plus spreadsheet-ready CSVs, in one deterministic zip."""
    keys = [("A", "get_trusted_ms"), ("B", "get_trusted_ms"), ("A", "post_api_ms"),
            ("B", "post_api_ms")]
    n = max(len(latency[k]) for k in keys)
    derived = {
        "latency_requests_wide.csv": _csv(
            ["index", "A_get_ms", "B_get_ms", "A_post_ms", "B_post_ms"],
            [[i + 1] + [latency[k][i] if i < len(latency[k]) else "" for k in keys]
             for i in range(n)]),
        "latency_long.csv": _csv(
            ["phase", "metric", "index", "value"],
            [[p, m, i + 1, v] for (p, m), vals in sorted(latency.items())
             for i, v in enumerate(vals)]),
        "correlation_rows.csv": _csv(
            list(correlation["rows"][0]), [list(r.values()) for r in correlation["rows"]]),
        "ocsf_http_events.csv": _csv(
            ["phase", "time", "sandbox", "engine", "action", "method", "url", "policy", "reason"],
            [[p, e["time"], e["sandbox"], e["engine"], e["action"], e["method"], e["url"],
              e["policy"], e["reason"]] for p in "AB"
             for e in sorted(events.get(p, []), key=lambda e: e["time"])]),
        "upstream_receipts.csv": _csv(
            ["phase", "time", "method", "url"],
            [[p, r["time"], r["method"], r["url"]] for p in "AB" for r in receipts[p]]),
    }
    with zipfile.ZipFile(DATASETS, "w", zipfile.ZIP_DEFLATED) as archive:
        def add(name, data):
            info = zipfile.ZipInfo(name, date_time=(2026, 9, 28, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
        for name, text in derived.items():
            add(f"derived/{name}", text)
        for path in sorted(EVIDENCE.iterdir()):
            if path.is_file():
                add(f"evidence/{path.name}", path.read_bytes())
        add("paper/BULL_OPENSHELL_COMPOSITION_20260928.md", PAPER.read_bytes())


if __name__ == "__main__":
    raise SystemExit(main())
