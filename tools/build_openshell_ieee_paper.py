#!/usr/bin/env python3
"""Build the IEEEtran BULL x OpenShell paper from the recorded evidence.

Every number, table and figure the manuscript uses is generated here from
docs/evidence/openshell-20260928/ into docs/papers/openshell-ieee/generated/
and .../figs/, then docs/papers/openshell-ieee/main.tex is compiled with
pdflatex. The manuscript text references values only through the generated
macros (generated/numbers.tex), so the prose cannot drift from the data.

    python tools/build_openshell_ieee_paper.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import zipfile

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from build_openshell_paper_pdf import (  # noqa: E402
    EVIDENCE, bootstrap_median_diff, load, mann_whitney, pct)

PAPER_DIR = ROOT / "docs/papers/openshell-ieee"
GEN = PAPER_DIR / "generated"
FIGS = PAPER_DIR / "figs"
OUTPUT = ROOT / "docs/papers/BULL_OPENSHELL_IEEE_20260928.pdf"
SOURCE_ZIP = ROOT / "docs/papers/BULL_OPENSHELL_IEEE_20260928_latex.zip"
COLORS = {"A": "#5b7083", "B": "#c0392b"}

plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.titlesize": 8,
                     "axes.labelsize": 8, "legend.fontsize": 6.5, "xtick.labelsize": 7,
                     "ytick.labelsize": 7, "pdf.fonttype": 42})


# ---------------------------------------------------------------- helpers

_TEX = {"\\": r"\textbackslash{}", "{": r"\{", "}": r"\}", "_": r"\_", "%": r"\%",
        "&": r"\&", "#": r"\#", "$": r"\$", "^": r"\^{}", "~": r"\~{}",
        "<": r"\textless{}", ">": r"\textgreater{}", "|": r"\textbar{}"}


def tex(value) -> str:
    text = str(value).replace("\u2713", "ok").replace("\u00d7", "x").replace("\u2502", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return "".join(_TEX.get(ch, ch) for ch in text)


def brk(value) -> str:
    """Escape and allow line breaks inside long tokens (URLs, JSON, hashes)."""
    out = []
    for ch in tex(value):
        out.append(ch)
        if ch in ",/:=." or ch == "-":
            out.append(r"\allowbreak{}")
    text = "".join(out).replace(r"\_", r"\_\allowbreak{}")
    return text


def macro(name: str, value) -> str:
    assert re.fullmatch(r"[A-Za-z]+", name), name
    return f"\\newcommand{{\\{name}}}{{{value}}}\n"


def f2(v):
    return f"{v:.2f}"


def reached(observed: str):
    code = re.search(r"http (\d*)", observed)
    hit = re.search(r"reached=(True|False)", observed)
    return (code.group(1) if code else ""), (hit.group(1) == "True" if hit else None)


def effect_text(observed: str) -> str:
    code, hit = reached(observed)
    parts = []
    if code:
        parts.append(f"HTTP {code}")
    if hit is not None:
        parts.append("effect reached upstream" if hit else "no effect")
    return "; ".join(parts)


# ---------------------------------------------------------------- figures

def save(fig, name):
    fig.savefig(FIGS / name, bbox_inches="tight")
    plt.close(fig)


def figures(latency, cases, events):
    # Outcome matrix (figure*)
    order = ["C1", "C2", "C3", "C3b", "C4", "C5", "C5b", "C6", "C7", "C8", "C9", "C10"]
    rows = {(c["phase"][0], c["case"]): c for c in cases}
    fig, ax = plt.subplots(figsize=(7.0, 1.35))
    for x, case in enumerate(order):
        for y, phase in enumerate("AB"):
            row = rows.get((phase, case))
            if row is None:
                color, label = "#eeeeee", "n/a"
            else:
                _, hit = reached(row["observed"])
                leaked = phase == "A" and (
                    (case in ("C2", "C4", "C7", "C3b") and
                     ("reached=True" in row["observed"]))
                    or (case == "C5" and "loaded" in row["observed"]))
                if leaked:
                    color, label = "#f5b7b1", "effect\nhappened"
                elif row["pass"] == "True":
                    color, label = "#abebc6", "held" if phase == "B" else "as expected"
                else:
                    color, label = "#e74c3c", "FAIL"
            ax.add_patch(plt.Rectangle((x, 1 - y), 1, 1, color=color, ec="white", lw=1.2))
            ax.text(x + 0.5, 1.5 - y, label, ha="center", va="center", fontsize=5.8)
    ax.set_xlim(0, len(order))
    ax.set_ylim(0, 2)
    ax.set_xticks([i + 0.5 for i in range(len(order))], order)
    ax.set_yticks([1.5, 0.5], ["A: OpenShell", "B: +BULL"])
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    save(fig, "outcomes.pdf")

    # Distributions (column)
    fig, axes = plt.subplots(1, 2, figsize=(3.45, 2.0), sharey=True)
    for ax, metric, title in ((axes[0], "get_trusted_ms", "GET (trusted)"),
                              (axes[1], "post_api_ms", "POST (allowed)")):
        data = [latency[("A", metric)], latency[("B", metric)]]
        parts = ax.violinplot(data, showextrema=False, widths=0.8)
        for body, phase in zip(parts["bodies"], "AB"):
            body.set_facecolor(COLORS[phase])
            body.set_alpha(0.35)
        ax.boxplot(data, widths=0.2, medianprops={"color": "black"},
                   flierprops={"markersize": 1.5})
        ax.set_xticks([1, 2], ["A", "B"])
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("latency (ms)")
    save(fig, "distributions.pdf")

    # ECDF (column)
    fig, axes = plt.subplots(1, 2, figsize=(3.45, 1.9), sharey=True)
    for ax, metric, title in ((axes[0], "get_trusted_ms", "GET"),
                              (axes[1], "post_api_ms", "POST")):
        for phase in "AB":
            v = sorted(latency[(phase, metric)])
            ax.step(v, [(i + 1) / len(v) for i in range(len(v))], where="post",
                    color=COLORS[phase], lw=1, label={"A": "A", "B": "B"}[phase])
        ax.set_title(title)
        ax.set_xlabel("latency (ms)")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("cumulative fraction")
    axes[0].legend(loc="lower right")
    save(fig, "ecdf.pdf")

    # Drift (figure*)
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.0), sharey=True)
    for ax, metric, title in ((axes[0], "get_trusted_ms", "GET"),
                              (axes[1], "post_api_ms", "POST")):
        for phase in "AB":
            v = latency[(phase, metric)]
            ax.scatter(range(1, len(v) + 1), v, s=2, alpha=0.35, color=COLORS[phase])
            rolling = [statistics.median(v[max(0, i - 24):i + 1]) for i in range(len(v))]
            ax.plot(range(1, len(v) + 1), rolling, color=COLORS[phase], lw=1.2,
                    label=f"{phase}: rolling median (w=25)")
        ax.set_title(title)
        ax.set_xlabel("request index within run")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("latency (ms)")
    axes[0].legend(loc="upper left")
    save(fig, "drift.pdf")

    # Creation + L7->middleware gap (column)
    gaps = []
    ev = events.get("B", [])
    for i, e in enumerate(ev):
        if e["engine"] == "l7" and e["action"] == "ALLOWED":
            nxt = [m for m in ev[i + 1:i + 3]
                   if m["engine"] == "middleware" and m["url"] == e["url"]]
            if nxt:
                gaps.append(round((nxt[0]["time"] - e["time"]) * 1000))
    fig, axes = plt.subplots(1, 2, figsize=(3.45, 1.7))
    for row, phase in enumerate("AB"):
        v = latency[(phase, "sandbox_create_seconds")]
        axes[0].scatter(v, [row] * len(v), color=COLORS[phase], s=10, zorder=3)
        axes[0].vlines(statistics.median(v), row - 0.3, row + 0.3, color="black", lw=1)
    axes[0].set_yticks([0, 1], ["A", "B"])
    axes[0].set_ylim(-0.7, 1.7)
    axes[0].set_xlabel("create --detach (s)")
    axes[0].grid(axis="x", alpha=0.3)
    axes[1].hist(gaps, bins=range(0, 10), color=COLORS["B"], alpha=0.7, edgecolor="white")
    axes[1].set_xlabel("L7 event to BULL verdict (ms)")
    axes[1].set_ylabel("requests")
    fig.subplots_adjust(wspace=0.55)
    save(fig, "create_gap.pdf")
    return gaps


# ------------------------------------------------------------------ tables

CASE_TEXT = {
    "C1": "BULL ALLOW $\\wedge$ OpenShell ALLOW executes",
    "C2": "BULL DENY $\\wedge$ OpenShell ALLOW is blocked",
    "C3": "BULL ALLOW $\\wedge$ OpenShell DENY is blocked",
    "C3b": "L7 rules left at default (audit) enforcement",
    "C4": "ESCALATE: no effect before approval, one after",
    "C5": "Unauthorized policy widening rejected",
    "C5b": "Host outside signed ceiling rejected",
    "C6": "Provider credential never readable",
    "C7": "Internet-derived content $\\rightarrow$ POST",
    "C8": "Native bypass contained",
    "C9": "BULL unavailable $\\Rightarrow$ fail closed",
    "C10": "One correlatable audit trail",
}


def outcome(case, phase, row, results):
    obs = row["observed"]
    evidence = next((r["evidence"] for r in results["results"]
                     if r["phase"][0] == phase and r["case"] == case), {})
    if case in ("C1", "C2", "C3", "C7") or (case == "C4" and phase == "A"):
        text = effect_text(obs)
        if case == "C7" and phase == "A":
            text = "effect reached upstream" if "reached=True" in obs else "no effect"
        return text
    if case == "C3b":
        if phase == "A":
            hit = "reached=True" in obs
            return "created; out-of-rule POST " + ("reached upstream" if hit else "blocked")
        return "creation refused (enforcement not enforce)" if "created=False" in obs else obs
    if case == "C4":
        e = evidence
        return (f"HTTP {e['first_http']} $\\rightarrow$ approve $\\rightarrow$ "
                f"{e['retry_http']} $\\rightarrow$ reuse {e['third_http']}; "
                f"upstream count {e['upstream_count']}")
    if case == "C5":
        if phase == "A":
            m = re.search(r"version (\d+) loaded", obs)
            return f"applied (policy v{m.group(1)} loaded)" if m else tex(obs[:60])
        m = re.search(r"with \[([^\]]*)\]", obs)
        return "refused: approval required for " + tex(m.group(1)) if m else tex(obs[:60])
    if case == "C5b":
        return "refused: outside signed ceiling" if "ceiling" in obs else tex(obs[:60])
    if case == "C6":
        visible = "secret_visible=True" in obs
        if phase == "A":
            return "canary " + ("VISIBLE" if visible else "not in sandbox env") + \
                   ("; attach pending supervisor" if "waiting_for_supervisor" in obs else "")
        return ("attach refused; canary " + ("VISIBLE" if visible else "not in env")
                if "permission" in obs else tex(obs[:60]))
    if case == "C8":
        e = evidence
        direct = e.get("/v1/x", {})
        mediated = "+".join(direct.get("ocsf_engines", [])) or "none"
        return (r"\texttt{-{}-noproxy} POST " + ("reached" if direct.get("reached_upstream") else "blocked")
                + f" (OCSF: {mediated}); other binary, raw socket, UDP DNS failed")
    if case == "C9":
        m = re.search(r"post http (\d+) reached=(\w+); create_while_down=(\w+); "
                      r"after_restart_docs_http=(\d*)", obs)
        return (f"POST HTTP {m.group(1)}, no effect; create refused; after restart GET "
                f"{m.group(4)}") if m else tex(obs[:60])
    if case == "C10":
        data = json.loads(obs)
        if phase == "A":
            return f"{data['ocsf_http_events']['l7']} OCSF L7 events; no authority record"
        return (f"{data['consistent']}/{data['bull_decisions']} decisions consistent; "
                f"{data['effects_without_bull_allow']} effects w/o allow; ledger "
                + ("valid" if data["ledger_valid"] else "INVALID"))
    return tex(obs[:60])


def case_table(cases, results):
    rows = {(c["phase"][0], c["case"]): c for c in cases}
    lines = []
    for case in CASE_TEXT:
        a, b = rows.get(("A", case)), rows.get(("B", case))
        a_text = outcome(case, "A", a, results) if a else "---"
        b_text = outcome(case, "B", b, results) if b else "---"
        verdict = r"\textbf{held}" if b and b["pass"] == "True" else r"\textbf{FAILED}"
        lines.append(f"{case} & {CASE_TEXT[case]} & {a_text} & {b_text} & {verdict} \\\\")
    (GEN / "cases.tex").write_text("\n".join(lines) + "\n")


def latency_tables(latency):
    lines = []
    for metric, label in (("get_trusted_ms", "GET"), ("post_api_ms", "POST")):
        for phase in "AB":
            v = latency[(phase, metric)]
            lines.append(f"{label} & {phase} & {len(v)} & {statistics.mean(v):.2f} & "
                         f"{statistics.median(v):.2f} & {pct(v, .95):.2f} & "
                         f"{pct(v, .99):.2f} & {min(v):.2f} & {max(v):.2f} & "
                         f"{statistics.pstdev(v):.2f} \\\\")
    for phase in "AB":
        v = [x * 1000 for x in latency[(phase, "sandbox_create_seconds")]]
        lines.append(f"Create & {phase} & {len(v)} & {statistics.mean(v):.0f} & "
                     f"{statistics.median(v):.0f} & {pct(v, .95):.0f} & {pct(v, .99):.0f} & "
                     f"{min(v):.0f} & {max(v):.0f} & {statistics.pstdev(v):.0f} \\\\")
    (GEN / "latency.tex").write_text("\n".join(lines) + "\n")

    lines = []
    for metric, label in (("get_trusted_ms", "GET"), ("post_api_ms", "POST")):
        a, b = latency[("A", metric)], latency[("B", metric)]
        lo, hi = bootstrap_median_diff(a, b)
        u, z, p, r = mann_whitney(a, b)
        p_text = r"$<10^{-15}$" if p < 1e-15 else f"{p:.1e}"
        lines.append(f"{label} & {statistics.median(b) - statistics.median(a):+.2f} & "
                     f"[{lo:+.2f}, {hi:+.2f}] & {u:.0f} & {z:.2f} & {p_text} & {r:.3f} \\\\")
    (GEN / "stats.tex").write_text("\n".join(lines) + "\n")

    lines = []
    for metric, label in (("get_trusted_ms", "GET"), ("post_api_ms", "POST")):
        for phase in "AB":
            v = latency[(phase, metric)]
            first, last = statistics.median(v[:50]), statistics.median(v[-50:])
            lines.append(f"{label} & {phase} & {first:.2f} & {last:.2f} & {last - first:+.2f} \\\\")
    (GEN / "drift.tex").write_text("\n".join(lines) + "\n")


def correlation_table(correlation):
    lines = []
    for i, r in enumerate(correlation["rows"], 1):
        path = r["resource"].split("://", 1)[-1].split("/", 1)[-1]
        port = r["resource"].rsplit(":", 1)[-1].split("/", 1)[0]
        lines.append(
            f"{i} & {tex(r['sandbox'])} & {r['method']} & {tex(':' + port + '/' + path)} & "
            f"{tex(r['bull_decision'])}{'' if not r['approval_id'] else '*'} & "
            f"{tex(r['openshell_l7'])} & {tex(r['openshell_middleware'])} & "
            f"{'yes' if r['effect_observed'] else 'no'} & "
            f"{'yes' if r['consistent'] else 'NO'} \\\\")
    (GEN / "correlation.tex").write_text("\n".join(lines) + "\n")


def appendix_tables(cases, correlation, events, receipts, latency, gaps):
    # Complete case table
    lines = []
    for c in cases:
        lines.append(f"{c['phase'][0]} & {tex(c['case'])} & {brk(c['name'])} & "
                     f"{brk(c['expected'])} & \\texttt{{\\scriptsize {brk(c['observed'])}}} & "
                     f"{'yes' if c['pass'] == 'True' else 'NO'} \\\\ \\hline")
    (GEN / "app_cases.tex").write_text("\n".join(lines) + "\n")

    # Correlation full
    lines = []
    for i, r in enumerate(correlation["rows"], 1):
        lines.append(
            f"{i} & {tex(r['sandbox'])} & {r['method']} & "
            f"\\texttt{{{brk(r['resource'].split('://', 1)[-1])}}} & "
            f"{tex(','.join(r['provenance'] or []))} & {tex(r['bull_decision'])} & "
            f"{brk(r['bull_reason_code'])} & \\texttt{{{tex(r['approval_id'] or '')}}} & "
            f"{tex(r['openshell_l7'])} & {tex(r['openshell_middleware'])} & "
            f"{'yes' if r['effect_observed'] else 'no'} & "
            f"\\texttt{{{tex((r['ledger_hash'] or '')[:12])}}} \\\\")
    (GEN / "app_correlation.tex").write_text("\n".join(lines) + "\n")

    # OCSF events
    for phase in "AB":
        lines = []
        for e in sorted(events.get(phase, []), key=lambda e: e["time"]):
            lines.append(f"{e['time']:.3f} & {tex(e['sandbox'])} & {tex(e['engine'])} & "
                         f"{tex(e['action'])} & {e['method']} & "
                         f"\\texttt{{{brk(e['url'].split('://', 1)[-1])}}} & "
                         f"\\texttt{{{brk(e['reason'])}}} \\\\")
        (GEN / f"app_ocsf_{phase}.tex").write_text("\n".join(lines) + "\n")
        lines = [f"{r['time']:.3f} & {r['method']} & \\texttt{{{brk(r['url'])}}} \\\\"
                 for r in receipts[phase]]
        (GEN / f"app_receipts_{phase}.tex").write_text("\n".join(lines) + "\n")

    # Raw latency, two blocks of 100 rows side by side
    keys = [("A", "get_trusted_ms"), ("B", "get_trusted_ms"), ("A", "post_api_ms"),
            ("B", "post_api_ms")]
    n = len(latency[keys[0]])
    half = n // 2
    lines = []
    for i in range(half):
        left = " & ".join(f"{latency[k][i]:.3f}" for k in keys)
        right = " & ".join(f"{latency[k][i + half]:.3f}" for k in keys)
        lines.append(f"{i + 1} & {left} & {i + half + 1} & {right} \\\\")
    (GEN / "app_raw.tex").write_text("\n".join(lines) + "\n")
    a = latency[("A", "sandbox_create_seconds")]
    b = latency[("B", "sandbox_create_seconds")]
    (GEN / "app_create.tex").write_text("\n".join(
        f"{i + 1} & {a[i]:.3f} & {b[i]:.3f} \\\\" for i in range(len(a))) + "\n")
    (GEN / "app_gaps.tex").write_text(", ".join(str(g) for g in gaps) + "\n")

    # Hashes
    lines = []
    for path in sorted(EVIDENCE.iterdir()):
        if path.is_file():
            lines.append(f"\\texttt{{{tex(path.name)}}} & {path.stat().st_size} & "
                         f"\\texttt{{\\scriptsize {hashlib.sha256(path.read_bytes()).hexdigest()}}} \\\\")
    (GEN / "app_hashes.tex").write_text("\n".join(lines) + "\n")


def numbers(latency, results, correlation, events, receipts, gaps, cases):
    out = []
    for metric, key in (("get_trusted_ms", "Get"), ("post_api_ms", "Post")):
        a, b = latency[("A", metric)], latency[("B", metric)]
        lo, hi = bootstrap_median_diff(a, b)
        out += [macro(f"med{key}A", f2(statistics.median(a))),
                macro(f"med{key}B", f2(statistics.median(b))),
                macro(f"delta{key}", f2(statistics.median(b) - statistics.median(a))),
                macro(f"ciLo{key}", f2(lo)), macro(f"ciHi{key}", f2(hi)),
                macro(f"pNine{key}A", f2(pct(a, .95))), macro(f"pNine{key}B", f2(pct(b, .95))),
                macro(f"nLat{key}", len(a)),
                macro(f"driftFirst{key}B", f2(statistics.median(b[:50]))),
                macro(f"driftLast{key}B", f2(statistics.median(b[-50:]))),
                macro(f"driftFirst{key}A", f2(statistics.median(a[:50]))),
                macro(f"driftLast{key}A", f2(statistics.median(a[-50:])))]
    ca = latency[("A", "sandbox_create_seconds")]
    cb = latency[("B", "sandbox_create_seconds")]
    out += [macro("createMeanA", f"{statistics.mean(ca) * 1000:.0f}"),
            macro("createMeanB", f"{statistics.mean(cb) * 1000:.0f}"),
            macro("createDelta", f"{(statistics.mean(cb) - statistics.mean(ca)) * 1000:.0f}"),
            macro("createN", len(ca)),
            macro("gapMedian", f"{statistics.median(gaps):.0f}"),
            macro("gapMin", min(gaps)), macro("gapMax", max(gaps)), macro("gapN", len(gaps))]
    s = correlation["summary"]
    c10 = next(r for r in results["results"] if r["phase"][0] == "B" and r["case"] == "C10")
    c10obs = json.loads(c10["observed"])
    out += [macro("corrDecisions", s["bull_decisions"]),
            macro("corrMatched", s["matched_openshell_event"]),
            macro("corrConsistent", s["consistent"]),
            macro("corrUnexplained", s["effects_without_bull_allow"]),
            macro("corrOrphans", s["openshell_events_without_bull_decision"]),
            macro("ledgerRecordsCTen", c10obs["ledger_records"]),
            macro("ledgerRecordsTotal",
                  sum(1 for _ in open(EVIDENCE / "bull-audit.jsonl"))),
            macro("ocsfEventsB", len(events.get("B", []))),
            macro("ocsfEventsA", len(events.get("A", []))),
            macro("receiptsA", len(receipts["A"])), macro("receiptsB", len(receipts["B"]))]
    passed = {p: sum(1 for c in cases if c["phase"][0] == p and c["pass"] == "True") for p in "AB"}
    total = {p: sum(1 for c in cases if c["phase"][0] == p) for p in "AB"}
    out += [macro("passA", passed["A"]), macro("totalA", total["A"]),
            macro("passB", passed["B"]), macro("totalB", total["B"]),
            macro("passAll", passed["A"] + passed["B"]),
            macro("totalAll", total["A"] + total["B"])]
    out += [macro("osVersion", "v" + tex(results["openshell"]["cli_version"].split()[-1])),
            macro("hostKernel", tex(results["host"]["kernel"])),
            macro("dockerVersion", tex(results["host"]["docker"]))]
    (GEN / "numbers.tex").write_text("".join(out))


CLOSED = ['cases', 'correlation', 'latency', 'stats', 'drift', 'app_correlation', 'app_ocsf_A', 'app_ocsf_B', 'app_receipts_A', 'app_receipts_B', 'app_raw', 'app_create', 'app_hashes']


def close_tables():
    """\\input inside a tabular breaks a following \\bottomrule, so the
    generated bodies carry their own closing rule."""
    for name in CLOSED:
        path = GEN / f"{name}.tex"
        path.write_text(path.read_text() + "\\bottomrule\n")


def main() -> int:
    for folder in (GEN, FIGS):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
    latency, cases, results, correlation, events, receipts = load()
    gaps = figures(latency, cases, events)
    case_table(cases, results)
    latency_tables(latency)
    correlation_table(correlation)
    appendix_tables(cases, correlation, events, receipts, latency, gaps)
    numbers(latency, results, correlation, events, receipts, gaps, cases)
    close_tables()
    for _ in range(2):
        done = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error",
                               "main.tex"], cwd=PAPER_DIR, capture_output=True, text=True)
        if done.returncode != 0:
            print(done.stdout[-4000:])
            return 1
    shutil.copy2(PAPER_DIR / "main.pdf", OUTPUT)
    with zipfile.ZipFile(SOURCE_ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted([PAPER_DIR / "main.tex", *GEN.iterdir(), *FIGS.iterdir()]):
            info = zipfile.ZipInfo(str(path.relative_to(PAPER_DIR)),
                                   date_time=(2026, 9, 28, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    warnings = [line for line in done.stdout.splitlines()
                if "Overfull" in line or "undefined" in line.lower()]
    print(OUTPUT)
    print(f"{len(warnings)} overfull/undefined warnings")
    for line in warnings[:15]:
        print("  ", line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
