#!/usr/bin/env python3
"""Build the paper from reviewed inputs, or verify its checked-in publication."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
RUNTIME = "ab53f563bcbcaf60820acb318b8212796ce502ff"
EPOCH = "1790164800"  # Fixed publication epoch; not an experiment timestamp.


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sources() -> dict[str, bytes]:
    allowed = {".cls", ".tex", ".py", ".json", ".csv", ".md", ".svg", ".txt"}
    return {
        str(p.relative_to(HERE)): p.read_bytes()
        for p in sorted(HERE.rglob("*"))
        if p.is_file() and not p.is_symlink()
        and "__pycache__" not in p.parts
        and p.relative_to(HERE).parts[0] != "generated"
        and (p.suffix in allowed or p.name == "LICENSE")
    }


def validate_inputs() -> dict:
    manifest = json.loads((HERE / "evidence-manifest.json").read_text())
    if manifest["runtime_commit"] != RUNTIME:
        raise ValueError("Unexpected runtime identity")
    for name, record in manifest["inputs"].items():
        path = (HERE / name).resolve()
        if not path.is_relative_to(HERE) or digest(path.read_bytes()) != record["sha256"]:
            raise ValueError("Evidence hash mismatch: " + name)
    report = json.loads((HERE / "evidence/validation-ab53f56.json").read_text())
    if report["commit"] != RUNTIME or report["source_dirty"]:
        raise ValueError("Latest evidence does not describe the pinned clean source")
    if report["regression"] != {"passed": 501, "subtests_passed": 21, "failures": 0, "skipped": 0}:
        raise ValueError("Paper counts differ from retained validation")
    if len(report["kvm_cases"]) != 5 or set(report["kvm_cases"].values()) != {"PASS"}:
        raise ValueError("KVM evidence differs from the manuscript")
    if report["deployment_gates"]["hardware_approval_protocol"] != "BLOCKED":
        raise ValueError("Physical-signing scope changed; review the manuscript")
    return report


def latex(text: str) -> str:
    replacements = {"&": r"\&", "%": r"\%", "_": r"\_", "#": r"\#", "→": r"$\to$"}
    return "".join(replacements.get(c, c) for c in text)


def tables(work: Path, report: dict) -> None:
    with (HERE / "evidence/site/data/benchmarks/20260920/attack-summary.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    if sum(int(r["passed"]) for r in rows) != 33 or any(int(r["failed"]) for r in rows):
        raise ValueError("Historical benchmark changed")
    lines = [r"\begin{table*}[!t]\centering\small", r"\begin{tabularx}{\linewidth}{@{}Yrrrr@{}}",
             r"\toprule Selected scenario & Runs & Mean ms & Min--max ms & RSS MiB \\", r"\midrule"]
    for r in rows:
        lines.append(latex(r["attack"]) + " & " + r["runs"] + " & " + r["mean_ms"] + " & "
                     + r["min_ms"] + "--" + r["max_ms"] + " & " + r["peak_rss_mb"] + r" \\")
    lines.extend([r"\bottomrule\end{tabularx}",
                  r"\caption{Historical selected defensive corpus at cd461ae. All 33 runs passed. End-to-end pytest durations, not isolated policy latency; RSS is the recorded peak.}\end{table*}"])
    (work / "benchmark-table.tex").write_text("\n".join(lines) + "\n")
    lines = [r"\begin{table*}[!t]\small", r"\begin{tabularx}{\linewidth}{@{}p{0.2\linewidth}Y@{}}",
             r"\toprule Artifact & SHA-256 \\", r"\midrule"]
    assets = dict(report["guest_assets_sha256"])
    assets["Source materials"] = report["guest_source_bundle"]["sha256"]
    for name, sha in assets.items():
        lines.append(latex(name) + r" & \nolinkurl{" + sha + r"} \\")
    lines.extend([r"\bottomrule\end{tabularx}",
                  r"\caption{Pinned assets in the latest runtime qualification. Full package digests and guest runtime-tree identity are in validation-ab53f56.json.}\label{tab:hashes}\end{table*}"])
    (work / "hashes-table.tex").write_text("\n".join(lines) + "\n")


def figures(work: Path, report: dict) -> None:
    import cairosvg
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    dest = work / "figures"
    dest.mkdir()
    for path in sorted((HERE / "figures").glob("*.svg")):
        cairosvg.svg2pdf(url=str(path), write_to=str(dest / (path.stem + ".pdf")))
    old = json.loads((HERE / "evidence/site/data/validation/603365e.json").read_text())
    qwen = json.loads((HERE / "evidence/docs/evidence/governed-agent-20260922/summary.json").read_text())
    earlier = json.loads((HERE / "evidence/docs/evidence/candidate-428db9c.json").read_text())
    # All numbers come from their own retained source records.
    values = [qwen["regression"], earlier["regression"], old["regression"], report["regression"]]
    labels = ["Qwen source manifest", "428db9c", "603365e", "ab53f56"]
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "pdf.fonttype": 42})
    fig, ax = plt.subplots(figsize=(7.2, 2.7), layout="constrained")
    counts = [v["passed"] for v in values]
    ax.barh(labels, counts, color=["#aac7c2", "#79a69c", "#477f74", "#175647"], height=0.57)
    ax.invert_yaxis()
    for i, v in enumerate(values):
        ax.text(v["passed"] + 7, i, f'{v["passed"]} + {v["subtests_passed"]} subtests', va="center", fontsize=9)
    ax.set_xlim(0, 680)
    ax.set_xlabel("Passing tests (distinct suites; not cumulative)")
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="y", length=0)
    fig.savefig(dest / "regression-milestones.pdf", metadata={"CreationDate": None, "ModDate": None})
    plt.close(fig)


def verify_publication(path: Path) -> None:
    validate_inputs()
    manifest = json.loads((path / "bull-ii-manifest.json").read_text())
    if manifest["validated_runtime_commit"] != RUNTIME:
        raise ValueError("Published runtime identity differs")
    src = sources()
    if {name: digest(data) for name, data in src.items()} != manifest["source_files_sha256"]:
        raise ValueError("Paper source changed; rebuild PDF and companion")
    for name, sha in manifest["artifacts_sha256"].items():
        if Path(name).name != name or digest((path / name).read_bytes()) != sha:
            raise ValueError("Published artifact hash mismatch: " + name)
    with zipfile.ZipFile(path / "bull-ii-companion.zip") as archive:
        for name, data in src.items():
            if archive.read("bull-ii/" + name) != data:
                raise ValueError("Companion source mismatch: " + name)
        checksums = archive.read("bull-ii/SHA256SUMS").decode().splitlines()
        expected_members = {"bull-ii/SHA256SUMS"}
        for line in checksums:
            sha, name = line.split("  ", 1)
            expected_members.add("bull-ii/" + name)
            if digest(archive.read("bull-ii/" + name)) != sha:
                raise ValueError("Companion checksum mismatch: " + name)
        if set(archive.namelist()) != expected_members:
            raise ValueError("Unexpected or unlisted companion files")
    print("Paper inputs, source, PDF and companion checksums: PASS")


def build(output: Path, engine: str) -> None:
    report = validate_inputs()
    executable = shutil.which(engine)
    if executable is None:
        raise SystemExit("Install pdfLaTeX (TeX Live) or supply --latex /path/to/pdflatex")
    output.mkdir(parents=True, exist_ok=False)
    src = sources()
    with tempfile.TemporaryDirectory(prefix="bull-paper-") as temp:
        work = Path(temp)
        shutil.copyfile(HERE / "paper.tex", work / "paper.tex")
        shutil.copyfile(HERE / "IEEEtran.cls", work / "IEEEtran.cls")
        figures(work, report)
        from plot_evidence import extra_figures
        extra_figures(HERE, work / "figures")
        tables(work, report)
        env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH, FORCE_SOURCE_DATE="1", TZ="UTC",
                   PATH=str(Path(executable).parent) + os.pathsep + os.environ.get("PATH", ""))
        for _ in range(3):
            result = subprocess.run([executable, "-no-shell-escape", "-halt-on-error", "-interaction=nonstopmode", "paper.tex"],
                                    cwd=work, env=env, capture_output=True, text=True)
            if result.returncode:
                (output / "latex-failure.log").write_text(result.stdout + result.stderr)
                raise SystemExit("LaTeX failed; see " + str(output / "latex-failure.log"))
        log = (work / "paper.log").read_text(errors="replace")
        if "undefined" in log.lower() or "Overfull \\hbox" in log or "Overfull \\vbox" in log:
            (output / "latex-review.log").write_text(log)
            raise SystemExit("Review unresolved references or layout overflow in " + str(output / "latex-review.log"))
        shutil.copyfile(work / "paper.pdf", output / "bull-ii.pdf")
        from pypdf import PdfReader
        pdf = PdfReader(output / "bull-ii.pdf")
        text = "\n".join(page.extract_text() for page in pdf.pages)
        for required in ["501", "707.483", "BLOCKED", "ab53f56", "three-click", "Zenodo"]:
            if required not in text:
                raise ValueError("Required paper text absent: " + required)
        bundle = dict(src)
        bundle["bull-ii.pdf"] = (output / "bull-ii.pdf").read_bytes()
        for name in ["benchmark-table.tex", "hashes-table.tex"]:
            bundle["generated/" + name] = (work / name).read_bytes()
        for p in sorted((work / "figures").glob("*.pdf")):
            bundle["generated/figures/" + p.name] = p.read_bytes()
        checksums = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(bundle.items()))
        bundle["SHA256SUMS"] = checksums.encode()
        with zipfile.ZipFile(output / "bull-ii-companion.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(bundle.items()):
                info = zipfile.ZipInfo("bull-ii/" + name, date_time=(2026, 9, 23, 12, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
        manifest = {
            "title": "BULL II: Binding Authority to Execution", "author": "Luis Minier / Anharmoniclabs",
            "edition": "Revised evidence edition, revision 4", "date": "2026-09-23", "pages": len(pdf.pages),
            "review_status": "Author-operated technical report; not peer reviewed or independently audited",
            "validated_runtime_commit": RUNTIME,
            "publication_scope": "Documentation revision; retained live results apply to the stated runtime and historical source identities",
            "zenodo_status": "Prepared for resubmission; author reports previous deposit removed; new DOI pending",
            "source_files_sha256": {name: digest(data) for name, data in src.items()},
            "artifacts_sha256": {name: digest((output / name).read_bytes()) for name in ["bull-ii.pdf", "bull-ii-companion.zip"]},
            "build": {"engine": subprocess.check_output([executable, "--version"], text=True).splitlines()[0],
                      "source_date_epoch": EPOCH, "python_dependencies": "requirements.txt", "shell_escape": False},
        }
        (output / "bull-ii-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    verify_publication(output)
    print(json.dumps({"pages": manifest["pages"], "output": str(output)}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="new directory outside the source tree")
    mode.add_argument("--verify-publication", type=Path, help="directory containing the three published artifacts")
    mode.add_argument("--check-inputs", action="store_true")
    parser.add_argument("--latex", default="pdflatex")
    args = parser.parse_args()
    if args.verify_publication:
        verify_publication(args.verify_publication)
    elif args.check_inputs:
        validate_inputs()
        print("Pinned paper evidence: PASS")
    else:
        if args.output.resolve().is_relative_to(HERE):
            parser.error("Build outside the paper source directory")
        build(args.output.resolve(), args.latex)


if __name__ == "__main__":
    main()
