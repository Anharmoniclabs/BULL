from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]

def test_benchmark_publication_contract():
    page = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    data = json.loads((ROOT / "site" / "data" / "benchmarks" / "20260920" / "benchmark.json").read_text(encoding="utf-8"))
    assert 'id="benchmarks"' in page
    assert "33 / 33" in page
    assert data["selected_redteam"] == data["selected_redteam"] | {"runs": 33, "passes": 33, "failures": 0}
    assert data["full_regression_suite"]["status"] == "PASS"
    assert (ROOT / "site" / "assets" / "benchmarks" / "attack-pass-rate.svg").is_file()
    assert (ROOT / "docs" / "BENCHMARK_20260920.md").is_file()
    assert (ROOT / "docs" / "PRODUCTION_EXTERNAL_AUDIT_EVIDENCE_20260920.md").is_file()
