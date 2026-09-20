from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "deploy" / "cloudflare-audit"

def test_cloudflare_anchor_files_and_route_contract():
    worker = (BASE / "src" / "index.ts").read_text(encoding="utf-8")
    schema = (BASE / "schema.sql").read_text(encoding="utf-8")
    config = (BASE / "wrangler.jsonc").read_text(encoding="utf-8")
    readme = (BASE / "README.md").read_text(encoding="utf-8")

    assert 'url.pathname !== "/v1/checkpoints"' in worker
    assert '"checkpoint"' in worker
    assert '"acknowledgement"' in worker
    assert "ON CONFLICT(session, sequence) DO NOTHING" in worker
    assert "PRIMARY KEY(session, sequence)" in schema
    assert '"binding": "DB"' in config
    assert "BULL_ANCHOR_MASTER_KEY" in readme
    assert "bull-production-provision.sh" in readme
    assert "localhost" in readme
