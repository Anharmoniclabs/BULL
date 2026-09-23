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


def test_build_config_uses_explicit_existing_database_without_changing_template(tmp_path):
    import importlib.util
    import json
    spec = importlib.util.spec_from_file_location("audit_prepare_build", BASE / "prepare_build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = (BASE / "wrangler.jsonc").read_bytes()
    (tmp_path / "wrangler.jsonc").write_bytes(original)
    database = "12345678-1234-4234-8234-123456789abc"
    result = module.prepare(database, tmp_path)
    config = json.loads(result.read_text())
    assert config["name"] == "bull-audit"
    assert config["main"] == "src/index.ts"
    assert config["d1_databases"][0]["database_id"] == database
    assert (tmp_path / "wrangler.jsonc").read_bytes() == original
    assert result.stat().st_mode & 0o077 == 0
    assert module.prepare(database, tmp_path) == result
    import pytest
    with pytest.raises(ValueError, match="differs"):
        module.prepare("22345678-1234-4234-8234-123456789abc", tmp_path)
    assert json.loads(result.read_text())["d1_databases"][0]["database_id"] == database


def test_build_config_refuses_missing_or_placeholder_database(tmp_path):
    import importlib.util
    import pytest
    spec = importlib.util.spec_from_file_location("audit_prepare_build", BASE / "prepare_build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for value in (None, "", "REPLACE_WITH_D1_DATABASE_ID", "00000000-0000-0000-0000-000000000000"):
        with pytest.raises(ValueError):
            module.prepare(value, tmp_path)
    assert not (tmp_path / "wrangler.build.json").exists()
