"""Recipe rejection tests; actual upstream Kconfig configuration is a CI job."""
import json
from pathlib import Path

import pytest

from microvm.guest import build_public as recipe


def sealed_configuration(tmp_path):
    inputs = tmp_path / "inputs"
    (inputs / "overlay/var/lib/clamav").mkdir(parents=True)
    (tmp_path / "output").mkdir()
    (tmp_path / "output/.config").write_text("configuration fixture, not a compiled image\n")
    record = {"format": "bull-public-guest-build-v1", "recipe_sha256": recipe.sha(recipe.__file__),
              "sources": {}, "inputs": recipe.snapshot(inputs),
              "resolved_config_sha256": recipe.sha(tmp_path / "output/.config"),
              "database_verification": "NOT_RUN"}
    recipe.save(tmp_path / "build.json", record)
    return record


def test_guest_build_refuses_unverified_databases_before_running_make(tmp_path, monkeypatch):
    sealed_configuration(tmp_path)
    # Supply the pinned source map separately so this fixture can exercise the
    # database gate without cloning or claiming a source checkout was inspected.
    record = json.loads((tmp_path / "build.json").read_text())
    record["sources"] = {name: {"path": str(tmp_path / name), "commit": pin, "url": url}
                         for name, (url, pin) in recipe.SOURCES.items()}
    recipe.save(tmp_path / "build.json", record)
    monkeypatch.setattr(recipe, "source", lambda *args: tmp_path)
    def forbidden(*args, **kwargs):
        pytest.fail("an unverified database must stop before compilation")
    monkeypatch.setattr(recipe, "command", forbidden)
    with pytest.raises(ValueError, match="verified before building"):
        recipe.build(tmp_path)
    assert not (tmp_path / "assets.json").exists()


@pytest.mark.parametrize("target", ["inputs/change", "output/.config"])
def test_changed_build_inputs_are_rejected(tmp_path, target):
    sealed_configuration(tmp_path)
    (tmp_path / target).write_text("changed\n")
    with pytest.raises(ValueError, match="changed"):
        recipe.load(tmp_path)


def test_missing_config_requirement_is_a_failure(tmp_path):
    config = tmp_path / "config"
    config.write_text("BR2_PACKAGE_BASH=y\n# BR2_PACKAGE_CLAMAV is not set\n")
    with pytest.raises(ValueError, match="BR2_PACKAGE_CLAMAV"):
        recipe.selected(config, ["BR2_PACKAGE_CLAMAV"])


@pytest.mark.parametrize("changed", ["missing", "revision"])
def test_source_identity_cannot_be_removed_or_changed(tmp_path, changed):
    record = sealed_configuration(tmp_path)
    if changed == "revision":
        record["sources"] = {name: {"path": str(tmp_path / name), "commit": "0" * 40, "url": url}
                             for name, (url, _) in recipe.SOURCES.items()}
        recipe.save(tmp_path / "build.json", record)
    with pytest.raises(ValueError, match="source"):
        recipe.load(tmp_path)


def test_prepare_requires_new_external_output_and_public_sources(tmp_path):
    with pytest.raises(ValueError, match="provide --buildroot"):
        recipe.prepare(tmp_path / "build")
    assert not (tmp_path / "build").exists()
    with pytest.raises(ValueError, match="outside Git"):
        recipe.prepare(recipe.ROOT / "unsafe-build", fetch=True)


def test_build_job_limit_reaches_package_builders_and_firmware(tmp_path, monkeypatch):
    """Check child-process limits without producing synthetic build evidence."""
    record = sealed_configuration(tmp_path)
    record.update(
        sources={name: {"path": str(tmp_path / name), "commit": pin, "url": url}
                 for name, (url, pin) in recipe.SOURCES.items()},
        database_verification="VERIFIED_BY_SIGTOOL",
        source_date_epoch="1",
    )
    recipe.save(tmp_path / "build.json", record)
    monkeypatch.setattr(recipe, "source", lambda *args: tmp_path)
    monkeypatch.setattr(recipe, "selected", lambda *args: None)
    calls = []

    class StopBeforeCompilation(Exception):
        pass

    def capture(args, **kwargs):
        argv = [str(arg) for arg in args]
        calls.append(argv)
        if Path(argv[0]).name == "ninja":
            raise StopBeforeCompilation

    monkeypatch.setattr(recipe, "command", capture)
    with pytest.raises(StopBeforeCompilation):
        recipe.build(tmp_path, jobs=3)
    make_calls = [argv for argv in calls if argv[0] == "make"]
    assert len(make_calls) == 2
    for argv in make_calls:
        assert "BR2_JLEVEL=3" in argv  # Buildroot's explicit package parallelism.
        assert "-j3" in argv  # Recursive make jobserver.
    assert "-j3" in calls[-1]  # Separate firmware Ninja process.
    assert not (tmp_path / "assets.json").exists()


@pytest.mark.parametrize("jobs", [0, 17, True])
def test_invalid_build_job_limit_stops_before_reading_inputs(tmp_path, jobs):
    with pytest.raises(ValueError, match="build jobs"):
        recipe.build(tmp_path, jobs=jobs)
