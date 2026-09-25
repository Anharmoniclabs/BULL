from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "ui" / "bull-command-center"


def _read(name: str) -> str:
    return (UI / name).read_text("utf-8")


def test_command_center_nav_routes_match_views():
    html = _read("index.html")
    nav = re.findall(r'data-view="([^"]+)"', html)
    views = re.findall(r'id="view-([^"]+)"', html)
    assert nav == views
    assert len(nav) == len(set(nav))


def test_command_center_javascript_dom_references_exist():
    html = _read("index.html")
    app = _read("app.js")
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    references = set(re.findall(r'(?<!\$)\$\("([^"]+)"\)', app))
    missing = sorted(references - ids)
    assert missing == []


def test_command_center_has_one_visible_initial_view():
    html = _read("index.html")
    sections = re.findall(
        r'<section class="view([^"]*)" id="view-([^"]+)"([^>]*)>',
        html,
    )
    initially_visible = [
        name
        for classes, name, attrs in sections
        if "active" in classes.split() and "hidden" not in attrs
    ]
    assert initially_visible == ["overview"]


def test_command_center_does_not_render_brand_asset_directory():
    html = _read("index.html")
    app = _read("app.js")
    assert 'id="brand-assets"' not in html
    assert 'id="brand-revision"' not in html
    assert '$("brand-assets")' not in app
    assert '$("brand-revision")' not in app


def test_command_center_keeps_legacy_route_aliases():
    app = _read("app.js")
    assert 'activity:"signals"' in app
    assert 'workspace:"files"' in app
    assert 'controls:"assurance"' in app
