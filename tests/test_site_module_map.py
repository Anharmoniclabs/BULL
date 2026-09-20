"""Publication module identities must retain package paths and fail on drift."""
from html.parser import HTMLParser
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("bull_module_map_builder", ROOT / "tools/build_site.py")
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)
COMMIT = "a" * 40
GROUPS = [
    ("Public API", "Top-level API", "__init__.py"),
    ("Multi-agent", "Orchestration", "multiagent/__init__.py multiagent/contracts.py multiagent/system.py"),
    ("Observation", "Observation only", "adversary/__init__.py adversary/contracts.py adversary/system.py"),
]


def rows_for(groups):
    return [{"path": "src/bulldog/" + name}
            for _, _, names in groups for name in names.split()]


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.hrefs = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.append(dict(attrs)["href"])


class SiteModuleMapTests(unittest.TestCase):
    def test_duplicate_basenames_keep_distinct_source_links(self):
        rows = rows_for(GROUPS)
        with patch.object(builder, "GROUPS", GROUPS):
            links = Links(builder.groups_html(COMMIT, rows)).hrefs
        expected = [builder.source_link(row["path"], COMMIT) for row in rows]
        self.assertCountEqual(links, expected)
        self.assertEqual(len(links), len(set(links)))
        self.assertNotIn(builder.source_link("src/bulldog/contracts.py", COMMIT), links)

    def test_descriptions_use_package_relative_identity(self):
        with patch.object(builder, "GROUPS", GROUPS):
            self.assertEqual(builder.describe("src/bulldog/__init__.py"), "Public API")
            self.assertEqual(builder.describe("src/bulldog/multiagent/contracts.py"), "Multi-agent")
            self.assertEqual(builder.describe("src/bulldog/adversary/contracts.py"), "Observation")

    def test_unknown_nested_module_still_fails_closed(self):
        rows = rows_for(GROUPS) + [{"path": "src/bulldog/other/contracts.py"}]
        with patch.object(builder, "GROUPS", GROUPS):
            with self.assertRaisesRegex(ValueError, "module-map drift"):
                builder.groups_html(COMMIT, rows)

    def test_missing_nested_module_is_not_masked_by_same_basename(self):
        rows = [row for row in rows_for(GROUPS)
                if row["path"] != "src/bulldog/adversary/contracts.py"]
        with patch.object(builder, "GROUPS", GROUPS):
            with self.assertRaisesRegex(ValueError, "module-map drift"):
                builder.groups_html(COMMIT, rows)

    def test_duplicate_documented_path_is_rejected(self):
        duplicate = GROUPS + [("Duplicate", "Invalid duplicate", "multiagent/system.py")]
        with patch.object(builder, "GROUPS", duplicate):
            with self.assertRaisesRegex(ValueError, "duplicate documented path"):
                builder.groups_html(COMMIT, rows_for(GROUPS))

    def test_non_runtime_paths_do_not_pollute_module_groups(self):
        rows = rows_for(GROUPS) + [{"path": "tests/system.py"}, {"path": "docs/system.py"}]
        with patch.object(builder, "GROUPS", GROUPS):
            self.assertEqual(len(Links(builder.groups_html(COMMIT, rows)).hrefs), len(rows_for(GROUPS)))

    def test_real_registry_links_match_every_tracked_runtime_path(self):
        commit = builder.git("rev-parse", "HEAD")
        rows = builder.inventory(commit)
        links = Links(builder.groups_html(commit, rows)).hrefs
        expected = [builder.source_link(row["path"], commit) for row in rows
                    if row["path"].startswith("src/bulldog/")]
        self.assertCountEqual(links, expected)
        self.assertEqual(len(links), len(set(links)))


if __name__ == "__main__":
    unittest.main()
