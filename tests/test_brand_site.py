"""Read-only publication contracts. These checks do not run or certify a VM."""
from collections import Counter
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
_spec = importlib.util.spec_from_file_location("bull_docs_builder", ROOT / "tools/build_site.py")
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class BrandSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="bull-docs-test-")
        cls.output = builder.build(Path(cls.tmp.name) / "public")
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def setUp(self):
        self.html = (self.output / "index.html").read_text(encoding="utf-8")
        self.page = Page(self.html)
    def test_homepage_tracks_current_kvm_and_authority_status(self):
        self.assertIn("One-shot real KVM integration demonstrated", self.html)
        self.assertIn("September 20, 2026", self.html)
        self.assertIn("security-domain lineage and shared root-domain history", self.html)
        self.assertIn("Advisory monotonicity", self.html)
        self.assertIn("Recorded KVM integration evidence", self.html)
        self.assertNotIn("real KVM release boot evidence", self.html)
        self.assertNotIn("What is not connected yet", self.html)

    def test_public_testing_interface_is_removed(self):
        for path in builder.REMOVED:
            self.assertFalse((ROOT / path).exists(), path)
        tags = {tag for tag, _ in self.page.elements}
        self.assertFalse(tags & {"form", "input", "textarea", "select", "iframe"})
        for token in ("load-demo", "request-form", "model-endpoint", "brand-gallery", "cdn.jsdelivr.net", "pyodide.js"):
            self.assertNotIn(token, self.html)
        self.assertEqual([a.get("src") for t, a in self.page.elements if t == "script"], ["./infrastructure.js"])
    def test_publication_removes_video_and_transcript(self):
        self.assertFalse({"video", "track", "iframe"} & {t for t, _ in self.page.elements})
        for value in (".mp4", "#explainer", "transcript.html", "cloudfront.net"):
            self.assertNotIn(value, self.html)
        self.assertFalse((self.output / "transcript.html").exists())

    def test_built_links_assets_and_unique_ids(self):
        for name in ("index.html", "repository.html"):
            page = Page((self.output / name).read_text())
            ids = [a["id"] for _, a in page.elements if "id" in a]
            self.assertFalse([k for k, count in Counter(ids).items() if count > 1])
            for tag, attrs in page.elements:
                if tag == "a":
                    self.assertIn("href", attrs)
                for key in ("src", "href", "poster"):
                    value = attrs.get(key, "")
                    if value.startswith("./"):
                        path = value[2:].split("#", 1)[0]
                        # Verification metadata is created only after real CI succeeds.
                        if path != "data/verification.json":
                            self.assertTrue((self.output / path).is_file(), (name, value))
                    elif value.startswith("#"):
                        self.assertIn(value[1:], ids, (name, value))
            self.assertNotIn("data-code=", (self.output / name).read_text())
        self.assertNotIn("<!-- REPOSITORY_GROUPS -->", self.html)
    def test_every_tracked_source_file_is_indexed(self):
        record = json.loads((self.output / "data/repository.json").read_text())
        actual = {r["path"] for r in record["files"]}
        expected = {p for p in builder.tracked_paths() if (ROOT / p).is_file() and not (ROOT / p).is_symlink()}
        self.assertEqual(actual, expected)
        for row in record["files"]:
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
            if row["path"].startswith("src/bulldog/"):
                self.assertIn(Path(row["path"]).name, self.html)
        self.assertTrue(any(r["symbols"] for r in record["files"]))
    def test_vectors_are_self_contained_and_diagrams_accessible(self):
        for path in (SITE / "assets").rglob("*.svg"):
            root = ET.parse(path).getroot()
            self.assertTrue(root.attrib.get("viewBox"))
            for child in root.iter():
                self.assertNotIn(child.tag.split("}")[-1], ("script", "foreignObject", "image"))
                self.assertFalse(any(k.lower().startswith("on") for k in child.attrib))
            if path.parent.name == "architecture":
                self.assertIsNotNone(root.find("{http://www.w3.org/2000/svg}title"))
                self.assertIsNotNone(root.find("{http://www.w3.org/2000/svg}desc"))
    def test_published_deployment_evidence_matches_visible_claims(self):
        record = json.loads((self.output / "data/validation/ab53f56.json").read_text())
        self.assertEqual(record["commit"], "ab53f563bcbcaf60820acb318b8212796ce502ff")
        self.assertFalse(record["source_dirty"])
        self.assertEqual(record["regression"]["passed"], 501)
        self.assertEqual(record["regression"]["subtests_passed"], 21)
        self.assertEqual(len(record["kvm_cases"]), 5)
        self.assertTrue(all(v == "PASS" for v in record["kvm_cases"].values()))
        self.assertEqual(record["deployment_gates"]["hardware_approval_protocol"], "BLOCKED")
        self.assertFalse(record["physical_key_inspection"]["approval_available"])
        for value in ("501", "21 subtests", "ab53f56", "no secure element", "synthetic signatures"):
            self.assertIn(value, self.html)
        self.assertNotIn("437 tests", self.html)

    def test_readme_and_publication_keep_security_limits(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        normalized = " ".join(readme.split())
        report = " ".join((ROOT / "docs/MICROVM_INTEGRATION_REPORT.md").read_text(encoding="utf-8").split())
        self.assertIn("site/assets/brand/bull-primary.svg", readme)
        self.assertIn("independent third-party security audit", readme)
        # Local KVM integration is now recorded. Keep its evidence link and
        # release limitations instead of requiring obsolete pre-boot wording.
        self.assertIn("docs/MICROVM_INTEGRATION_REPORT.md", readme)
        self.assertIn("ab53f56", normalized)
        self.assertIn("Five cases passed", normalized)
        self.assertIn("external host/guest receipts passed", normalized)
        self.assertIn("Persistent VM recovery", normalized)
        self.assertIn("host namespace sandbox, not the MicroVM", normalized)
        self.assertIn("not production certification or authorization to release", report)
        self.assertIn("parent-acknowledged", self.html)
        self.assertIn("One-shot real KVM integration demonstrated · Persistent VM reuse unfinished", self.html)
    def test_builder_refuses_source_output(self):
        with self.assertRaises(ValueError):
            builder.build(ROOT / "src")
        with self.assertRaises(ValueError):
            builder.build(ROOT)


if __name__ == "__main__":
    unittest.main()
