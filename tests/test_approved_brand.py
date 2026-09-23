"""Verify the approved B-shaped bulldog, not a substitute logo or external image."""
import hashlib
import json
from pathlib import Path
import struct
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "site/assets/brand"
SOURCE_SHA256 = "79a75d93e09f2b0a460c7ae3feb854c601803adc922bf9a54346955bfd7d803a"
VARIANTS = ("bull-mark.svg", "bull-primary.svg", "bull-primary-dark.svg",
            "bull-stacked.svg", "bull-one-color.svg", "bull-favicon.svg")


class ApprovedBrandTests(unittest.TestCase):
    def test_original_approved_image_is_preserved_byte_for_byte(self):
        data = (BRAND / "bull-approved-sheet.png").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), SOURCE_SHA256)
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (1448, 1086))

    def test_every_asset_matches_the_manifest(self):
        manifest = json.loads((BRAND / "manifest.json").read_text())
        self.assertEqual(manifest["revision"], "approved-bulldog-B-20260919")
        self.assertEqual(manifest["source"]["sha256"], SOURCE_SHA256)
        self.assertTrue(set(VARIANTS).issubset(manifest["files"]))
        for name, record in manifest["files"].items():
            with self.subTest(asset=name):
                self.assertEqual(Path(name).name, name)
                data = (BRAND / name).read_bytes()
                self.assertEqual(len(data), record["bytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])

    def test_vectors_derive_from_approved_source_and_are_self_contained(self):
        for name in VARIANTS:
            with self.subTest(asset=name):
                text = (BRAND / name).read_text()
                self.assertIn(SOURCE_SHA256, text)
                root = ET.fromstring(text)
                self.assertEqual(len(root.attrib["viewBox"].split()), 4)
                self.assertGreater(len(root.findall("{http://www.w3.org/2000/svg}path")), 0)
                for element in root.iter():
                    self.assertNotIn(element.tag.split("}")[-1], ("script", "image", "foreignObject"))
                    self.assertFalse(any(k.lower().startswith("on") or k.split("}")[-1] == "href" for k in element.attrib))

    def test_existing_project_and_publication_logo_wiring_is_preserved(self):
        html = (ROOT / "site/index.html").read_text()
        builder = (ROOT / "tools/build_site.py").read_text()
        readme = (ROOT / "README.md").read_text()
        self.assertIn("./assets/brand/bull-primary.svg", html)
        self.assertIn("./assets/brand/bull-mark.svg", html)
        self.assertIn("./assets/brand/bull-favicon.svg", html)
        self.assertIn("./assets/brand/bull-primary.svg", builder)
        self.assertIn("./assets/brand/bull-favicon.svg", builder)
        self.assertIn("site/assets/brand/bull-primary.svg", readme)
        self.assertIn("site/assets/brand/bull-primary-dark.svg", readme)

    def test_one_color_variant_uses_only_ink_and_knockout(self):
        for name in ("bull-one-color.svg", "bull-favicon.svg"):
            root = ET.parse(BRAND / name).getroot()
            colors = {p.attrib["fill"] for p in root.findall("{http://www.w3.org/2000/svg}path")}
            self.assertTrue(colors <= {"#202830", "#ffffff"})


if __name__ == "__main__":
    unittest.main()
