"""Rebuild BULL artwork from the exact owner-approved PNG, without network access.

Maintainer-only dependencies: Pillow==11.3.0 and vtracer==0.6.12.
The normal website build and regression tests do not require either package.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "site/assets/brand"
SOURCE_NAME = "bull-approved-sheet.png"
SOURCE_SHA256 = "79a75d93e09f2b0a460c7ae3feb854c601803adc922bf9a54346955bfd7d803a"
SVG = "http://www.w3.org/2000/svg"
REGIONS = {
    "mark": (160, 120, 510, 440),
    "primary": (650, 130, 1400, 435),
    "stacked": (95, 530, 575, 940),
    "one-color": (660, 610, 1400, 895),
}
ET.register_namespace("", SVG)


def luminance(fill: str) -> float:
    value = fill.lstrip("#")
    if len(value) != 6:
        raise ValueError("Unexpected vector fill: " + fill)
    r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    return .299 * r + .587 * g + .114 * b


def vector_bytes(root: ET.Element, name: str, monochrome: bool = False, dark: bool = False) -> bytes:
    root = deepcopy(root)
    width, height = root.attrib["width"], root.attrib["height"]
    root.set("viewBox", f"0 0 {width} {height}")
    root.set("role", "img")
    root.set("aria-labelledby", "brand-title brand-description")
    title = ET.Element(f"{{{SVG}}}title", {"id": "brand-title"})
    title.text = "BULL — Blocking Unauthorized Logic Loopholes"
    description = ET.Element(f"{{{SVG}}}desc", {"id": "brand-description"})
    description.text = "Approved bulldog with the capital B integrated into its silhouette. " + name
    metadata = ET.Element(f"{{{SVG}}}metadata")
    metadata.text = "Source SHA-256: " + SOURCE_SHA256 + "; owner-approved raster-derived vector adaptation."
    root.insert(0, title)
    root.insert(1, description)
    root.insert(2, metadata)
    for element in root.iter(f"{{{SVG}}}path"):
        light = luminance(element.attrib["fill"])
        if light >= 210:
            fill = "#0d1117" if dark else "#ffffff"
        elif light >= 95 and not monochrome:
            fill = "#adb8c4" if dark else "#8c98a4"
        else:
            fill = "#f4f7fa" if dark else "#202830"
        element.set("fill", fill)
        if "transform" in element.attrib:
            element.set("transform", re.sub(r"-?\d+\.\d+", lambda m: str(round(float(m[0]), 2)), element.attrib["transform"]))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def build(source: Path) -> None:
    from PIL import Image, ImageOps
    import vtracer
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("Source is not the approved image; no artwork was changed")
    with Image.open(source) as opened:
        if opened.size != (1448, 1086):
            raise ValueError("Unexpected source dimensions")
        image = opened.convert("RGB")
    products = {SOURCE_NAME: data}
    with tempfile.TemporaryDirectory(prefix="bull-brand-") as temporary:
        tmp = Path(temporary)
        for name, region in REGIONS.items():
            crop = image.crop(region)
            ink = ImageOps.grayscale(crop).point(lambda value: 255 if value < 205 else 0)
            bounds = ink.getbbox()
            if bounds is None:
                raise ValueError("Empty approved artwork region: " + name)
            crop = crop.crop((bounds[0] - 8, bounds[1] - 8, bounds[2] + 8, bounds[3] + 8))
            if name in ("mark", "primary"):
                raster = tmp / (name + "-original.png")
                crop.save(raster, optimize=True)
                products["bull-" + name + ".png"] = raster.read_bytes()
            clean = Image.new("RGB", crop.size)
            clean.putdata([(32, 40, 48) if value < 95 else (140, 152, 164) if value < 210 else (255, 255, 255)
                           for value in ImageOps.grayscale(crop).getdata()])
            input_path, output_path = tmp / (name + ".png"), tmp / (name + ".svg")
            clean.save(input_path)
            vtracer.convert_image_to_svg_py(str(input_path), str(output_path),
                colormode="color", hierarchical="stacked", mode="spline", filter_speckle=1,
                color_precision=8, layer_difference=16, corner_threshold=60,
                length_threshold=3.5, max_iterations=10, splice_threshold=45, path_precision=2)
            root = ET.parse(output_path).getroot()
            background = list(root)[0]
            if background.attrib.get("transform") != "translate(0,0)" or luminance(background.attrib["fill"]) < 210:
                raise ValueError("Unexpected tracing background; refusing to discard artwork")
            root.remove(background)
            products["bull-" + name + ".svg"] = vector_bytes(root, name, monochrome=name == "one-color")
            if name == "primary":
                products["bull-primary-dark.svg"] = vector_bytes(root, "primary, dark background", dark=True)
            if name == "mark":
                products["bull-favicon.svg"] = vector_bytes(root, "browser tab", monochrome=True)
    manifest = {
        "revision": "approved-bulldog-B-20260919",
        "source": {"file": SOURCE_NAME, "sha256": SOURCE_SHA256, "width": 1448, "height": 1086,
                   "note": "Exact owner-approved PNG, unchanged. SVGs are two-tone vector adaptations of its artwork; they are not original vector masters."},
        "generator": {"script": "tools/build_brand_assets.py", "Pillow": "11.3.0", "vtracer": "0.6.12"},
        "files": {name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
                  for name, content in sorted(products.items())},
    }
    BRAND.mkdir(parents=True, exist_ok=True)
    for name, content in products.items():
        (BRAND / name).write_bytes(content)
    (BRAND / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Built {len(products)} approved brand assets; exact source SHA-256 {SOURCE_SHA256}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=BRAND / SOURCE_NAME)
    args = parser.parse_args()
    build(args.source)
