"""Static branding and DOM contract checks; these do not certify a live sandbox."""
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / 'site'

class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

class BrandSiteTests(unittest.TestCase):
    def setUp(self):
        self.html = (SITE / 'index.html').read_text(encoding='utf-8')
        self.page = Page(self.html)
    def test_existing_browser_dom_contract(self):
        ids = [attrs['id'] for _, attrs in self.page.elements if 'id' in attrs]
        self.assertFalse([key for key, value in Counter(ids).items() if value > 1])
        for name in ('app.js', 'story.js', 'model-connector.js'):
            required = set(re.findall(r"byId\(['\"]([^'\"]+)['\"]\)", (SITE / name).read_text(encoding='utf-8')))
            self.assertFalse(required - set(ids), (name, sorted(required - set(ids))))
    def test_local_assets_and_navigation_resolve(self):
        ids = {attrs['id'] for _, attrs in self.page.elements if 'id' in attrs}
        for _, attrs in self.page.elements:
            for key in ('src', 'href', 'poster'):
                value = attrs.get(key, '')
                if value.startswith('./'):
                    self.assertTrue((SITE / value[2:].split('#', 1)[0]).is_file(), value)
                elif value.startswith('#'):
                    self.assertIn(value[1:], ids)
    def test_python_demo_is_explicit_opt_in(self):
        scripts = [attrs.get('src', '') for tag, attrs in self.page.elements if tag == 'script']
        self.assertEqual(scripts, ['./story.js'])
        elements = {attrs['id']: attrs for _, attrs in self.page.elements if 'id' in attrs}
        self.assertIn('disabled', elements['evaluate-button'])
        self.assertIn('disabled', elements['reset-button'])
        self.assertIn('load-demo', elements)
    def test_vector_assets_are_self_contained(self):
        names = ('bull-mark.svg', 'bull-primary.svg', 'bull-primary-dark.svg', 'bull-stacked.svg', 'bull-one-color.svg', 'bull-favicon.svg')
        for name in names:
            node = ET.parse(SITE / 'assets' / 'brand' / name).getroot()
            self.assertTrue(node.attrib.get('viewBox'))
            for child in node.iter():
                self.assertNotIn(child.tag.split('}')[-1], ('script', 'foreignObject', 'image'))
                self.assertFalse(any(key.lower().startswith('on') for key in child.attrib))
    def test_readme_shares_brand_and_documents_limits(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertIn('site/assets/brand/bull-primary.svg', readme)
        self.assertIn('independent third-party security audit', readme)
        self.assertIn('real-KVM certification remain unfinished', readme)

if __name__ == '__main__':
    unittest.main()
