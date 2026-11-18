#!/usr/bin/env python3
"""Portable static/package checks. This does NOT compile Swift or certify runtime behavior."""
from pathlib import Path
import ast
import plistlib
import re
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parent.parent
for path in ROOT.rglob('*.py'):
    ast.parse(path.read_text(), filename=str(path))
with (ROOT / 'ios/Info.plist').open('rb') as handle:
    plistlib.load(handle)
ET.parse(ROOT / 'ios/CellularTunnel.xcodeproj/xcshareddata/xcschemes/CellularTunnel.xcscheme')
project = (ROOT / 'ios/CellularTunnel.xcodeproj/project.pbxproj').read_text()
ids = set(re.findall(r'^\s*([A-F0-9]{24})(?: /\*.*?\*/)? =', project, re.M))
refs = set(re.findall(r'\b[A-F0-9]{24}\b', project))
assert ids == refs, f'Missing project IDs: {refs - ids}'
for path in re.findall(r'path = ([A-Za-z]+\.swift);', project):
    assert (ROOT / 'ios' / path).is_file(), path
for path in ROOT.rglob('*'):
    assert path.suffix not in {'.p12', '.pem', '.key', '.der'}, 'Private credential artifact in source tree'
print('PASS: Python AST, Info.plist, scheme XML, project references, no key artifacts. This static check does not compile Swift.')
