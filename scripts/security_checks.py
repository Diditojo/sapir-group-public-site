#!/usr/bin/env python3
"""Offline regression checks for the four public information pages and their CSP.

Run with Python 3 and Node.js: python3 scripts/security_checks.py [--node /path/to/node]
This does not fetch dependencies or test the hosting account or response headers.
"""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PAGES = (
    'index.html',
    '404.html',
    'gmail-connector/index.html',
    'gmail-connector/privacy/index.html',
)



class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs), self.getpos()[0]))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check_html(name, text, node):
    doc = Document()
    doc.feed(text)
    policies = [(i, attrs) for i, (tag, attrs, _) in enumerate(doc.tags)
                if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'content-security-policy']
    require(len(policies) == 1, 'expected exactly one CSP meta element')
    csp_index, meta = policies[0]
    rules = {}
    for directive in meta['content'].split(';'):
        parts = directive.split()
        if parts:
            require(parts[0] not in rules, 'duplicate CSP directive')
            rules[parts[0]] = parts[1:]
    for directive in ['default-src', 'script-src-attr', 'connect-src', 'object-src',
                      'base-uri', 'form-action', 'frame-src']:
        require(rules.get(directive) == ["'none'"], directive + ' must deny by default')
    scripts = rules.get('script-src', [])
    # script-src-elem takes precedence for script elements, so it must not
    # silently override the reviewed hash policy with a permissive source list.
    require('script-src-elem' not in rules, 'script-src-elem overrides the reviewed script-src policy')
    require(scripts and all(s == "'none'" or re.fullmatch(r"'sha(?:256|384|512)-[A-Za-z0-9+/=]+'", s)
                            for s in scripts), 'script-src must contain only hashes or none')
    for index, (tag, attrs, line) in enumerate(doc.tags):
        require(not any(key.startswith('on') for key in attrs), 'inline event attribute at line ' + str(line))
        require(not any(str(attrs.get(key, '')).lstrip().lower().startswith('javascript:')
                        for key in ['href', 'src', 'action']), 'javascript URL at line ' + str(line))
        if tag in ['script', 'style', 'link']:
            require(index > csp_index, 'resource precedes CSP at line ' + str(line))
        if tag == 'a' and attrs.get('target') == '_blank':
            require({'noopener', 'noreferrer'} & set(attrs.get('rel', '').split()), 'unsafe new-window link')
        if tag == 'script':
            require('src' not in attrs, 'external scripts are not approved for these public pages')
    openings = len(re.findall(r'<script\b', text, re.I))
    blocks = list(re.finditer(r'<script\b([^>]*)>([\s\S]*?)</script\s*>', text, re.I))
    require(len(blocks) == openings, 'unclosed script element')
    count = 0
    for match in blocks:
        attrs, body = match.groups()
        if re.search(r'\bsrc\s*=|type="application/(?:json|ld\+json)"', attrs, re.I):
            continue
        digest = "'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'"
        require(digest in scripts, 'inline script does not match CSP hash')
        result = subprocess.run([node, '--check'], input=body, text=True, capture_output=True)
        require(result.returncode == 0, 'JavaScript syntax failed: ' + result.stderr.strip())
        count += 1
    print('PASS ' + name + ' (' + str(count) + ' inline scripts checked)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', default=shutil.which('node'))
    args = parser.parse_args()
    require(args.node, 'Node.js is required; supply --node /path/to/node')
    negative = '''<meta http-equiv="Content-Security-Policy" content="default-src 'none';
script-src 'none'; script-src-elem 'unsafe-inline'; script-src-attr 'none';
connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'">'''
    try:
        check_html('negative fixture', negative, args.node)
    except AssertionError as error:
        require(str(error) == 'script-src-elem overrides the reviewed script-src policy',
                'negative fixture failed for the wrong reason')
    else:
        raise AssertionError('negative fixture accepted a permissive script-src-elem override')
    print('PASS negative fixture: permissive script-src-elem rejected')
    for name in PUBLIC_PAGES:
        path = ROOT / name
        check_html(name, path.read_text(), args.node)
    print('PASS all ' + str(len(PUBLIC_PAGES)) + ' public HTML documents')



if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(1)
