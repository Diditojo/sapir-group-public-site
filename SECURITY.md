# Public site security maintenance

This release covers the homepage, error page and two public connector information
pages. The connector pages describe a local tool; this website does not implement
that tool or authenticate mailbox users.

Each of these four HTML documents has an early meta Content Security Policy.
Executable homepage scripts are approved by their exact content hash. The other
three pages permit no scripts. Script attributes and dynamic evaluation are
blocked. Inline styles remain allowed for the existing design; Google Fonts
styles and font files retain their existing permitted origins.

After changing executable scripts, review the change and update only the matching
SHA-256 hash in that document's CSP. Hash the exact UTF-8 script body between the
opening and closing script tags, including whitespace, then Base64-encode the
digest. Do not add `unsafe-inline` or `unsafe-eval` to make a failing page work.

Run the regression checker using Python 3 and Node.js:

```sh
python3 scripts/security_checks.py
# Or use an installed Node executable explicitly:
python3 scripts/security_checks.py --node /path/to/node
```

The checker intentionally reads only these four public HTML paths and includes a
negative test rejecting a permissive `script-src-elem` override. It does not test
other repository paths. Also check desktop and mobile navigation in a browser,
inspect the console for CSP failures, and verify an unapproved injected inline
script and event attribute are blocked.

Meta CSP cannot provide `frame-ancestors`, reporting or HTTP security headers.
Review actual hosting responses and account/domain controls separately. This
release does not add access control for other repository files, assess their
publication suitability, audit the local connector implementation or establish
that the hosting account is secure.
