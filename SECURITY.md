# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✓ |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a [GitHub Security Advisory](https://github.com/SoundMatt/c-FuSa/security/advisories/new).

**Do not open a public issue for security vulnerabilities.**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 14 days for critical issues.

## Scope

c-FuSa processes untrusted source files (it reads and scans C source code).
Vulnerabilities in the file parsing, walking, or output generation are in scope.

The rule engine itself operates in read-only mode — it does not execute scanned code.
