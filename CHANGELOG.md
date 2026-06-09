# Changelog

All notable changes to c-FuSa are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-06-09

### Added
- `init` — project config initialisation
- `check` — full check runner (lint + analyze + cyber)
- `lint` — MISRA-C:2012 rules L001–L010
- `analyze` — static analysis rules A001–A007
- `cyber` — CWE-mapped rules CY001–CY010 (ISO 21434)
- `tara` — ISO 21434 §9 TARA skeleton
- `fmea` — dFMEA from function signatures (IEC 60812)
- `report` — multi-format compliance report (text/json/sarif/html/md)
- `template` — safety doc templates (HARA, PSAC, safety-plan, test-evidence)
- `trace` — requirements traceability matrix
- `verify` — test evidence collection bundle
- `release` — SBOM (SPDX-2.3), build provenance (SLSA)
- `qualify` — tool self-test with SHA-256 known-answer tests
- `safety-case` — GSN safety case + evidence index
- `boundary` — component dependency graph (mermaid/dot)
- `vuln` — known-vulnerable pattern scan
- `audit-pack` — artifact bundle with MANIFEST.json
- `diff` — compare two JSON reports
- `badge` — SVG status badge
- `req` — requirement ID source lookup
- `fix` — mechanical auto-fix
- `hooks` — git pre-commit hook install/remove
- `sign` — HMAC-SHA256 file signing
- `do178` — DO-178C Annex A objective gap report
- `sas` — Software Accomplishment Summary
- `sci` — Software Configuration Index
- `coverage` — gcov/lcov coverage analysis with MC/DC flag
- `pr` — problem report CRUD log
- SHA-256 and HMAC-SHA256 implemented in-tree (no external crypto deps)
- Zero external runtime dependencies
- CMake build system with tests/CTest
- Unity test framework (vendored)
- GitHub Actions CI (multi-platform, coverage, SARIF upload, CodeQL)
- Release pipeline with SBOM and binary artifacts

[Unreleased]: https://github.com/SoundMatt/c-FuSa/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SoundMatt/c-FuSa/releases/tag/v0.1.0
