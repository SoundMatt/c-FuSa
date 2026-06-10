# Changelog

All notable changes to c-FuSa are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-06-10

### Added
- `iso26262 --format json` / `--output` — JSON gap report with x-FuSa spec §1.8 envelope (`kind: iso26262-gap`)
- `iec61508 --format json` / `--output` — JSON gap report with spec envelope (`kind: iec61508-gap`)
- `misra --format json` / `--output` — JSON coverage report with spec envelope (`kind: misra-coverage`)
- SARIF 2.1.0 `driver.rules[]` array (all 27 registered rules) and `partialFingerprints.primaryLocationLineHash` (djb2) on every finding

### Changed
- All JSON outputs now carry x-FuSa spec §1.8 envelope: `schemaVersion`, `kind`, `tool`, `toolVersion`, `language`, `generatedAt`
  - Affected commands: `do178`, `iso21434`, `unece`, `coverage`, `fmea`, `tara`, `hara`, `sas`, `verify`
  - Coverage JSON field names aligned to camelCase: `lcovFile`, `lineCoverage`, `functionCoverage`, `branchCoverage`
  - FMEA, TARA, SAS, verify: `generated`/`timestamp`/`created` → `generatedAt`
- `qualify --format json` now writes to stdout by default (was writing to `qualify-report.json`)
- `cfusa capabilities --format json` formats map updated to list all JSON-capable commands
- Evidence filenames lowercased to kebab-case: `safety-case.md`, `tara.md`, `fmea.md`, `hara.md`, `safety-plan.md`, `test-evidence.md`, `sas.md`
- Data files renamed `.cfusa-*` → `.fusa-*` (`.fusa-hara.json`, `.fusa-dispositions.json`, `.fusa-metrics.jsonl`, `.fusa-prs.jsonl`) with legacy fallback reads
- `unece --format json` adds `regulation: "UN R.155"` field
- Trace/req scanner: false-positive annotations filtered by ID format validation (`[a-zA-Z0-9\-_]+`); line break on `"` to prevent string literal leakage

### Fixed
- `cfusa engine_get_rule(i)` accessor exposed for SARIF rules-array and JSON remediation fields
- OCI image labels added to Dockerfile (`org.opencontainers.image.*`)

## [0.2.0] — 2026-06-09

### Added
- `hara` — Hazard Analysis & Risk Assessment (ISO 26262-3:2018 §6): `init`/`show`/`asil` subcommands with full ASIL determination table (S×E×C)
- `iso26262` — ISO 26262 Part 6 compliance gap report (`--asil ASIL-A|B|C|D`)
- `iec61508` — IEC 61508 Parts 1–3 compliance gap report (`--sil SIL-1|2|3|4`)
- `misra` — MISRA C:2012 rule coverage mapping with gap reporting (`--gaps`)
- `disposition` — Finding disposition tracking (`add`/`list`/`show`); stored in `.cfusa-dispositions.json`
- `impact` — Change impact analysis on requirements (`--from`/`--to` git refs)
- `metrics` — Safety metrics recording and trend view (`record`/`show`); stored in `.cfusa-metrics.jsonl`
- Requirements registry format: `.cfusa-reqs.json` with `id`, `title`, `text`, `standard`, `level` per requirement
- `//cfusa:req`, `//cfusa:test`, `//cfusa:sec-test` annotation scheme for traceability
- `cfusa trace --req-coverage N` and `--sec-tested N` quality gates (exit 1 if below threshold)
- `cfusa req export` / `cfusa req import` — CSV round-trip for requirements interchange
- Docker image and `docker-compose.yml` pipeline (`check → trace → qualify → release`)
- SPDX format upgrade from 2.3 to 3.0.1 JSON in release artifacts

### Changed
- Test suite expanded from 9 suites to **27 suites with 454 tests** — 100% passing
- Requirements traceability: **140 formally specified requirements** (`//cfusa:req` and `//cfusa:test` annotated), 0 gaps
- Line coverage improved to **63%** (above 60% CI gate)
- `cfusa release --full` now invokes fmea, boundary, vuln, and produces SHA256SUMS
- `cfusa vuln` adds JSON output format and word-boundary matching to reduce false positives

### Fixed
- CY009 false positive on function names containing `des_` as a substring
- L002 goto detection now requires `goto` at line start (no false positives in strings)
- L001 function length uses `close_brace_line − open_brace_line` (not +1)

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

[Unreleased]: https://github.com/SoundMatt/c-FuSa/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SoundMatt/c-FuSa/releases/tag/v0.1.0
