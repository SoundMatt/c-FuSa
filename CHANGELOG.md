# Changelog

All notable changes to c-FuSa are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] — 2026-06-11

### Fixed
- `cfusa trace --format json` output now conforms to spec §5: `requirements[]` + `tags[]` (with `requirementId`, `file`, `line`, `kind`) + nested `coverage{}` with camelCase keys `totalRequirements/tracedRequirements/testedRequirements/secTestedRequirements`; `secTestedRequirements` was computed but never emitted
- `cfusa qualify --format json` key names corrected to spec §6: `total/passed/failed` (were `tests_total/tests_passed/tests_failed`)
- Dockerfile: added required `io.x-fusa.*` OCI labels per spec §15 (`io.x-fusa.tool`, `io.x-fusa.language`, `io.x-fusa.binary`, `io.x-fusa.spec-version`)
- Added `slsa` command — SLSA v1.0 provenance gap report (`--level 1|2|3|4`, text/md/json, spec §9.3 `objectives[]` + `summary{}`)

## [0.5.0] — 2026-06-11

### Added
- **Safety runtime library** (`include/cfusa/runtime.h`, `src/cfusa_runtime.c`):
  - `cfusa_watchdog_t` — kick-based timeout monitor (ISO 26262 ASIL-D, IEC 61508 SIL-4)
  - `cfusa_heartbeat_t` — periodic beat health checker
  - `cfusa_state_mgr_t` — formal safe-state machine (ISO 26262-4 §6.4.6, 4 states including terminal EmergencyStop)
  - `cfusa_diag_mgr_t` — bounded ring buffer of diagnostic events (up to 256 entries, configurable)
  - `cfusa_fault_monitor_t` — per-fault occurrence counter with threshold callbacks
- **Engine rules** — 13 new rules registered during `cfusa check`:
  - `HARA001` — errors when `.fusa-hara.json` is absent (ISO 26262-3 Clause 6)
  - `HARA002` — errors on hazards with incomplete S/E/C risk ratings
  - `HARA003` — errors on hazards with no safety goal
  - `HARA004` — warns on safety goals with undetermined ASIL (TBD/empty)
  - `HARA005` — errors when hazard max ASIL exceeds project ASIL
  - `ISO26262001` — warns when `iso26262-gap-report.json` not present
  - `ISO26262002` — warns when requirements in `.fusa-reqs.json` lack ASIL annotations
  - `ISO26262003` — errors when tool qualification report has failures
  - `COUP001` — warns on `extern` mutable variable declarations (data coupling, DO-178C §6.4.4.3)
  - `COUP002` — warns on function pointer parameters (control coupling, DO-178C §6.4.4.3)
  - `COUP003` — info when `coupling-report.json` is absent
  - `DISP001` — warns on ERROR findings in `check-report.json` with no disposition record
  - `COMP001` — warns when cyclomatic complexity V(G) exceeds threshold by DAL (A≤4, B≤10, C≤15, D≤20)
- **Gap report evidence-file checks**:
  - `iso26262`: new objectives 7.3 (`.fusa-hara.json`), 10.4 (`sci.json`), 11.3 (`coupling-report.json`)
  - `iec61508`: new objectives 1.3 (`.fusa-hara.json`), 4.2 (`fmea.json`), 5.4 (`sci.json`)
  - `do178`: A-2.2 checks `.fusa-reqs.json`; A-6.2 checks `check-report.json`; A-6.3 checks `coupling-report.json`
- **Requirements registry** (`.fusa-reqs.json`): 50 formally specified requirements with ASIL/DAL/SIL annotations
- **XML import** for `cfusa req import`:
  - Polarion XML (`<workitems>`) via `--format polarion` with `.xml` file
  - Codebeamer XML (`<tracker><item>`) via `--format codebeamer` with `.xml` file
  - Jama XML (`<items><item>`) via `--format jama` with `.xml` file
- **Evidence documents**: `safety-case.md` (8 safety claims with evidence table), `tara.md` (ISO 21434 §9 TARA)
- **Test coverage**: 30 test suites, 2 new suites (`test_runtime`, `test_safety_rules`)
- **CI**: docs version-consistency check, ISO 26262 gap report and trace output uploaded as CI artifacts

### Changed
- Version bumped to 0.5.0
- `iso26262` gap report now covers Parts 6–11 (was Part 6 only)
- `iso26262` obj 6.4.8 now maps to `COMP001` (was `CFUSA-L001`)
- Coverage threshold raised from 60% to 70%
- CMake project version corrected from 0.3.0 to 0.5.0

## [0.4.0] — 2026-06-10

### Added
- `iec62443` — IEC 62443-4-2 Component Security Requirements gap report (`--sl SL-1|2|3|4`)
  - 28 CRs across FR 1–7 mapped to cfusa rules; spec envelope with `kind: iec62443-gap`
- `sas --dal DAL-A|B|C|D` — Design Assurance Level flag for Software Accomplishment Summary
  - DAL included in JSON, text, and Markdown output headers
- `req export --format doors|polarion|codebeamer|jama` — ALM XML export formats
  - DOORS: ReqIF XML; Polarion: workitems XML; Codebeamer: tracker XML; Jama: items XML
- All gap report JSON outputs now carry `"standard"` and `"projectRoot"` per x-FuSa spec 1.9 canonical envelope
  - Affected: `iso26262`, `iec61508`, `iec62443`, `do178c`, `misra`, `iso21434`, `unece`
  - `unece`: renames `"regulation"` key to `"standard"` for envelope consistency

### Changed
- Spec version bumped to 1.9 (`CFUSA_SCHEMA_VERSION`, `CFUSA_SPEC_VERSION`)
- `capabilities --format json` standards list updated to include `iec62443`

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

[Unreleased]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SoundMatt/c-FuSa/releases/tag/v0.1.0
