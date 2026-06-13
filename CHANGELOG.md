# Changelog

All notable changes to c-FuSa are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.23] — 2026-06-13

### Fixed
- **`metrics` subcommand validation** (go-FuSa parity) — `cfusa metrics` now returns exit 2 when no subcommand is given or an unknown subcommand is specified. Previously it defaulted to `show` when no subcommand was given. Also `metrics record` output now includes "Metrics recorded" prefix. Matches go-FuSa `TestRunMetrics_NoSubcmd`, `TestRunMetrics_UnknownSubcmd`, `TestRunMetricsRecord_EmptyDir`.
- **`hooks install` already-exists returns exit 2** (go-FuSa parity) — `cfusa hooks install` now returns exit 2 when the hook file already exists. Also uses `cfusa_mkdir_p` to create the hooks directory if missing (returns exit 3 on failure). Messages use lowercase "pre-commit hook installed/removed". Matches go-FuSa `TestHooksInstall_AlreadyExists`, `TestHooksInstall_MkdirAllError`, `TestHooksInstall_Success_V025`.
- **`hooks remove` not-found returns exit 2** (go-FuSa parity) — `cfusa hooks remove` now returns exit 2 when the hook file is not found (was: exit 0 with info message). Returns exit 3 on other remove errors. Matches go-FuSa `TestHooksRemove_NotFound`, `TestHooksRemove_RuntimeError`, `TestHooksRemove_Success_V025`.
- **`badge` positional report file + too-many-args exit 3** (go-FuSa parity) — `cfusa badge` now accepts the report file as an optional positional argument (in addition to `--report`). Passing more than one positional argument returns exit 3. Matches go-FuSa `TestRunBadge_TooManyArgs`, `TestRunBadge_FromFileWithErrors`, `TestRunBadge_OutputFile`.
- **`disposition add` invalid `--action` returns exit 2** (go-FuSa parity) — `cfusa disposition add` now validates `--action` accepts only `accept`, `fix`, `mitigate` and returns exit 2 for any other value. Matches go-FuSa `TestRunDispositionAdd_InvalidAction`.

## [0.5.22] — 2026-06-13

### Fixed
- **`disposition` subcommand validation** (go-FuSa parity) — `cfusa disposition` now returns exit 2 when no subcommand is given, when an unknown subcommand is specified, or when required `add` flags (`--rule`, `--rationale`, `--reviewer`) are missing. Previously these cases either defaulted to `list` (no subcommand) or returned exit 1 (missing flags). Matches go-FuSa `TestRunDisposition_NoSubcmd`, `TestRunDisposition_UnknownSubcmd`, `TestRunDispositionAdd_MissingFlags`, `TestRunDispositionAdd_MissingReviewer`, `TestRunDispositionAdd_MissingRationale`.

## [0.5.21] — 2026-06-13

### Added
- **`vuln --output-dir <dir>`** (go-FuSa parity) — `cfusa vuln` now accepts `--output-dir <dir>`. When set, it creates the directory, writes `vuln.json` (JSON format) there, prints "Vulnerability scan report written to {path}", and prints a summary line to stdout. Matches go-FuSa `TestRunVuln_OutputDir`.

## [0.5.20] — 2026-06-13

### Added
- **`init` returns exit 2 when all files already exist** (go-FuSa parity) — `cfusa init` now returns exit 2 (usage error) instead of exit 0 when `.fusa.json` and `.fusa-reqs.json` both already exist and `--force` is not set. Matches `TestRunInit_AlreadyExists`.
- **`init --module <path>`** (go-FuSa parity) — `cfusa init` now accepts a `--module` flag (analogous to go-FuSa's Go module path). The value is accepted without error; c-FuSa treats it as informational. Matches `TestRunInit_WithNameAndModule`.
- **`sas --prepared-by <name>`** (go-FuSa parity) — `cfusa sas` now accepts `--prepared-by <name>`. The preparer name appears in the generated SAS document across all output formats (`text`, `json`, `md`). Matches `TestRunSas_PreparedBy`.
- **`sas --output -`** (go-FuSa parity) — `cfusa sas` now treats `--output -` as stdout, matching go-FuSa's convention. Previously `-` was treated as a file path.

## [0.5.19] — 2026-06-13

### Added
- **`hara show --output <file>`** (go-FuSa parity) — `cfusa hara show` now accepts `--output <file>` to write output to a file instead of stdout, for all three formats (`text`, `json`, `markdown`). Matches go-FuSa's `TestRunHaraShow_WithOutputAndGaps`. Internally refactored show functions to accept `FILE*` parameter.

## [0.5.18] — 2026-06-13

### Added
- **`template --type <type>`** (go-FuSa parity) — `cfusa template` now accepts a `--type` flag (`safety-plan`, `test-evidence`, `hara`, `psac`, `all`). Default is `all`, which writes all templates to the output directory and prints "Templates written to <dir>". The legacy positional-arg form is still accepted. Default output directory is now `docs/safety` (matching go-FuSa) when `--dir` is not specified. Matches `TestRunTemplate_SafetyPlan`, `TestRunTemplate_All`, `TestRunTemplate_Default`.

## [0.5.17] — 2026-06-13

### Added
- **`init --docs`** (go-FuSa parity) — `cfusa init --docs` now generates starter safety documentation templates (`safety-plan.md`, `test-evidence.md`, `hara.md`, `psac.md`) in `<dir>/docs/safety/`, matching go-FuSa's `init --docs` behaviour. Equivalent to running `cfusa template` for all template types.

## [0.5.16] — 2026-06-13

### Fixed
- **Invalid `--format` exit codes — batch 2** (go-FuSa parity) — `cfusa slsa`, `iec62443`, and `comp` now return proper exit codes for unrecognised `--format` values. `slsa` and `iec62443` return exit 3 (matches `TestRunSLSA_BadFormat` / `TestRunIEC62443_BadFormat`); `comp` returns exit 2 (matches `TestRunComp_BadFormat` which expects `ExitUsage`). Previously all three silently fell back to text output and returned 0.

## [0.5.15] — 2026-06-13

### Fixed
- **Invalid `--format` exit codes** (go-FuSa parity) — `cfusa unece`, `iso26262`, `iec61508`, and `iso21434` now return exit 3 when given an unrecognised `--format` value (e.g. `--format xml`). Previously they silently fell back to text output and returned 0. Matches go-FuSa's `TestRunUNECE_BadFormat` / `TestRunISO26262_BadFormat` / `TestRunIEC61508_BadFormat` / `TestRunISO21434_BadFormat` expectations. `cfusa version` already returned exit 2 for bad format; no change needed there.

## [0.5.14] — 2026-06-13

### Added
- **`hara show --format json|markdown`** (go-FuSa parity) — `cfusa hara show` now accepts `--format text|json|markdown`. JSON dumps the `.fusa-hara.json` file content; Markdown emits a `| ID | Event | S | E | C | ASIL | Safety Goal |` table. Default remains `text` (unchanged). Matches go-FuSa's `hara show -format json|markdown` behaviour.

## [0.5.13] — 2026-06-13

### Added
- **`check --no-summary`** (go-FuSa parity) — text output now includes a per-category `SUMMARY` table and a `TOP RULES` table after the findings list, matching go-FuSa's text report format. The new `--no-summary` flag suppresses these tables (equivalent to go-FuSa's `--no-summary`). The `Summary: N total` and `Result: PASS/FAIL` lines always appear.

## [0.5.12] — 2026-06-13

### Fixed
- **`finding.category` spec §4 MUST conformance** — `"cyber"` is now mapped to `"security"` and `"analyze"` is mapped to `"safety"` at report storage time, bringing all finding categories into the spec §4 closed enum (`lint`, `style`, `safety`, `security`, `coverage`, `requirement`, `concurrency`, `supply-chain`, `config`, `other`). Previously `check --format json` would fail the FuSaOps `check/category-enum` conformance check. Internal engine filtering (`--category analyze`/`--category cyber`) is unchanged.

## [0.5.11] — 2026-06-13

### Fixed
- **`capabilities` commands list was incomplete** (spec §9.1 MUST) — 11 implemented commands were missing from the advertised list: `verify`, `coupling`, `badge`, `sas`, `sci`, `pr`, `hooks`, `impact`, `metrics`, `comp`, `template`. All are now listed, matching go-FuSa parity. Also added `"comp": ["text","json"]` to the formats map.

## [0.5.10] — 2026-06-13

### Fixed
- **`capabilities` omitted `slsa`** (spec §9.1 MUST) — `slsa` is now listed in the `commands` array, the `formats` map (`["text","json"]`), and the `standards` array (`slsa`). The command also gains `--output <file>` for machine-readable discovery (parity with go-FuSa).

## [0.5.9] — 2026-06-12

### Added
- **`endLine`/`endColumn` in finding location** (spec §4 MAY) — `cfusa_finding_t` now carries `end_line` and `end_column` fields; JSON and SARIF output emit them conditionally when non-zero, aligning c-FuSa with go-FuSa, cpp-FuSa, rust-FuSa, and py-FuSa. Default is 0 (not emitted), so all existing callers are backward-compatible.

## [0.5.8] — 2026-06-12

### Added
- **`coverage --dal`** — DO-178C Design Assurance Level flag (`DAL-A`/`DAL-B`/`DAL-C`/`DAL-D`); sets level-specific thresholds (DAL-A: 100% line+branch+MC/DC, DAL-B: 100% line+branch, DAL-C: 100% line, DAL-D: no threshold). Invalid DAL value returns exit code 2.
- **`metrics record` auto-collection** — without manual `--errors`/`--warnings`/`--info` flags, `record` now reads `check-report.json`, `trace-matrix.json`, and `coverage-report.json` from the project directory to collect `errorCount`, `warningCount`, `infoCount`, `totalRequirements`, `tracedRequirements`, `testedRequirements`, `coveragePct` automatically (parity with go-FuSa).
- **`metrics show --format`/`--output`** — `show` now accepts `--format text|json` and `--output <file>`, enabling machine-readable metrics export (parity with go-FuSa).
- **Snapshot schema extended** — metrics snapshots now include `totalRequirements`, `tracedRequirements`, `testedRequirements`, `coveragePct`; old snapshots missing these fields remain backward-compatible.

## [0.5.7] — 2026-06-12

### Fixed
- **gap-report `kind`** (§3.1 MUST) — all 7 commands (`iso26262`, `iec61508`, `iec62443`, `iso21434`, `unece`, `do178`, `slsa`) now emit `"kind": "gap-report"` instead of `"iso26262-gap"` etc.
- **gap-report `standard`** (§2.4.1 MUST) — canonical lowercase ids (`iso26262`, `iec61508`, `iec62443`, `iso21434`, `unece-r155`, `do178c`) replace display strings (`"ISO 26262"`, `"IEC 61508"`, etc.)
- **gap-report objective `status`** (§9.3 MUST) — `"covered"` → `"satisfied"`, `"gap-recommended"` → `"partial"`, `"pending"` → `"gap"` across all commands
- **gap-report objective `rule`** (§9.3 MUST) — `"rule": "RULE001"` (single string) replaced by `"findings": ["RULE001"]` (array) across all commands; empty `"findings": []` for commands without rule mappings
- **`audit-pack` stdout** (§2.2 MUST) — success confirmation line now goes to stderr so stdout is clean when `--output` is given
- Tests updated to assert canonical `"gap-report"` kind and lowercase standard ids

## [0.5.6] — 2026-06-12

### Fixed
- **`init --name`** — added `--name` as an alias for `--project` (§9.1; FuSaOps conformance calls `init --name <n> --standard <s>`); project now defaults to the directory basename when neither flag is given, removing the non-interactive-mode hard failure
- FuSaOps conformance score: **38 PASS, 0 FAIL, 0 SKIP** (previously 36/38 with `init` skipped)

## [0.5.5] — 2026-06-12

### Fixed
- **`audit-pack --output <file>`** — `zip` was treating a pre-existing empty temp file as a corrupt archive and exiting 3; `remove()` now clears the output path before zipping so `zip` always creates a fresh archive. FuSaOps §8 conformance check now fully passes (36 PASS, 0 FAIL, 2 SKIP)
- **`audit-pack` staging dir leak** — staging directory is now removed after the ZIP is assembled

## [0.5.4] — 2026-06-12

### Fixed
- **`trace --format json`** — added missing `"projectRoot"` field (§3.2 MUST); `g_dir_abs` (resolved absolute path) is now included in every JSON trace-matrix document
- **`qualify --output <file>`** — without `--format json`, the file was written as text; now defaults to JSON when `--output` is given and `--format` is not explicitly set (§6 MUST); verbose progress lines are suppressed from JSON output to preserve machine-readability (§2.2)

## [0.5.3] — 2026-06-12

### Added
- **`cfusa comp`** — standalone cyclomatic complexity (McCabe V(G)) report command, achieving full feature parity with cpp-FuSa, py-FuSa, rust-FuSa, and java-FuSa:
  - Walks `.c` source files and computes V(G) per function using brace-tracking and decision-node counting
  - Per-assurance-level thresholds: `--dal-a` (4), `--dal-b` (10, default), `--dal-c` (15), `--dal-d` (20); `--asil-d/c/b/a` aliases
  - Custom threshold via `--threshold <n>`
  - Output formats: `text` (table), `json` (`comp-report.json` schema), `md` (Markdown table)
  - `--output <file>` writes report to disk; `--verbose` includes all functions (default: violations only)
  - Exits 1 if any function exceeds threshold; exits 0 when clean (DO-178C §6.3.4 gate-able)
  - Requirements `REQ-COMP001`–`REQ-COMP005` tagged in source

## [0.5.2] — 2026-06-12

### Added
- **Cyber rules CY011–CY020** — 10 new rules for go-FuSa parity: SSRF via curl URL variable (CY011), debug socket option exposed (CY012), archive path traversal / zip-slip (CY013), weak/deprecated TLS method (CY014), SQL injection via sprintf (CY015), permissive directory mode (CY016), permissive file mode (CY017), path traversal from argv/env (CY018), TOCTOU race (CY019), predictable /tmp path (CY020)
- **FUSA001–FUSA005 project-structure engine rules**: safety config present (FUSA001), build system present (FUSA002), license file present (FUSA003), README present (FUSA004), CI configuration present (FUSA005)
- **`cfusa hooks show`** subcommand — prints the installed hook script to stdout
- **`cfusa qualify` FUSA rule exercise cases** — 18 known-answer tests including FUSA001–005 positive/negative scenarios; JSON output gains `"kind"` and `"ruleId"` fields per case

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

[Unreleased]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.7...HEAD
[0.5.7]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/SoundMatt/c-FuSa/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SoundMatt/c-FuSa/releases/tag/v0.1.0
