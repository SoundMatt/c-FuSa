# Changelog

All notable changes to c-FuSa are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.5.43 — 2026-07-27

Fixes from a 2026-07-27 cross-repo audit (issues #62, #63).

### Fixed
- **Dockerfile OCI license label was factually wrong**:
  `org.opencontainers.image.licenses` said `"MIT"`; the project is
  MPL-2.0 (matches `LICENSE` and the README badge). Every published image
  misrepresented its license until now. (#62)
- **Dockerfile version/spec-version labels were hardcoded and stale**:
  `org.opencontainers.image.version="0.5.33"` (13 releases behind) and
  `io.x-fusa.spec-version="1.9"` are now `ARG`s (`CFUSA_VERSION`,
  `CFUSA_SPEC_VERSION`) injected by `.github/workflows/docker-publish.yml`
  from the release tag and `include/cfusa/version.h`, so published images
  track the real version going forward instead of drifting. (#62)
- **CHANGELOG.md was missing the `v0.2.1` entry** — the log jumped
  `[0.2.0] → [0.3.0]` even though tag `v0.2.1` exists in git history.
  Added in its correct chronological slot. (#62)
- **Release notes were boilerplate**: `.github/workflows/release.yml` now
  extracts the matching version's section from `CHANGELOG.md` and leads the
  release body with it, instead of only the generic install/verify
  template (which is now appended after the real summary). (#62)
- **README.md was missing `iec62443` entirely**: added a row to both the
  Commands table and the Standards table for the fully-registered
  `iec62443` command (IEC 62443-4-2 Component Security Requirements gap
  report). (#63)

### Changed
- `CFUSA_SPEC_VERSION` bumped `1.10.12` → `1.11.0` to match the x-FuSa
  master spec's additive §1.4.1 MINOR bump; c-FuSa v0.5.41 already
  implements the corresponding `--func-coverage` gate and dangling-ID
  detection, so this only makes the reported spec version accurate. (#62)

## v0.5.42 — 2026-07-27

### Added
- **Closed the 10 confirmed `REQ-CLI-*` requirement→test gaps** left by the
  v0.5.41 CLI retrofit (`REQ-CLI-BOUNDARY001`, `REQ-CLI-FMEA001`,
  `REQ-CLI-PR001`, `REQ-CLI-TARA001`, `REQ-CLI-VERIFY001`,
  `REQ-CLI-VERSION001`, `REQ-CLI-TEMPLATE001`, `REQ-CLI-SCI001`): each
  already had an exercising test in `test_commands2.c` or
  `test_safety_commands.c` under its lower-level requirement id — added a
  second `//cfusa:test REQ-CLI-*` tag to that same test function rather than
  duplicating coverage.
  - `REQ-CLI-REPORT001` and `REQ-CLI-MAIN001` had no exercising test at all:
    added `test_report_help_returns_zero`, `test_report_runs_no_crash`,
    `test_report_json_format_writes_output`, and
    `test_report_strict_is_usage_error` (the last covers the §9.1 usage-error
    path for `--strict` on `report`), plus `test_help_lists_known_commands`
    for `cmd_help()`'s dispatch-table-driven usage output, all in
    `test_commands2.c`.
  - `main.c` previously defined `CFUSA_COMMANDS[]`, `CFUSA_COMMAND_COUNT`, and
    `cmd_help()` alongside `main()`, so none of the three were linkable into
    a unit-test binary (the `cfusa_cmds` library deliberately excludes
    `main.c` to avoid a duplicate `main` symbol). Split the table and
    `cmd_help()` out into a new `cmd/cfusa/cmd_dispatch.c` (added to the
    `cfusa_cmds` library in `CMakeLists.txt`); `main.c` now only contains the
    dispatch loop wired around them. No behavioural change.
- **Function-tag coverage**: `cfusa trace --func-coverage 100` was reporting
  82% (116/140), but investigation showed every one of the 24 "unannotated"
  functions was a CMake compiler-ID probe (`CMakeCCompilerId.c:main`) inside
  six stray, gitignored/untracked build directories left over in the working
  tree (`build_asan/`, `build_fortify/`, `build-asan/`, `build-asan-test/`,
  `build-cov2/`, `build-local/`, `build-release/`) — the source walker's
  build-dir exclusion list only matches the literal names `build` and
  `build-cov`, not these. Every file in `cmd/cfusa/*.c` and `src/*.c` already
  carries a file-level `//cfusa:req` tag (real-source function coverage was
  already 100%); removed the stray build directories so the metric reflects
  that. Density now measures 97% (116/119) — the residual 3 are the same
  compiler-probe `main()`, unavoidably present in the `build-test/` directory
  this project's own build instructions require.

## v0.5.41 — 2026-07-27

### Added
- **x-FuSa spec §1.4.1 "Tag placement & completeness"** implemented in
  `cfusa trace`:
  - `--func-coverage N` flag (mirrors `--req-coverage`): gates on the
    percentage of non-static public functions (in `cmd/cfusa/*.c` and
    `src/*.c`) that live in a file carrying at least one `//cfusa:req` tag
    (this repo's file-level tagging convention). `N=0` disables the gate;
    exit 1 when below `N`. Prints a "Function Coverage Report" listing
    `UNANNOTATED` functions (truncated at 20, same as `--req-coverage`).
  - Dangling-ID detection: a `//cfusa:test` or `//cfusa:sec-test` tag whose
    ID is not registered in `.fusa-reqs.json` now emits a `WARNING` to
    stderr (checked whenever a requirements registry was loaded), the same
    treatment as a malformed annotation per §1.4.

### Fixed (retrofit — issue #60)
- **Requirement-annotation retrofit of the `cmd/cfusa/*.c` CLI layer**: all
  29 previously-untagged command files (`cmd_badge.c`, `cmd_check.c`,
  `cmd_init.c`, `cmd_report.c`, `cmd_version.c`, `main.c`, `cmd_pr.c`,
  `cmd_fix.c`, `cmd_tara.c`, and 20 more) plus `cmd_capabilities.c` now carry
  a file-level `//cfusa:req` tag block. 10 new `REQ-CLI-*` requirement ids
  were minted for commands with no prior formal requirement
  (boundary/fmea/pr/tara/report/verify/version/main/template/sci); the rest
  were tagged with their existing matching requirement ids.
- **5 previously-untagged test files** (`test_engine.c`, `test_fusa_rules.c`,
  `test_config.c`, `test_report.c`, `test_utils.c`) now carry a file-level
  `//cfusa:test` tag block against new (`REQ-FUSA001`..`005`, `REQ-RPTCORE001`,
  `REQ-CFGCORE001`, `REQ-UTILCORE001`) or existing (`REQ-ENG001`..`005`)
  requirement ids describing what each file's tests actually exercise.
- **Closed all 18 requirement→test gaps** listed in issue #60 by adding or
  correcting `//cfusa:test` tags: `REQ-ISO21434-001`, `REQ-IEC62443-001`,
  `REQ-IEC62443-002`, `REQ-IEC62443-003`, `REQ-IEC62443-004`, `REQ-REQXML001`
  (strengthened the existing DOORS-ReqIF test to assert on parsed content),
  `REQ-REQXML002`/`003`/`004` (new Codebeamer/Jama/Polarion XML import
  tests — only CSV variants existed before), `REQ-DISP-SUBCMD001`/`002`/
  `REQ-DISP-ADD001`/`REQ-DISP-ACTION001` (existing `test_new_commands.c`
  tests were already exercising this exactly but were untagged),
  `REQ-MET-SUBCMD002`/`REQ-MET-REC001` (fixed two tests that were mistagged
  `REQ-MET-SUBCMD001`), `REQ-UNECE-OUT001`, `REQ-CYBER-SUMMARY001`
  (strengthened to actually capture and assert stdout), and
  `REQ-IEC62443-HEADER001` (new test). Note: `REQ-IEC62443-003`'s
  "recommended/partial" tri-state status is documented in the new test as
  currently unreachable given the built-in CR table only ever sets
  mandatory (1) or n/a (0) — a pre-existing, out-of-scope finding, not
  something this pass changed.
- **Registered 30 previously-dangling `//cfusa:test` requirement ids** that
  already existed as tags in `tests/test_cli_commands.c`, `test_commands2.c`,
  and `test_safety_commands.c` but were never added to `.fusa-reqs.json`
  (`REQ-DO178`, `REQ-VULN001-003`, `REQ-SCI001-002`, `REQ-COV001-002`,
  `REQ-SAS001-002`, `REQ-MET001-003`, `REQ-PR001-002`, `REQ-HOOK001`,
  `REQ-TMPL001-002`, `REQ-FIX001-002`, `REQ-VER001`, `REQ-BND001-002`,
  `REQ-VRFY001-002`, `REQ-TARA001-003`, `REQ-FMEA001-002`) — discovered by
  running the new dangling-ID check against this repo. A much larger body of
  pre-existing dangling test-tag ids remains across other test files
  (`REQ-CYB*`, `REQ-LINT*`, `REQ-RPT001-008`, `REQ-BADGE*`, `REQ-TRA*`,
  `REQ-UTIL*`, `REQ-CFG*`, and others) — out of scope for this pass; tracked
  as a follow-up.
- `.fusa-reqs.json` grows from 113 to 163 registered requirements; `cfusa
  trace --req-coverage 0` now reports 163/163 traced (up from 113/113 traced
  but with far less of the CLI surface actually covered by real
  `//cfusa:req` evidence).

## v0.5.40 — 2026-07-27

### Fixed
- **Coverage gate raised from 68% to 80%** in `.github/workflows/ci.yml`.

### Added
- **38 gap-coverage tests** in `tests/test_gap_coverage.c` covering previously
  untested code paths in nine low-coverage command modules:
  `cmd_diff` (parse\_report, find\_key), `cmd_fmea` (fmea\_line, infer\_severity,
  sev\_string, fmea\_file, all format/cyber variants), `cmd_badge` (badge
  rendering with and without a JSON report), `cmd_pr` (new\_pr, close\_pr, list),
  `cmd_impact` (load\_req\_ids), `cmd_vuln` (match\_word, vuln\_line, vuln\_file,
  output-dir and file output), `cmd_boundary` (boundary\_line, boundary\_file,
  mermaid/dot/text formats), `cmd_fix` (lookup\_fix, report output), and
  `cmd_sci` (sci\_file, json/md/text formats).
- Overall line coverage improved from 76.9% to **83.3%** (exceeds the 80% gate).

## v0.5.39 — 2026-07-27

### Fixed
- **[P0] CFUSA-L004 "no recursion" false positive on every function (issue #59)**
  The scanner ran the self-call check on the same line as the function's own
  signature (`void foo(void) {` always contains `foo(`), causing every
  multi-line function definition to be flagged as recursive.
  Fix: `fn_just_detected` flag skips the self-call check on the definition line.
- **[P1] CFUSA-L004 brace-depth mis-tracking inside comments and strings**
  Braces inside `/* block comments */`, `// line comments`, and string/character
  literals were counted, corrupting function-boundary tracking.
  Fix: replaced the raw brace loop with a comment- and string-aware parser;
  `in_block_comment` state persists across `fgets()` iterations.
- **SpecVersion updated** from "1.10.4" to "1.10.12" in `version.h`.

### Added
- **`disabled_rules` config key** — list rule IDs in `.fusa.json` to suppress
  them globally:
  ```json
  { "disabled_rules": ["CFUSA-L004"] }
  ```
  The engine skips disabled rules in both `run_all` and `run_category`.
  Adds `cfusa_config_is_rule_disabled()` to the config API.
- **5 regression tests** in `test_lint_rules2.c` covering the fixed cases:
  definition-line false positive, block-comment brace, string brace,
  real recursion still detected, and `disabled_rules` suppression.

## v0.5.38 — 2026-07-26

### Fixed
- **[P0] realpath buffer too small in cmd_init** — replaced `char resolved[512]` with
  `realpath(dir, NULL)` (dynamic allocation) to fix glibc `_FORTIFY_SOURCE=2` abort on
  ubuntu-22.04. `__realpath_chk` requires the destination buffer to be at least `PATH_MAX`
  (4096 bytes); the 512-byte stack buffer triggered `*** buffer overflow detected ***`
  during `cfusa init --docs --dir <path>` (test_init_docs_generates_templates), aborting
  all remaining CLI tests in the Release CI build.

## v0.5.37 — 2026-07-26

### Fixed
- **[P0] Engine cleanup in cmd_qualify** — added `cfusa_engine_reset()` at the end of
  `cmd_qualify()` so the global rule table is cleared after the qualification exercise
  suite. Without this, stale engine state referenced stack memory from helper functions
  (`qt_run_safety_rules`, etc.) that had already returned, causing glibc heap corruption
  detected as a `SIGABRT` in the test runner on Linux (ubuntu-22.04 CI).
- **[P2] CodeQL "Commented-out code" in cmd_coverage.c** — replaced the inline JSON
  format example in the `parse_mcdc_json()` block comment with an equivalent prose
  description, eliminating the false-positive CodeQL CWE alert.

## v0.5.36 — 2026-07-26

### Fixed
- **[P0] Security: cmd_qualify.c symlink/TOCTOU + CWE-78** — replaced `system("rm -rf " QTMP)`
  in `qt_setup()` with a new `qt_rmdir_recursive()` helper that uses POSIX `opendir`/`readdir`/
  `unlink`/`rmdir`. Eliminates CWE-78 (OS Command Injection), MISRA-C Rule 21.8, and the
  TOCTOU symlink-dereference window where an attacker could pre-place a symlink at `QTMP` to
  cause deletion of an arbitrary directory tree.
- **[P1] REQ-HLR004 annotation gap** — `cmd_trace.c` parentId loading (load_reqs), parentId
  JSON output (requirements[] emit), and `hlrllrSummary` block were attributed to REQ-HLR001.
  Changed inline comments to `//cfusa:req REQ-HLR004`. In `test_hlr_llr.c`,
  `test_json_output_has_parent_id` and `test_text_output_has_hlrllr_line` re-annotated from
  REQ-HLR001 to REQ-HLR004 so cfusa trace now surfaces these tests as evidence for REQ-HLR004.
- **[P1] test_qualify.c requirement annotations** — all 5 test functions were invisible to
  cfusa trace. Added `//cfusa:req` / `//cfusa:test` annotations:
  `test_qualify_text_qualified` and `test_qualify_json_qualified` → REQ-QUAL001/REQ-QUAL002;
  `test_qualify_verbose_qualified` → REQ-QUAL001; `test_qualify_output_file` → REQ-QUAL002;
  `test_qualify_help` → REQ-QUAL003. Added `#define _POSIX_C_SOURCE 200809L` per project style.
- **[P2] Dead variable in cmd_coverage.c** — removed unused `obj_start` declaration (line 55)
  and its `(void)obj_start` suppression cast (line 77) from `parse_mcdc_json()`.

## v0.5.35 — 2026-07-26

### Added
- **Feature 1 — HLR/LLR hierarchical traceability** (`cmd_trace.c`): `parent_id` field in
  `req_t` struct; `compute_hlr_llr()` function detecting orphaned LLRs (missing/invalid
  `parentId`) and uncovered HLRs (no LLR children). CLI `--strict-hlr-llr` flag gates on
  any violation (exit 1). Text renderer shows `HLR/LLR: N HLRs  N LLRs` summary line.
  JSON renderer adds `hlrllrSummary` object and emits `parentId` field on LLR requirements.
  Markdown renderer adds HLR/LLR summary table rows. 8 new tests in `test_hlr_llr.c`.
  (REQ-HLR001, REQ-HLR002, REQ-HLR003, REQ-HLR004; closes #48)
- **Feature 2 — Tool qualification display** (`cmd_qualify.c`): `--qualification-method`
  (self|independent), `--qualifier`, `--record-uri` CLI flags. `qualification_badge()`
  helper returns "independently-qualified", "self-qualified", or "unqualified". Badge and
  fields shown in text and JSON output. 9 new tests in `test_qualify_vv.c` covering
  Features 2 and 4. (REQ-QUAL003, REQ-QUAL006; closes #49)
- **Feature 3 — MC/DC coverage measurement** (`cmd_coverage.c`): `--mcdc-file` (path to
  LLVM coverage JSON export) and `--mcdc-threshold` (0–100, default 100) CLI flags.
  `parse_mcdc_json()` parses LLVM `mcdc_records`/`conditions` format. A condition is MC/DC
  covered when `covered_true_count > 0 AND covered_false_count > 0`. Gate fails when overall
  coverage falls below threshold. MC/DC-file-only mode skips lcov auto-detection. JSON output
  adds `mcdcReport` object. 8 new tests in `test_mcdc.c`. (REQ-COV015; closes #50)
- **Feature 4 — V&V independence declaration** (`cmd_qualify.c`): `--implementation-author`,
  `--independent-reviewer`, `--independent-test-executor`, `--achievable-asil` CLI flags.
  `independence_status()` helper returns "independent" when reviewer differs from author,
  "self-reviewed" when they are the same, "unqualified" when no reviewer is set. Fields
  included in JSON output. (REQ-VV001, REQ-VV004; closes #51)
- 9 new requirements registered in `.fusa-reqs.json`:
  REQ-HLR001–004, REQ-QUAL003, REQ-QUAL006, REQ-VV001, REQ-VV004, REQ-COV015.
- 3 new test files: `tests/test_hlr_llr.c` (8 tests), `tests/test_qualify_vv.c` (9 tests),
  `tests/test_mcdc.c` (8 tests). Total tests: 37 (was 34).

### Fixed
- `cmd_coverage`: Added macOS/BSD `optreset = 1` alongside `optind = 1` to ensure proper
  getopt state reset between multiple calls in the same process.
- `cmd_qualify`: Same `optreset` fix.

## v0.5.34 — 2026-07-25

- Fix CFUSA_SCHEMA_VERSION and CFUSA_SPEC_VERSION from "1.9" to "1.10.4"
- Add docker-publish.yml — publish ghcr.io/soundmatt/c-fusa on tag push

## [0.5.33] — 2026-06-13

### Fixed
- **`cfusa iec62443`**: Text output header changed from `"IEC 62443-4-2 Gap Report"` to `"IEC 62443 Gap Report"` so the canonical substring `"IEC 62443 Gap Report"` is present. Parity with go-FuSa `TestRunIEC62443_TextDefault`.

### Requirements
- REQ-IEC62443-HEADER001

## [0.5.32] — 2026-06-13

### Fixed
- **`cfusa comp`**: Text output now shows `"Total functions: N  Exceeding threshold: N"` summary line (was `"Functions: N  Violations: N  Max V(G): N"`). Parity with go-FuSa `TestRunComp_Text_NoExceedances`.
- **`cfusa comp`**: JSON output now includes top-level `"total"` and `"exceeding"` fields. Parity with go-FuSa `TestRunComp_JSON` / `TestRunComp_DALFlag`.
- **`cfusa req import`**: CSV empty file now exits 2; bad CSV header (first field not "id") exits 2; file not found exits 3. Parity with go-FuSa `TestRunReqImport_CSVEmptyFile`, `TestRunReqImport_CSVBadHeader`, `TestRunReqImport_CSVReadError`.
- **`cfusa fix`**: Added `--report <file>` flag that writes a JSON findings report. Parity with go-FuSa `TestRunFix_WithFindingsAndOutput`.

### Requirements
- REQ-COMP-TEXT001
- REQ-CLI-REQ002
- REQ-CLI-FIX001

## [0.5.31] — 2026-06-13

### Fixed
- **`cfusa cyber`**: Now always prints `"Cyber findings: N error  N warning  N info"` to stdout after analysis. Parity with go-FuSa `TestRunCyber_StrictWithWarnings` (cmd_v024e_test.go).

### Requirements
- REQ-CYBER-SUMMARY001

## [0.5.30] — 2026-06-13

### Fixed
- **`cfusa unece --output <file>`**: Now prints "UN R.155 gap report written to \<file\>" to stderr after writing. Parity with go-FuSa `TestRunUNECE_OutputFile` (§2.2: stdout stays empty, confirmation goes to stderr).

### Requirements
- REQ-UNECE-OUT001

## [0.5.29] — 2026-06-13

### Fixed
- **`cfusa hara` ASIL table**: Extended from 3-column (C1-C3) to 4-column (C0-C3) to match go-FuSa's `DetermineASIL`. C0 is now a valid controllability class (always one level less severe than C1). S2/E4/C2 now correctly yields ASIL-C (was ASIL-B), S2/E4/C3 → ASIL-D (was ASIL-C), etc.
- **`cfusa hara asil`**: Accepts `Sx`/`Ex`/`Cx` prefix format (e.g. `--severity S2 --exposure E4 --controllability C2`). Parity with go-FuSa `TestRunHara_ASIL`.
- **`cfusa hara asil`**: Missing `--severity`/`--exposure`/`--controllability` now returns exit 2 (was exit 1). Parity with go-FuSa `TestRunHara_ASIL_MissingFlags`.
- **`cfusa hara init`**: Returns exit 2 with "already exists" in stderr when `.fusa-hara.json` already exists. Parity with go-FuSa `TestRunHara_InitAlreadyExists`.
- **`cfusa hara <unknown>`**: Unknown subcommand now returns exit 2. Parity with go-FuSa `TestRunHara_UnknownSubcommand`.

### Requirements
- REQ-HARA-ASIL-C0001
- REQ-HARA-INIT-EXISTS001
- REQ-HARA-SUBCMD001

## [0.5.28] — 2026-06-13

### Fixed
- **`cfusa slsa --level L1/L2/L3/L4`**: SLSA level flag now accepts the `Lx` prefix format in addition to bare integers. Previously `--level L1` was parsed by `atoi()` as 0, causing exit 2 (invalid level). Parity with go-FuSa `TestRunSLSA_AllLevels`.
- **`cfusa slsa` text header**: Changed "SLSA v1.0 Gap Report" → "SLSA Supply-Chain Gap Report" for consistency with go-FuSa output and spec-level language.
- **`cfusa slsa --output <file>`**: Now prints confirmation "SLSA gap report written to \<file\>" to stderr after writing. Parity with go-FuSa `TestRunSLSA_OutputFile`.
- **`cfusa iec62443 --output <file>`**: Now prints confirmation "IEC 62443 gap report written to \<file\>" to stderr after writing. Parity with go-FuSa `TestRunIEC62443_OutputFile`.

### Requirements
- REQ-SLSA-LEVEL001
- REQ-SLSA-OUT001
- REQ-IEC62443-SL001
- REQ-IEC62443-OUT001

## [0.5.27] — 2026-06-13

### Fixed
- **§2.2 spec compliance** (`cfusa unece`, `cfusa iso21434`, `cfusa comp`): when `--output <file>` is given, no text is written to stdout. Previously these three commands printed a "written to" confirmation message to stdout, violating spec §2.2 ("stdout MUST be empty when --output is given"). Parity with go-FuSa `TestConform_OutputNoStdout_*` tests.

### Requirements
- REQ-SPEC22-001

## [0.5.26] — 2026-06-13

### Fixed
- `cfusa do178 --dal DAL-Z` (invalid DAL) now returns exit 2 (usage error) instead of exit 1. Parity with go-FuSa `TestRunDo178_InvalidDALv2`.
- `cfusa do178 --dal DAL-A` prefix format now parsed correctly — previously `DAL-A` was silently misread as DAL-D because only the first character was checked. Accepted values: `a|b|c|d` or `DAL-A|DAL-B|DAL-C|DAL-D` (case-insensitive).

### Requirements
- REQ-DO178-DAL001

## [0.5.25] — 2026-06-13

### Added
- `cfusa sign --keygen <path>` generates a 32-byte random key (64 hex chars) and writes it to `<path>`, overwriting any existing file. Prints "Key written to \<path\> (keep this secret)". Returns exit 3 on write error. Parity with go-FuSa `TestSignKeygen_*` tests.

### Requirements
- REQ-SIGN-KEYGEN001

## [0.5.24] — 2026-06-13

### Added
- `cfusa trace --req-coverage` now implements two metrics matching go-FuSa parity:
  - Metric 1 — Requirement traceability: % of requirements with implementation traces
  - Metric 2 — Function annotation density: % of non-static functions in annotated `.c` files
- Output header "Requirement Coverage Report" with UNTRACED/UNANNOTATED listings
- UNANNOTATED listing truncated at 20 entries with "... and N more"
- N/A shown for each metric when no requirements or no functions exist
- `--req-coverage 0` disables the gate and shows the regular trace matrix
- Stderr gate-failure messages distinguish "metric 1" vs "metric 2"

### Requirements
- REQ-REQCOV-M2-001, REQ-REQCOV-NA-001, REQ-REQCOV-ZERO-001, REQ-REQCOV-TRUNC-001

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

## [0.2.1] — 2026-06-10

### Added
- `req import` — ALM formats DOORS/Polarion (ReqIF XML), Codebeamer, and Jama,
  auto-detected from the `.reqif` extension or selected explicitly via
  `--format`
- `coverage --mutate` / `--mutate-score` — DO-178C MC/DC mutation-testing
  evidence (mutation-only mode; reads the `score` field from
  `mutation-report.json` automatically)
- 3 new commands added in the v0.2.0 alignment pass: `coupling`, `iso21434`,
  `unece`

### Changed
- JSON schema aligned to camelCase throughout (`generatedAt`, `ruleId`,
  `infos`)
- `disposition`: `--reviewer`, `--action`, `--ref` flags aligned with go-FuSa
- Docker: `alpine:3.20`, Ninja, `/project` workdir
- Test suite expanded to 28 suites

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
[0.3.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/SoundMatt/c-FuSa/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/SoundMatt/c-FuSa/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SoundMatt/c-FuSa/releases/tag/v0.1.0
