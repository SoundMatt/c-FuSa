# Changelog

All notable changes to c-FuSa are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.6.2 — 2026-08-18

Architecture-plan loop: eleven tracked improvement issues (#203–#213),
eight shipped across eight PRs (#215–#218, #220–#223); #206/#207
deliberately deferred per their own issue scoping; #211 (Windows/MSVC)
resolved as a scoping decision rather than an implementation — see
below. Minor-version-worthy in spirit (new user-facing flags/commands),
kept as a patch bump per policy. 47/47 test suites pass, self-check
clean (0 errors).

### Added
- **A shared, comment/string-literal-aware line-stripping primitive**
  (`cfusa_lex_strip_line()`, `include/cfusa/lex.h`/`src/lex.c`) replacing
  ad hoc per-rule comment/string state machines — space-blanks (never
  deletes) comment/string content so column positions are preserved and
  tokens never glue together across a stripped comment. (#203)
- **A single tree-walk / single file-read engine for line-scan rules**
  (`cfusa_engine_register_line_rule()` / `cfusa_engine_run_line_rules()`)
  — collapsed 54 independent `cfusa_walk_sources()` call sites (one per
  rule) into one walk-and-dispatch pass per `cfusa check`/`lint`/
  `analyze`/`cyber` run. (#204)
- **`#if 0` preprocessor-lite awareness** — code inside an
  unconditionally-disabled `#if 0` block is no longer scanned by
  line-based rules, removing a class of false positives on intentionally
  dead/documentation code. (#205)
- **`cfusa baseline`** and `.fusa-baseline.json` — snapshot a project's
  current findings to exclude them from the exit-code gate, so an
  existing codebase can adopt c-FuSa without gating on its full
  pre-existing backlog. Composes with `.fusa-dispositions.json`. (#208)
- **`cfusa check --changed-since <git-ref>`** — scopes a report to only
  findings on lines actually changed since `<ref>` (via `git diff
  --unified=0`), for gating a pull request on newly-introduced findings
  rather than a project's full existing backlog. Independent of, and
  composable with, baseline/dispositions. (#209)
- **`cfusa fix` remediation-guidance coverage expanded from 19 to the
  full 39 lint/analyze/cyber rules**, plus a real `--dry-run`/`--apply`
  auto-rewrite for `CFUSA-CY006` (free-without-NULL) — conservatively
  scoped to a bare `free(<simple-lvalue>);` call, and safe to re-run
  since it skips a pointer already NULL'd on the next line. (#210)
- **`cfusa explain <RULE-ID>`** (and `cfusa explain --list`) — prints a
  rule's category, standard/clause citation, description, and remediation
  guidance in one place; rule-id lookup is case-insensitive and tolerates
  a missing `CFUSA-` prefix. (#212)
- **A first-party GitHub Action** (`action.yml`, usable as `uses:
  SoundMatt/c-FuSa@<tag>`) — installs a pinned `cfusa` release binary,
  runs `cfusa check`, and uploads SARIF to the code-scanning tab, with
  `dir`/`version`/`strict`/`changed-since`/`fail-on-error` inputs.
  Dogfooded against this repo itself in CI
  (`.github/workflows/action-smoke-test.yml`). (#213)

### Documented
- **Windows/MSVC support was audited and deliberately deferred, not
  implemented.** `fork()`/`pipe()`/`execvp()` subprocess spawning (4
  files), the `opendir()`/`readdir()`-based tree walk underlying every
  rule, and `getopt_long` (all 44 `cmd_*.c` files) have no direct Windows
  equivalent — this is a systemic, cross-cutting port, not a bounded
  feature. WSL2 already runs today's `cfusa` unmodified and is the
  recommended path; see issue #211 for the full audit and rationale.

## v0.6.1 — 2026-08-18

Forty-three fixes from a 40-agent deep-audit sweep of the codebase
(#141–#182) plus one more found and fixed the same session (#187).
Patch version bump — precision/correctness fixes only, no new
user-facing flags or behaviors. Every fix ships with regression tests
verified to fail against the pre-fix code and pass against the fix;
44/44 test suites pass and the self-check is clean.

### Fixed
- **Disposition JSON loading was brittle to incidental whitespace**
  around field values in `.fusa-dispositions.json`/`.fusa-qualitybar.json`/
  HARA files — replaced ad hoc field extraction with a shared
  whitespace-tolerant JSON string-field helper. (#143, #159, #175, #176)
- **`cfusa disposition add` wasn't atomic and could corrupt the
  dispositions file under concurrent writes**, and didn't handle a
  bare-array file shape. Now writes via a locked, atomic
  temp-file-plus-rename, with a bare-array merge fallback. (#144, #158)
- **DISP001 matched on a whole-file substring instead of the real
  fingerprint-scoped disposition mechanism**, so an unrelated finding
  whose message happened to mention a disposed rule id could be wrongly
  suppressed. (#148)
- **`project_root` wasn't set consistently across commands**, so the
  same finding could get different fingerprints depending on which
  command produced it — breaking cross-command disposition matching.
  (#153)
- **`cmd_req.c` resolved the wrong requirements filename in some code
  paths, `--sec-tested` didn't gate on the real tested count, and
  Metric 1 could disagree with the underlying data.** Canonical
  `.fusa-reqs.json` resolution with legacy fallback; a real
  `--sec-tested` gate. (#146, #147, #166)
- **Five CFUSA-CY rules (CY003/CY004/CY006/CY007/CY019) matched
  dangerous-function names without identifier-boundary checks**,
  false-positiving on any name merely containing the pattern as a
  substring. Switched to a shared boundary-aware matcher
  (`cfusa_find_token_outside_string()`). (#154, #155, #156, #157, #173)
- **`cmd_lint.c`'s L001/L002/L003/L006 had precision and safety gaps**:
  L001's `strncpy` could leave an unterminated buffer; L002 only matched
  `goto` when it started the line; L003/L006 had no persistent
  block-comment tracking across lines, so multi-line comments without a
  leading `*` on continuation lines were scanned as code. (#161, #162,
  #163, #177)
- **The legacy `REQ:` scanner and `cfusa_config_is_excluded()` matched
  substrings without boundary checks**, e.g. excluding `src/rebuild_utils.c`
  purely because it contains "build". Anchored to identifier/path-segment
  boundaries. (#174, #180)
- **`cmd_analyze.c`'s A001/A003/A006/A007 had false-positive/negative
  precision issues**: A003 missed multi-declarator lines, A006 matched
  pointer-arithmetic incorrectly, A007 missed some unchecked-`fclose`
  sites. (#149, #150, #151, #169)
- **Silent-truncation trio**: `cfusa coverage`'s lcov parser could
  misread an empty/unreadable file as 100% coverage; the HLR/LLR arrays
  were capped at a fixed 512 entries with no warning; HARA's nested
  reference arrays silently dropped entries past their cap. All three
  now fail loudly or warn instead of silently under-reporting. (#142,
  #160, #167)
- **`report.c` had internal-consistency and formatting gaps**: the
  printed Result line didn't account for `--strict`; summary
  tables/top-rules didn't exclude dispositioned findings; JSON/CSV
  output had buffer-sizing and escaping issues. A new RFC 4180 CSV
  writer was added. (#164, #165, #178, #179)
- **A failed report write silently exited 0** instead of the documented
  exit code 3. (#141)
- **`cmd_hara.c`'s top-level JSON parsing was key-order-dependent** —
  reordering `operationalSituations`/`hazards`/`safetyGoals` in the
  source file could scope a scan incorrectly. Fixed via depth-1-bounded
  bracket matching that no longer depends on key order. (#145)
- **`cfusa_config_save()` only persisted the first declared standard**
  when multiple were set via `--standard a,b`, silently dropping the
  rest on every re-save. (#168)
- **`--dal DAL-D` silently discarded an explicit `--threshold`**
  (zeroing it instead of leaving it alone, asymmetric with how
  `--asil QM` already behaves), and **`--dal DAL-A`/`--asil ASIL-D`'s
  100%-MC/DC requirement wasn't reflected in `--mcdc-threshold`**,
  letting a weaker explicit threshold silently pass. (#152, #172)
- **Only 3 of the ~41 commands' `getopt_long` loops fully reset BSD's
  `optreset`/glibc's `nextchar`** between invocations — a bare
  `optind = 1` doesn't fully clear either, risking stale-state misparses
  across the repeated, in-process invocation pattern this project's own
  test suite (and any embedding caller) uses. Applied the full
  platform-reset block to every command. (#170, #171)
- **COUP001's `extern`-variable match was unanchored and
  comment-unaware**, false-positiving on prose mentioning "extern"
  inside a multi-line comment continuation line; **COUP001/COUP002/
  COMP001 all hardcoded `return 0`** regardless of findings added,
  breaking the `run()`-returns-finding-count contract every other rule
  follows. (#181, #182)
- **CFUSA-L004's recursion detector had no comment-awareness**,
  misreporting a function as recursive when a comment inside its body
  merely mentioned its own name. (#187)

## v0.6.0 — 2026-08-18

Nine fixes: seven from an open-issue sweep (#128, #124, #126, #97, #127,
#125, #122) plus two more (#129, #137) found and fixed the same session.
Minor version bump — includes new user-facing flags/behaviors, not just
bug fixes.

### Fixed
- **`cfusa qualify`'s `qualified`/`qualificationBadge` JSON fields could
  disagree** (`qualified: true` next to `qualificationBadge:
  "unqualified"`) since they were computed independently. `qualified` now
  requires both passing self-tests AND a declared `--qualification-method`.
  (#128)
- **`cmd_hara.c`'s `split_array()` silently dropped any hazard/safety-goal
  JSON element >=511 bytes** (fixed 512-byte stack buffer, no warning) — a
  real HARA document could read 0 hazards. Now heap-allocates each element
  at its exact length; the (generous) entry-count cap now warns instead of
  silently truncating. (#124)
- **CFUSA-A003 (signed/unsigned vs `sizeof`, CERT INT02-C) was a
  near-100% false-positive rate on real code** — purely syntactic, no type
  awareness. Now does a two-pass scan for locally-visible
  `size_t`/unsigned-family names before flagging; self-scan on this repo
  went from 22 to 2 findings. (#126)
- **`cfusa safety-case` hardcoded exact lowercase evidence filenames**
  (`hara.md`, `safety-plan.md`, etc.), case-sensitive via `stat()` — broke
  on Linux CI/release for projects naming files e.g. `HARA.md`. New shared
  `cfusa_find_file_ci()` does a real case-insensitive directory-listing
  match. (#97)
- **`cfusa coverage --mcdc-file` parsed a schema that never matched real
  `llvm-cov export` output**, so every genuine export reported 0 MC/DC
  conditions. Fixed and verified against an actual captured `llvm-cov
  export` run (both a fully-covered and zero-covered case). (#129)

### Added
- **`cfusa fix` remediation guidance for CFUSA-CY006** (free-without-NULL,
  CWE-416/CERT-C MEM30-C). (#127)
- **`cfusa trace --func-coverage-strict`** — a genuinely per-function
  annotation-density gate (a `//cfusa:req` tag directly above the
  function's own definition), additive alongside the unchanged file-level
  `--func-coverage`. (#125)
- **`.fusa-dispositions.json` is now enforced, not just logged.**
  `cfusa check`/`cfusa lint` load it and exclude accept/mitigate-action
  findings (matched by fingerprint, never rule-wide) from the exit-code
  gate — the finding stays visible, tagged inline, and its own summary
  bucket. `cfusa disposition add --fingerprint <sha256:...>` is new.
  (#122)
- **`cfusa coverage --branch-threshold <pct>`** — an independent
  branch-coverage regression floor, separate from `--threshold`'s
  line-only gate; acts as a floor alongside `--dal`/`--asil` (never
  weakens their fixed-100% branch requirement, only raises it if
  stricter). (#137)

## v0.5.54 — 2026-08-14

Three fixes from a direct quality review: unchecked `fclose()` return values,
a CFUSA-A006 false-positive class, and CFUSA-L003 precision + ASIL-scaled
severity.

### Fixed
- **All previously-flagged CFUSA-A007 (`unchecked fclose()`) sites now check
  the return value.** 39 sites across 9 files touched this session; product
  code gets real error handling (`perror`/`fprintf(stderr, ...)`), test code
  fails loudly via `TEST_FAIL_MESSAGE`.
- **CFUSA-A006 ("pointer arithmetic") no longer fires on coincidental,
  unrelated `*`/`++`/`--`/`+=`/`-=` co-occurrence on the same line.** Was a
  same-line-proximity heuristic with no correlation check between the
  dereferenced/declared pointer and the incremented variable; now requires
  the same identifier on both sides. Project-wide: 545 → 141 findings (a 74%
  reduction), each verified by hand as a genuine unrelated-token coincidence,
  not a missed real finding.
- **CFUSA-L003 ("dynamic memory") no longer fires on custom `_free()`-suffixed
  functions or string-literal text.** Was a plain substring match, so
  `free(` also matched inside e.g. `cfusa_report_free()`. Project-wide:
  464 → 133 findings (61% were this false-positive class).
- **CFUSA-L003 severity is now ASIL-scaled.** ISO 26262-6 lists avoiding
  dynamic memory allocation as "highly recommended" at ASIL-C/D but only
  "recommended" at QM/A/B; a declared ASIL-C/D project now gets a hard
  `SEV_ERROR` instead of the uniform `SEV_WARNING` every project got before.
  Shared `cfusa_declared_asil_rank()` (moved from a `cmd_misra.c`-local
  helper into `severity.h`) so this and the accredited-tool note (v0.5.52)
  don't drift independently.

### Logged, not yet built
- Issue #122: wire `.fusa-dispositions.json` into `cfusa check`/`lint`
  enforcement. Dispositions are currently a standalone audit log — logging
  one doesn't suppress the finding or affect the exit-code gate.

## v0.5.53 — 2026-08-13

Two MC/DC gate honesty fixes, found during a direct quality review of c-FuSa's
MC/DC support (not filed as a separate issue — fixed on request).

### Fixed
- **`cfusa coverage --mcdc-file` no longer silently passes on an empty
  parse.** A file that parses to zero MC/DC condition records used to
  return a PASS ("nothing to fail") — indistinguishable, purely from
  content, from a wrong path, a truncated file, or a future LLVM
  export-format change the tool's string-scan no longer recognizes. Same
  failure shape as the `MAX_REQS` silent-truncation bug (v0.5.51, issue
  #100): incomplete data must never read as complete. Now fails loudly
  with a diagnostic note; the report also no longer shows a contradictory
  `100.00% (0/0 conditions) FAIL`.
- **The branch-coverage MC/DC fallback is now honestly labeled.** Without
  `--mcdc-file`, the DAL-A/ASIL-D-required MC/DC gate falls back to
  treating 100% branch coverage as a proxy — but the output was labeled
  "MC/DC analysis", which is materially misleading: 100% branch/decision
  coverage does not establish that every condition within a decision
  independently affects its outcome (the entire reason MC/DC exists as a
  distinct, stricter metric). Now: a stderr `WARNING` whenever the proxy
  is used, the text label changed to "MC/DC gate (branch-coverage
  proxy — NOT verified MC/DC)", a machine-readable
  `"mcdcProxy": {"verified": false, ...}` JSON field, and `--help` text
  spelling out the distinction.

## v0.5.52 — 2026-08-13

ASIL-scaling initiative (issue #103, sub-issues #104-#109). c-FuSa correctly
derived ASIL but didn't scale the rigor ISO 26262 actually escalates at
higher ASIL levels — MC/DC coverage, independent review/test, and
complexity/rule strictness were either DO-178C-DAL-only or inert metadata.
Checked against both the x-FuSa master spec and its Go reference
implementation (FuSaOps) before starting: neither mandates or implements
this either, so this is c-FuSa leading the tool family, not catching up
to a spec requirement.

### Added
- **Shared ASIL/DAL severity helper** (`include/cfusa/severity.h`,
  `src/severity.c`, #104): `cfusa_dal_rank()`, `cfusa_asil_rank()`, and
  `cfusa_required_severity(enforce, dal, asil, &sev)` — one canonical
  "how strict should this gate be" derivation (an `--enforce
  auto|error|warn|off` convention), modeled on FuSaOps'
  `trace.SeverityForDecomposition`. `cmd_safety_rules.c`'s local
  `asil_rank()` (HARA005) migrated onto it as a proof of the API shape.
- **`cfusa qualify --project-asil` / `--enforce`** (#105): `achievableAsil`
  is now *computed* from `--implementation-author`/`--independent-reviewer`/
  `--independent-test-executor` (ISO 26262-8 §11 ceiling logic: no
  independent reviewer → ASIL-B, reviewer only → ASIL-C, reviewer +
  test executor → ASIL-D; self-attestation doesn't count) instead of
  accepted as a free-input string, and the command now **fails** when the
  computed ceiling is below a declared `--project-asil`. **Breaking:**
  removes the previously-inert `--achievable-asil` flag.
- **`cfusa coverage --asil QM|ASIL-A|ASIL-B|ASIL-C|ASIL-D`** (#106):
  ISO 26262-6 Table 12 structural-coverage/MC/DC gate, mirroring `--dal`'s
  four-tier shape (ASIL-D requires MC/DC, ASIL-C requires full branch
  coverage, ASIL-A/B require full line coverage, QM has no requirement).
  When both `--dal` and `--asil` are given, the stricter of the two
  applies to each of line/branch/MC/DC independently.
- **`CFUSA-L011`/`CFUSA-L012` lint rules** (#108): octal constants
  (MISRA-C 2012 Rule 7.1) and macros named the same as a C keyword
  (Rule 20.4). `cfusa misra`'s accredited-third-party-tool recommendation
  now escalates to `REQUIRED` (not `RECOMMENDED`) when the project
  declares ISO 26262 ASIL-C/D — the recommendation itself is unchanged,
  only its stated strength scales with declared criticality.
- **`docs/standards/iso26262.md`** (#109): command mapping, ASIL
  derivation, what scales by ASIL today, and an explicit statement of
  what doesn't — no programmatic Tool Confidence Level (TCL, ISO 26262-8
  Tables 4-5) determination exists anywhere in c-FuSa (or the wider
  x-FuSa family) yet. Every command in its workflow example was run
  against a real build before being written down.

### Fixed
- **`check`'s automatic `COMP001` gate now recognizes ISO 26262 ASIL**
  (#107): previously only DO-178C DAL tags in `.fusa.json`'s
  `standards[]` were recognized, so an ISO-26262-only project silently
  got the unscaled default complexity threshold instead of the
  ASIL-appropriate one (matching `cfusa comp --asil-d/c/b/a`'s existing
  table), unless it separately ran `cfusa comp` by hand. When both a DAL
  and an ASIL are declared, the stricter threshold wins.

## v0.5.51 — 2026-08-13

Fixes issue #100: silent, uncapped-looking data loss in the three commands
`check`/CI treat as the safety-traceability source of truth.

### Fixed
- **`cmd_req`/`cmd_trace`: silent requirement-catalog truncation
  (`MAX_REQS`).** `.fusa-reqs.json`'s `requirements` array was parsed into a
  fixed 1024-entry stack array (`g_reqs`); the parse loop simply stopped
  once it was full, with no error, warning, or truncation notice of any
  kind. A project whose requirement catalog grew past 1024 entries got a
  **false 100% coverage / 0-errors reading** from `cfusa trace`/`cfusa
  check`, because every requirement past the cap was never loaded at all —
  it could never be reported missing, untested, or dangling. Reproduced
  concretely against a 1075-entry catalog: `cfusa trace` reported
  `1024/1024 requirements traced` (should be `1075/1075`), and a real,
  correctly-tagged requirement past the cap was flagged as a dangling test
  reference despite existing in the file.
- **`cmd_impact`: same bug, `MAX_REQS=256`.** `load_req_ids()` capped the
  requirement-id list at a fixed 256 entries with the same silent-stop
  behavior, so a requirement past the cap could never be matched against
  changed files in `cfusa impact`'s change-impact analysis.
- **`cmd_req`/`cmd_trace`: same bug, `MAX_TAGS=4096`.** The `//cfusa:req`/
  `//cfusa:test`/`//cfusa:sec-test` annotation array (`g_tags`) had the
  identical fixed-cap/silent-stop pattern. Since a fully-traced requirement
  needs at least one (usually two) tags, tag count grows faster than
  requirement count — this cap could silently under-report coverage well
  before the (now-uncapped) requirements array itself filled up.
- All four arrays now grow dynamically via `realloc` with no fixed cap,
  bounded only by available memory. A genuine allocation failure (OOM) —
  the only way a load can now be incomplete — is reported as a hard
  `ERROR` to stderr with a non-zero exit code, so a truncated run can never
  be silently mistaken for a complete one.

## v0.5.50 — 2026-07-30

_Renumbered from v0.5.49: the tag/release `v0.5.49` had already been
published (2026-07-29, PR #93) against a commit whose `version.h` still
read "0.5.48" — a pre-existing off-by-one in that release, unrelated to
this change. To avoid re-using an already-shipped version string, this
release is v0.5.50 instead._

External third-party audit remediation. Two of the findings are
**live-exploitable command/argument-injection vulnerabilities**, independently
reproduced against the shipped tool before being fixed here; the rest are
correctness/robustness defects in the ASIL derivation table, its test
coverage, and several `check`/`trace`/`report` code paths.

### Security
- **`impact` git-ref argument injection.** `cmd_impact.c`'s `--from`/`--to`
  validator accepted a value beginning with `-` and built the underlying
  `git diff` invocation with no `--` separator between refs and paths. A
  crafted `--from` value could smuggle an arbitrary `git diff` flag —
  reproduced concretely with `cfusa impact --from '--output=victim.txt' --to
  HEAD`, which truncates `victim.txt` via git's own `--output` flag. Refs
  beginning with `-` are now rejected, and a `--` separator is always
  inserted before the ref arguments. While hardening this path, `run_git_diff()`
  was also moved off `popen()`/a shell command string onto `fork`+`execvp`
  (argv passed directly, no shell), removing the shell entirely rather than
  just refusing to abuse it.
- **`audit-pack` shell command injection.** `cmd_audit_pack.c` interpolated
  unsanitized `--output`/`--dir` values into a double-quoted
  `system("cd ... && zip ...")` string; `$(...)` command substitution is
  still expanded inside double quotes by the shell, so a crafted `--output`
  executed arbitrary commands — reproduced concretely with `cfusa audit-pack
  --output 'x.zip$(touch /tmp/pwned)'`. The `system()`/`zip`/`rm -rf` shell
  pipeline has been replaced with `fork`/`execvp` (argv passed directly, no
  shell interpretation) and a POSIX `nftw()`-based recursive remove for
  staging cleanup.

### Fixed
- **ISO 26262-3:2018 Table 4 ASIL derivation corrected (Critical).** The
  shared `cfusa_compute_asil()` table (`src/asil.c`) over-assigned ASIL in 19
  of 36 S×E×C cells (all S2 except the E1 row, and every S3 row). It now
  implements the additive S+E+C mapping (≤6 → QM, 7 → A, 8 → B, 9 → C, 10 →
  D). `tests/test_asil_table.c`'s "exhaustive" 36-cell test previously only
  asserted `exit == 0` and never the returned ASIL string, so it passed
  against the wrong table; it now asserts the exact ASIL for every cell. The
  dogfooded `.fusa-hara.json` shipped over-classified hazard ASILs (H-001
  through H-005) as a direct consequence of the table bug and has been
  regenerated to match. NOTE: the v0.5.47 entry below described the table as
  making both call sites "provably consistent" — they were consistent with
  each other but consistently wrong until this fix.
- **C0 controllability now maps to QM.** A non-standard `C0` ("controllable
  in general") value previously fell through to a non-QM result; per ISO
  26262-3:2018 §4.3.5 it now short-circuits `cfusa_compute_asil()` to QM
  regardless of S/E.
- **Out-of-range S/E/C now rejected.** `hara` previously coerced an
  out-of-range severity/exposure/controllability value to QM silently; it
  now exits 2 with a diagnostic instead of masking a malformed hazard entry.
- **Duplicate requirement ids now fail `check`.** A duplicate `id` in
  `.fusa-reqs.json`/`.cfusa-reqs.json` was previously only reported as a
  `cfusa trace: ERROR: ...` line on stderr, never as a machine-readable
  `Finding`, and never affected any command's exit code. A new `check`
  engine rule, `DUPREQ001`, re-parses the requirements registry and emits a
  real, fingerprinted §4 Finding (SEV_ERROR) for each duplicated id, so
  `cfusa check` now fails on it.
- **`trace` reads the canonical `parent` key.** `cmd_trace.c` read only the
  legacy `parentId` field for LLR→HLR links; it now reads the spec-canonical
  `parent` key first, falling back to `parentId` for backward compatibility.
- **Report envelope no longer hardcodes an always-empty `errors` array.**
  `src/report.c` emitted a permanently-empty `"errors": []` array in every
  report; per the x-FuSa spec this MUST be a singular `error{code,message}`
  object present only when a runtime error occurred (and omitted
  otherwise), which is now what's emitted.
- **`ftell()` return value now bounds-checked.** `cfusa_read_file()`
  (`src/utils.c`) used an unchecked `ftell()` result as an allocation size;
  on a crafted or unseekable file this could wrap to a huge or negative
  value and cause a heap-overflow/DoS. The result is now validated before
  use.
- **Requirement objects over 1KB no longer truncated.** `cmd_trace.c`
  parsed each requirement object into a fixed 1024-byte stack buffer,
  silently dropping `id`/`title`/`parent` fields past that size; it now
  heap-allocates to the exact object length.
- **`.fusa.json` version string reconciled.** `project.version` had drifted
  to a stale `"0.5.1"` while the shipped tool moved well past it; it now
  matches the real released version. (The README's config-name guidance was
  also updated to point at the canonical `.fusa-*` names rather than the
  deprecated `.cfusa-*` ones, with the legacy names kept as a documented
  fallback; a version badge was added to README so the new
  version-consistency CI check has something real to verify against.)
- **`cfusa check` now passes cleanly on c-FuSa's own source** (previously
  masked by `|| true` in CI — see Changed, below — so this had silently
  regressed): `cmd_qualify.c`'s pre-existing `qt_rmdir_recursive()` and the
  new `cmd_audit_pack.c` `ap_rmdir_recursive()` both used genuine user-code
  recursion (MISRA-C 2012 Rule 17.2, `CFUSA-L004`); both are now iterative,
  built on POSIX `nftw(FTW_DEPTH|FTW_PHYS)`. `cmd_comp.c` had two lines each
  freeing two distinct pointers, which a same-line text scan mistook for a
  double-free (`CFUSA-CY007`); the frees are now on separate lines. Two test
  function names — `..._includes_end_line` and `..._no_build_system` —
  coincidentally contained the substrings `des_` and `system(`, false-firing
  the weak-crypto and unchecked-system-call rules (`CFUSA-CY009`/`CY003`);
  both were renamed.
- **`cmd_req.c`'s ALM-import entry builder hardened against unbounded
  write.** `append_entry()` (used by `req import` for CSV/ReqIF/XML sources)
  tracked the destination buffer's fill level via a caller-passed running
  total rather than the buffer's actual content length, and appended with
  `strcat()`. GitHub Advanced Security's CodeQL flagged this as a possible
  unbounded write from `fgets`/`fread`-sourced input (critical). It's
  rewritten to measure the buffer's real length directly and append with an
  exact-length `memcpy()` bounded against that, removing the dependency on
  the caller's bookkeeping entirely.

### Changed
- `qualify`'s qualification timestamp now honours `SOURCE_DATE_EPOCH` for
  reproducible builds.
- CI (`ci.yml`) no longer masks 5 meaningful steps behind `|| true`,
  including the version-consistency check, which now actually fails the
  build on drift. The `iso26262` gap-report step is intentionally left
  informational (`|| true`): it exits 1 whenever any §9.3 gap remains by
  design, and closing every long-standing documentation/process gap (e.g.
  "functional safety concept", "no multiple exit points") is a separate,
  much larger effort than this release's scope. The Docker self-check step
  now checks the whole mounted repo (`--dir /workspace`) instead of just
  `/workspace/src`, matching the native self-check step — `src/` alone can
  never contain the root-level `.fusa.json`/`.fusa-hara.json`, so scoping to
  it made `FUSA00x`/`HARA001` fail unconditionally the moment this step's
  exit code started being enforced.
- `docker-publish.yml`'s runner is pinned to `ubuntu-22.04` for
  build-environment parity/reproducibility.

### Removed
- The stale committed `.cfusa_qualification.json` (wrong version, obsolete
  schema) has been deleted; CI regenerates it as a build artifact instead of
  it being tracked in source control.

## v0.5.47 — 2026-07-28

x-FuSa spec v1.15.0 adoption + deep-audit bug-fix sprint (issues #73-80):
`hara`/`fmea`/`tara`/`sci` schema-conformance fixes found by running the
tool against its own codebase and diffing real output against the spec.

### Added
- **HARA006 `check` engine rule.** `risk.asil` is now cross-checked against
  the ISO 26262-3 Table 4 S x E x C derivation both as a `check`-gating
  `Finding` (HARA006) and in `hara --format json`'s new
  `completeness.asilMismatches` count — previously the mismatch only
  surfaced as a `hara show` (text) warning line that never affected any
  exit code or machine-readable output (#74). The S x E x C table itself is
  now `src/asil.c`'s shared `cfusa_compute_asil()`, used by both call sites
  instead of a copy local to `cmd_hara.c`.
- **`hara --format json` verbatim passthrough.** `hazards[].source`/
  `situations`/`safetyGoals` and `safetyGoals[].hazards`/`safeState` are no
  longer silently dropped, and a document-level `attestation` (when present
  in `.fusa-hara.json`) is now passed through — closing the gap between
  what `hara show` (text) already displayed and what a consumer of the
  JSON contract could actually see (#73).
- **`cfusa fmea --output <file>`.** `fmea` previously defined only
  `--output-dir <dir>`, so GNU `getopt_long`'s unambiguous-prefix matching
  silently treated `--output <path>` (the exact form the CLI synopsis in
  §9.2 documents) as an abbreviation of `--output-dir`, writing a bogus
  `<path>/fmea.json` and failing with a confusing error instead of either
  working or rejecting cleanly (#79).
- Shared `src/utils.c` helpers: `cfusa_relativize_path()` (the one
  canonical project-relative-path implementation, replacing ad hoc copies
  in `cfusa_report_add()`/`cmd_trace.c`), `cfusa_is_test_source_file()`,
  `cfusa_is_stdlib_call()`, and `cfusa_extract_call_name()` — the last two
  centralise the "does this line look like a real call/definition site"
  heuristic previously duplicated (and independently under-guarded) in
  `cmd_fmea.c`'s `fmea_line()` and `cmd_tara.c`'s `asset_line()`, per the
  x-FuSa spec §1.6 rule 4 implementation note.
- Regenerated this repo's own `fmea.json`/`fmea.csv`, `tara.json`/`tara.md`,
  and `safety-case.json`/`safety-case.md` against the fixes below —
  dogfooding, same convention as v0.5.46.

### Fixed
- **`fmea.json`/`tara.json` picked up standard-library calls and
  string-literal text as project components/assets (#78).** The scanner's
  naive paren-based heuristic found the first `(` on a line without regard
  to whether it sat inside a quoted string (misreading a qualification
  test-case description like `"strcpy() triggers CY001"` as a call to a
  function named `"strcpy`, leading-quote included), and never excluded
  well-known libc calls (`fprintf`/`snprintf`/`printf`/`malloc`/`memcpy`/...
  — 67 of 370 entries, 18%, in this repo's own previously-committed
  `fmea.json`). `cfusa_extract_call_name()` now requires the `(` to be
  outside a string literal and excludes standard-library identifiers
  outright. `cfusa_walk_sources()` also skipped only a fixed directory-name
  enum (`build`/`vendor`/`build-cov`/`node_modules`); a local working tree
  with other build-type variants side by side (`build-asan`,
  `build_fortify`, ...) had every one of them scanned as project source
  too, picking up CMake's own generated `CompilerIdC` probe. Both are §1.6
  rule 4 "real referents only" violations; `cfusa_walk_sources()` now skips
  any `build`/`build-*`/`build_*` directory, matching this project's own
  `.gitignore` convention.
- **`fmea.json`/`tara.json` truncated `file` to a bare basename; `sci.json`
  emitted an absolute path when `--dir` was given absolute (#77).**
  `cfusa_relativize_path()` now relativizes against the literal `--dir`
  value used to build each scanned path (deliberately *not*
  `realpath(dir)` — see its doc comment: `path` is always built by
  concatenating the literal `--dir`, and resolving symlinks first can
  silently break the prefix match, e.g. macOS aliases `/tmp` to
  `/private/tmp`), applied to `fmea`/`tara`'s entry `file` and `sci`'s
  `artifacts[].file`.
- **`fmea.json`/`tara.json` `standard` was a citation string, not the
  canonical id (#75).** `"IEC 60812:2018 / ISO 26262-5"` -> `"iso26262"`;
  `"ISO/SAE 21434:2021 Clause 15"` -> `"iso21434"`, matching
  `safety-case.json`'s existing (correct) convention and x-FuSa spec
  §2.4.1's "never a display string" rule.
- **`tara.json` `impact.*` used `high|medium|low`, and `risk` was an ad hoc
  score (#76).** The four category profiles now emit the v1.14.1 closed
  enum (`critical|major|moderate|negligible`), and `risk` is a literal
  lookup against the x-FuSa spec §9.2 combination table (highest-ranked
  SFOP impact x `attackFeasibility`) instead of an independently-invented
  `feasibility_rank x impact_rank` numeric threshold that didn't correspond
  to the table's cells.
- **`summary.coveragePct` defensive clamp (fmea/tara, #80).** Added
  `if (coveragePct > 100) coveragePct = 100;` to both commands per the
  x-FuSa spec §9.2 MUST, plus a regression test with a non-trivial
  test-source tree on each (a fixture with no `test_*.c`-equivalent
  directory can't exercise the bug this clamp guards against).

## v0.5.46 — 2026-07-28

x-FuSa spec v1.13.0/v1.14.0 conformance sprint (issue #71): `hara`/`fmea`/
`tara`/`safety-case`/`sas`/`sci` schemas, the §1.6 content-quality baseline
(FUSA-STUB001/002 detection + §1.6.2 attestation), and `fmea`/`tara`
coverage metrics.

### Added
- **`.fusa-hara.json` three-collection schema (§1.2.5).** `operationalSituations[]`/
  `hazards[]`/`safetyGoals[]` replace the old flat `hazards[]` shape (each with a
  singular `safety_goal` string). `safetyGoals[].fssrRefs` is now **MUST, ≥1
  entry**, cross-checked against `.fusa-reqs.json`. `hara init` scaffolds
  empty collections (never dummy rows); `hara show`/`--format json` add a
  `completeness` block (`safetyGoalsWithFssrRefs`, `danglingReferences`) and
  the §1.6.1 content-quality scan.
- **`fmea`/`tara`/`safety-case` real schemas (§9.2).** `fmea.json` gets
  `ratingScale`, `failureMode`/`effect`/`cause` text that's heuristically
  templated per function (name/file/category) instead of static/blank
  fields, `actionPriority`, and `summary.componentsInProject`/`coveragePct`.
  `tara.json` gets an SFOP `impact` object (safety/financial/operational/
  privacy) per ISO 21434 Clause 15.7 instead of one generic severity, plus
  `summary.assetsInProject`/`coveragePct`/`assetInventoryMethod`. `tara`'s
  assets/threats are now discovered by scanning for functions that look
  like they handle network/file/auth/memory input, instead of a static
  placeholder-filled template. `safety-case --format json` is new:
  `nodes[]`/`edges[]`/`completeness` using the six real GSN node types
  (goal/strategy/solution/context/assumption/justification); `solution`
  nodes only cite `evidence` for a file that actually exists.
- **`sas`/`sci` real schemas (§9.3).** `sas --format json` emits
  `checklist[]`/`summary` (`present` reflects a real evidence-file check,
  not a hardcoded `false`) and always also writes the `sas.md` companion.
  `sci --format json` renames `files`→`artifacts` and `sha256`→`hash`
  (`sha256:`-prefixed, per §2.7 — a field *named* `hash` carries a
  algorithm-prefixed value, unlike a field named for its algorithm).
- **`--min-coverage N` on `fmea`/`tara`** (mirrors `trace --func-coverage`):
  exits 1 when `summary.coveragePct < N`; `N=0` disables the gate.
  `componentsInProject`/`assetsInProject` now exclude test files
  (`test_*.c`/`*_test.c`), matching `trace --func-coverage`'s own
  denominator, so the FMEA/TARA aren't diluted by test scaffolding.
- **§1.6.1 content-quality baseline**: a new `qualitybar` module implements
  Rule A / `FUSA-STUB001` (always `ERROR`, a placeholder/template-text
  deny-list scan; suppressible only via `.fusa-dispositions.json`, never
  attestation) and Rule B / `FUSA-STUB002` (`WARNING` by default; a
  distinct-value-ratio check across ≥10 entries), wired into
  `hara`/`fmea`/`tara`/`safety-case`/`sas`.
- **§1.6.2 attestation**: any of the above commands accept
  `--strict`/`--require-attestation` (escalates an unsuppressed Rule B to
  exit 1) and `--attest <reviewer>` (stamps a `status: "reviewed"`
  attestation with a canonical-content `sha256:` hash). A non-stale,
  genuinely-independent attestation suppresses Rule B; a self-attestation
  or one whose content hash no longer matches falls back to `"heuristic"`
  (fail-safe).
- Regenerated this repo's own `.fusa-hara.json` (migrated from the retired
  `.cfusa-hara.json`), `fmea.json`/`fmea.csv`, `tara.json`/`tara.md`, and
  added `safety-case.json` against the new schemas — c-FuSa dogfooding its
  own spec conformance work, mirroring FuSaOps' own PR #84/PR2.

### Fixed
- **`fmea.json`/`fmea.csv` could contain invalid JSON/CSV.** The function-name
  scanner's naive paren-based heuristic occasionally misdetects a quoted
  string literal (e.g. a known-answer-test table entry) as a function name;
  the `item`/`Function` field was written unescaped, so an embedded `"`
  broke both the JSON and CSV output. Every free-text field is now escaped
  for its target format (JSON string-escaping; CSV quote-doubling per RFC
  4180).
- `cmd_safety_rules.c`'s `HARA002`/`HARA003`/`HARA004` engine rules read the
  old flat `.fusa-hara.json` shape; updated to the new nested
  `risk.severity`/`.exposure`/`.controllability` and `safetyGoals[]`
  reference-array fields, and scoped to the `hazards`/`safetyGoals` arrays
  specifically so they don't cross-match a same-named nested key in a
  sibling collection.

## v0.5.45 — 2026-07-27

### Fixed
- **`audit-pack.zip`'s `manifest.json` claimed hashes for files that were
  silently missing from the archive.** `cmd_audit_pack` staged and hashed
  `.fusa.json`/`.fusa-reqs.json` correctly, but the final ZIP was built with
  `system("cd staging && zip -j out * ")` — a shell `*` glob, which does not
  match dotfiles by default. So both dotfiles were listed in `manifest.json`
  with valid hashes but were never actually written into the archive,
  breaking the tamper-evidence guarantee the manifest exists to provide
  (#67). Fixed by building an explicit, quoted list of the exact basenames
  copied into staging during the artifact loop and passing that list to
  `zip -j` directly, instead of relying on any glob expansion. Added a
  regression test (`test_audit_pack_includes_dotfile_artifacts`) that runs
  a real `audit-pack` and asserts every dotfile artifact is present in the
  resulting archive, not just referenced in the manifest.

## v0.5.44 — 2026-07-27

### Fixed
- **The v0.5.43 Docker license-label fix didn't actually reach the published
  image.** `docker/metadata-action` auto-generates a set of OCI labels
  (including `org.opencontainers.image.licenses`, defaulted to
  `NOASSERTION` because it can't detect an SPDX license from the GitHub
  API) and `docker-publish.yml` passed that full label set to
  `build-push-action`, which overrides same-key `LABEL`s declared in the
  Dockerfile. So the real `ghcr.io/soundmatt/c-fusa:0.5.43` image still
  shipped `licenses=NOASSERTION`, silently undoing the Dockerfile fix from
  v0.5.43 (#62 item 1). Fixed by passing `org.opencontainers.image.licenses:
  MPL-2.0` as a custom label to `docker/metadata-action` itself, which
  overrides its own auto-generated value before it ever reaches
  `build-push-action`. Caught by manually inspecting the published v0.5.43
  image's labels via the Docker Publish workflow logs after tagging.

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
