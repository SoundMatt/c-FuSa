#ifndef CFUSA_VERSION_H
#define CFUSA_VERSION_H

#define CFUSA_VERSION_MAJOR  0
#define CFUSA_VERSION_MINOR  6
#define CFUSA_VERSION_PATCH  2
#define CFUSA_VERSION_STRING "0.6.2"
/* v0.6.2 — 2026-08-18 architecture-plan loop: eleven tracked improvement
 * issues (#203-#213), eight shipped across eight PRs (#215-#218,
 * #220-#223); #206/#207 (per-file result cache; compile_commands.json/
 * libclang integration) deliberately deferred per their own issue
 * scoping; #211 (Windows/MSVC) resolved as a scoping decision rather
 * than an implementation. Includes new user-facing flags/behaviors, not
 * just fixes. Highlights: a shared
 * comment/string-aware lexer (cfusa_lex_strip_line()) replacing ad hoc
 * per-rule state machines (#203); a single tree-walk/single file-read
 * engine for line-scan rules, collapsing 54 independent
 * cfusa_walk_sources() call sites into one dispatch pass (#204); #if 0
 * preprocessor-lite awareness so unconditionally-disabled code is no
 * longer scanned (#205); `cfusa baseline` / .fusa-baseline.json for
 * suppress-existing-debt adoption on a legacy codebase (#208); `cfusa
 * check --changed-since <ref>` to scope a report to only lines changed
 * since a git ref (#209); `cfusa fix` remediation-guidance coverage
 * expanded from 19 to the full 39 lint/analyze/cyber rules, plus a real
 * `--dry-run`/`--apply` autofix for CFUSA-CY006 (free-without-NULL)
 * (#210); Windows/MSVC support audited and deliberately deferred —
 * WSL2 is the supported path today, see issue #211 for the full
 * rationale; `cfusa explain <RULE-ID>` for a rule's full
 * description/standard citation/fix guidance in one place (#212); a
 * first-party GitHub Action (action.yml, `uses: SoundMatt/c-FuSa@
 * <tag>`) installing a pinned release binary, running `cfusa check`,
 * and uploading SARIF (#213). 47/47 test suites pass, self-check clean.
 * See CHANGELOG.md for the itemised, issue-linked list.
 *
 * v0.6.1 — 2026-08-18 forty-three fixes from a 40-agent deep-audit
 * sweep of the codebase (#141-#182) plus one more found and fixed the
 * same session (#187). Patch bump — precision/correctness fixes only,
 * no new user-facing flags or behaviors. Highlights: disposition JSON
 * loading/writing hardened (whitespace-tolerant parsing, atomic
 * locked writes, bare-array fallback; #143-144, #158-159, #175-176);
 * DISP001 now defers to the real fingerprint-scoped disposition
 * mechanism instead of a substring match (#148); project_root is set
 * consistently across commands so fingerprints (and disposition
 * matching) agree everywhere (#153); cmd_req.c canonical filename
 * resolution + a real --sec-tested gate (#146-147, #166); five
 * CFUSA-CY rules and the legacy REQ: scanner/config exclude_dirs
 * switched to identifier/path-segment-boundary matching, removing
 * several substring false-positive classes (#154-157, #173-174, #180);
 * cmd_lint.c L001/L002/L003/L006 precision and persistent
 * block-comment-tracking fixes (#161-163, #177); cmd_analyze.c
 * A001/A003/A006/A007 precision fixes (#149-151, #169); a
 * silent-truncation trio fixed — lcov empty/unreadable-file handling,
 * dynamically-sized HLR/LLR arrays, HARA nested-ref truncation
 * warnings (#142, #160, #167); report.c --strict/summary-table/CSV
 * consistency fixes plus a new RFC 4180 CSV writer (#164-165,
 * #178-179); a failed report write now exits 3 as documented instead
 * of silently exiting 0 (#141); cmd_hara.c's top-level parsing is now
 * key-order-independent (#145); cfusa_config_save() persists every
 * declared standard, not just the first (#168); --dal DAL-D no longer
 * discards an explicit --threshold, and --dal DAL-A/--asil ASIL-D now
 * floor --mcdc-threshold to the 100% they document (#152, #172); a
 * getopt_long platform-reset (BSD optreset / glibc nextchar) sweep
 * across all ~41 commands, not just 3 (#170-171); COUP001's extern
 * match is now anchored and comment-aware, and COUP001/COUP002/COMP001
 * now honor the run()-returns-finding-count contract (#181-182);
 * CFUSA-L004's self-call detector is now comment-aware, not just
 * string-literal-aware (#187). Every fix ships with regression tests
 * verified to fail against the pre-fix code and pass against the fix;
 * 44/44 test suites pass, self-check clean. See CHANGELOG.md for the
 * itemised, PR-linked list.
 *
 * v0.6.0 — 2026-08-18 nine fixes, seven from an issue-tracker sweep
 * (#128, #124, #126, #97, #127, #125, #122) plus two more (#129, #137)
 * found and fixed the same session: (1) `cfusa qualify`'s
 * qualified/qualificationBadge fields could disagree — now
 * qualified requires both self-tests passing AND a declared
 * --qualification-method. (2) `cmd_hara.c`'s split_array() silently
 * dropped any JSON array element >=511 bytes — a real HARA could read 0
 * hazards; now heap-allocates each element at its exact length. (3)
 * CFUSA-A003 (signed/unsigned vs sizeof) was near-100% false positives on
 * real code — now type-aware via a two-pass locally-visible-name scan.
 * (4) `cfusa safety-case` hardcoded exact lowercase evidence filenames,
 * case-sensitive via stat() — broke on Linux for projects naming files
 * e.g. HARA.md; new cfusa_find_file_ci() does a real case-insensitive
 * match. (5) `cfusa fix` gained remediation guidance for CFUSA-CY006
 * (free-without-NULL). (6) new `cfusa trace --func-coverage-strict` — a
 * genuinely per-function annotation-density gate, additive alongside the
 * unchanged file-level --func-coverage. (7) `.fusa-dispositions.json` is
 * now actually enforced by `cfusa check`/`cfusa lint` (fingerprint-scoped,
 * never rule-wide) instead of being a standalone audit log. (8) `cfusa
 * coverage --mcdc-file` parsed a schema that never matched real `llvm-cov
 * export` output — verified and fixed against an actual captured export.
 * (9) new `cfusa coverage --branch-threshold` — an independent
 * branch-coverage regression floor, separate from --threshold's
 * line-only gate. Minor version bump (not patch): includes three new
 * user-facing flags/behaviors (--func-coverage-strict,
 * --branch-threshold, disposition enforcement), not just bug fixes.
 *
 * v0.5.54 — 2026-08-14 three fixes from a direct quality review: (1) all
 * previously-flagged CFUSA-A007 (unchecked fclose()) sites now check the
 * return value — 39 sites across 9 files, product code gets real error
 * handling, test code fails loudly via TEST_FAIL_MESSAGE. (2) CFUSA-A006
 * ("pointer arithmetic") no longer fires on coincidental, unrelated
 * `*`/`++`/`--`/`+=`/`-=` co-occurrence on the same line — now requires
 * the same identifier on both sides; project-wide 545 -> 141 findings
 * (74% reduction), each verified by hand as a genuine unrelated-token
 * coincidence. (3) CFUSA-L003 ("dynamic memory") no longer fires on
 * custom `_free()`-suffixed functions or string-literal text — was a
 * plain substring match, so `free(` also matched inside e.g.
 * cfusa_report_free(); project-wide 464 -> 133 findings (61% were this
 * false-positive class). L003 severity is also now ASIL-scaled (ISO
 * 26262-6: dynamic memory avoidance is "highly recommended" at ASIL-C/D,
 * only "recommended" at QM/A/B) via a new shared
 * cfusa_declared_asil_rank() (severity.h), moved out of a cmd_misra.c-
 * local helper so it doesn't drift independently from the accredited-
 * tool note (v0.5.52) that already used it.
 *
 * v0.5.53 — 2026-08-13 MC/DC gate honesty fixes, found during a direct
 * quality review of c-FuSa's MC/DC support: (1) `cfusa coverage
 * --mcdc-file` parsing to zero condition records used to silently PASS
 * ("nothing to fail") — indistinguishable from a wrong/empty/malformed
 * export purely from content, the same silent-incomplete-data-reads-as-
 * complete failure shape as the MAX_REQS bug (issue #100); now fails
 * loudly with a diagnostic note, and the report no longer shows a
 * contradictory "100.00% (0/0 conditions) FAIL". (2) without --mcdc-file,
 * the DAL-A/ASIL-D-required MC/DC gate falls back to treating 100% branch
 * coverage as a proxy, but the output was labeled "MC/DC analysis" —
 * materially misleading, since 100% branch/decision coverage does not
 * establish that every condition within a decision independently affects
 * its outcome. Now: a stderr WARNING when the proxy is used, an honest
 * "branch-coverage proxy — NOT verified MC/DC" label, a machine-readable
 * mcdcProxy.verified=false JSON field, and --help text spelling out the
 * distinction.
 *
 * v0.5.52 — 2026-08-13 ASIL-scaling initiative (issue #103, #104-#109):
 * c-FuSa correctly derived ASIL but didn't scale the rigor ISO 26262
 * actually escalates at higher ASIL levels — MC/DC coverage, independent
 * review/test, and complexity/rule strictness were either DO-178C-DAL-only
 * or inert metadata. Adds a shared cfusa_dal_rank()/cfusa_asil_rank()/
 * cfusa_required_severity() helper (include/cfusa/severity.h, #104);
 * `cfusa qualify` now computes achievableAsil from real V&V independence
 * declarations instead of accepting it as a free-input string, and
 * `--project-asil`/`--enforce` gate the command on it (#105, breaking:
 * removes `--achievable-asil`); `cfusa coverage --asil` adds an
 * ISO 26262-6 Table 12 MC/DC/coverage gate that composes with `--dal` via
 * stricter-wins (#106); `check`'s automatic COMP001 threshold now agrees
 * with `cfusa comp --asil-*` for ISO-26262-only projects (#107); two new
 * MISRA-C rules (CFUSA-L011 octal constants, CFUSA-L012 keyword-named
 * macros) and an ASIL-scaled accredited-third-party-tool note in
 * `cfusa misra` (#108); new docs/standards/iso26262.md documenting what
 * is and isn't ASIL-scaled, including the explicit non-goal of Tool
 * Confidence Level (TCL) determination (#109).
 *
 * v0.5.51 — 2026-08-13 fixes issue #100: cmd_req.c/cmd_trace.c's
 * requirements array (g_reqs, MAX_REQS=1024) and cmd_impact.c's
 * requirement-id array (MAX_REQS=256) were fixed-size stack arrays whose
 * parse loops silently stopped once full — no error, no warning, no
 * truncation notice — so a .fusa-reqs.json catalog larger than the cap
 * produced a false 100%-coverage / 0-errors reading from `trace`/`check`
 * while the untracked tail could never be reported missing, untested, or
 * dangling. All three now grow dynamically via realloc with no fixed cap;
 * a genuine allocation failure (OOM) is a hard ERROR with a non-zero exit
 * rather than a silent partial load. The same fixed-cap truncation bug was
 * also present in g_tags (MAX_TAGS=4096, cmd_req.c/cmd_trace.c) — since
 * real catalogs are annotated with both //cfusa:req and //cfusa:test tags,
 * tag count grows faster than requirement count and this cap could
 * silently under-report coverage well before the requirements array
 * itself filled up; fixed the same way.
 *
 * v0.5.50 (previously landed as v0.5.49, but the tag/release "v0.5.49" had
 * already been published against a stale commit whose version.h still read
 * "0.5.48" — see the PR that introduced this bump for the full story;
 * renumbered to v0.5.50 to avoid re-using an already-shipped version
 * string) — 2026-07-30 external audit remediation: corrects a Critical
 * mis-implementation of ISO 26262-3:2018 Table 4 in the shared
 * cfusa_compute_asil() (19/36 S x E x C cells were over-assigned; the
 * dogfooded .fusa-hara.json and the "exhaustive" 36-cell test both
 * inherited/masked the same error) and fixes two independently
 * live-reproduced command/argument-injection vulnerabilities: `impact`
 * accepted a git-ref beginning with '-' and built `git diff` without a
 * `--` separator (an attacker-controlled --from could smuggle a git flag
 * such as --output); `audit-pack` interpolated --output/--dir unsanitized
 * into a double-quoted system("... zip ...") string, allowing shell
 * command substitution. Also fixes: C0 controllability now short-circuits
 * to QM per ISO 26262-3:2018 4.3.5; out-of-range S/E/C now exits 2 instead
 * of silently coercing to QM; duplicate requirement ids in
 * .fusa-reqs.json now fail `check` as a real fingerprinted DUPREQ001
 * Finding instead of only printing to stderr; cmd_trace.c reads the
 * canonical "parent" key (with "parentId" as a legacy fallback) instead of
 * only "parentId"; the report envelope no longer hardcodes an always-empty
 * "errors": [] array; cfusa_read_file()'s unchecked ftell() can no longer
 * wrap into an oversized/negative allocation; cmd_trace.c heap-allocates
 * requirement-object parsing so objects over 1KB are no longer truncated;
 * and .fusa.json's project.version (stale at "0.5.1") now matches the
 * shipped tool version. Un-masking CI's self-check step (see ci.yml) also
 * surfaced (now fixed) a MISRA-C recursion violation in the new
 * ap_rmdir_recursive() plus a pre-existing one in qt_rmdir_recursive() (both
 * now iterative via nftw()), two double-free-lookalike lines in cmd_comp.c,
 * and two test names that false-triggered weak-crypto/system-call rules by
 * coincidental substring match. See CHANGELOG.md for the itemised list. */
#define CFUSA_SCHEMA_VERSION "1.15.2"
/* Bumped from 1.14.0 to 1.15.0: adopts the x-FuSa master spec's v1.15.0
 * attestation-carry-forward MUST (already conformant for fmea/tara/
 * safety-case/sas; hara's own JSON output now also passes through its
 * input file's attestation and cross-references verbatim, per §9.2), the
 * §1.6 rule 4 test-tree/stdlib-exclusion reuse guidance (fmea/tara now
 * share cfusa_is_test_source_file()/cfusa_extract_call_name() rather than
 * each maintaining an independently-drifting scanner), and the §9.2
 * coveragePct <= 100 MUST (defensive clamp + regression tests with a
 * non-trivial test-source tree on both fmea and tara). Also fixes several
 * post-v1.14.0 rollout-audit findings: fmea/tara `standard` now emits the
 * canonical id instead of a display string (§2.4.1); tara's `impact.*`
 * uses the v1.14.1 closed enum (critical|major|moderate|negligible) and
 * `risk` is derived from the spec's combination table instead of an ad hoc
 * score; fmea/tara/sci `file`/`location.file` are project-relative
 * (including subdirectory) instead of a bare basename or a leaked absolute
 * path; HARA's stored `risk.asil` is now cross-checked against the S x E x
 * C table both in `hara --format json`'s completeness block and as a new
 * `check` engine rule (HARA006), not just a text-mode warning. See issues
 * #73-80.
 *
 * v0.5.48 — 2026-07-28/29 deep-audit bug-fix sprint (issues #82-91):
 * SARIF tool.driver.name now "c-FuSa" (§2.9); hara init's scaffold matches
 * the §1.2.5 INPUT schema (no report envelope, no "kind": "hara"); sas
 * --format json now writes real sas.json + sas.md companion instead of raw
 * JSON into a file named sas.md; qualify accepts --dir (§2.2); misra now
 * uses the canonical §9.3 gap-report schema; iec62443's standard id is
 * "iec62443-4-2" (§2.4.1); iso26262/iec61508/do178/iso21434/unece/iec62443
 * gap-report JSON now carries a summary{total,satisfied,partial,gaps}
 * object (§9.3 MUST); check/lint/analyze/cyber findings emit a canonical
 * `standard` id with a separate `clause` field instead of a combined
 * display string (§2.4.1); fmea/tara/safety-case/sas now carry a prior
 * attestation forward verbatim (preserved-as-stale) instead of dropping it
 * the moment content changes (§1.6.2 MUST); CFUSA-L004 no longer
 * false-positives when a callee's name merely has the caller's name as a
 * suffix. */
#define CFUSA_SPEC_VERSION   "1.15.2"
/* CFUSA_SCHEMA_VERSION and CFUSA_SPEC_VERSION bumped 1.15.0 -> 1.15.2
 * together (as always): both intervening spec releases are pure
 * documentation clarifications with zero required behavior/wire-format
 * changes. v1.15.1 blessed MAJOR.MINOR.PATCH (not MAJOR.MINOR) as the
 * documented format for schemaVersion/specVersion, matching what c-FuSa
 * (and every other tool) already emitted. v1.15.2 added an explicit
 * false-positive example to §1.6.1 Rule A's placeholder-text deny-list,
 * documenting an already-intended tradeoff (resolved via disposition
 * waiver, not per-tool detector narrowing) rather than changing it. No
 * c-FuSa code changes required for either bump. */

#endif /* CFUSA_VERSION_H */
