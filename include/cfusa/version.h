#ifndef CFUSA_VERSION_H
#define CFUSA_VERSION_H

#define CFUSA_VERSION_MAJOR  0
#define CFUSA_VERSION_MINOR  5
#define CFUSA_VERSION_PATCH  53
#define CFUSA_VERSION_STRING "0.5.53"
/* v0.5.53 — 2026-08-13 MC/DC gate honesty fixes, found during a direct
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
