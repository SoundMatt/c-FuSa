#ifndef CFUSA_VERSION_H
#define CFUSA_VERSION_H

#define CFUSA_VERSION_MAJOR  0
#define CFUSA_VERSION_MINOR  5
#define CFUSA_VERSION_PATCH  48
#define CFUSA_VERSION_STRING "0.5.48"
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
