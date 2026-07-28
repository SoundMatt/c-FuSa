#ifndef CFUSA_VERSION_H
#define CFUSA_VERSION_H

#define CFUSA_VERSION_MAJOR  0
#define CFUSA_VERSION_MINOR  5
#define CFUSA_VERSION_PATCH  47
#define CFUSA_VERSION_STRING "0.5.47"
#define CFUSA_SCHEMA_VERSION "1.15.0"
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
 * #73-80. */
#define CFUSA_SPEC_VERSION   "1.15.0"

#endif /* CFUSA_VERSION_H */
