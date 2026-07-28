#ifndef CFUSA_QUALITYBAR_H
#define CFUSA_QUALITYBAR_H

/*
 * cfusa "quality bar" — the x-FuSa spec §1.6/§1.6.1/§1.6.2 evidence-artifact
 * content-quality baseline, shared by hara/fmea/tara/safety-case/sas.
 *
 * Two concrete, checkable rules over a generated evidence artifact's
 * qualitative (free-text) fields:
 *
 *   Rule A / FUSA-STUB001 (always ERROR, disposition-suppressible only) —
 *   literal placeholder/template text: cfusa_qb_is_stub_text().
 *
 *   Rule B / FUSA-STUB002 (WARNING by default, not gating unless
 *   --strict/--require-attestation) — a single hardcoded qualitative string
 *   applied to every entry: cfusa_qb_rule_b_flagged().
 *
 * Plus the §1.6.2 attestation mechanism that suppresses a Rule B finding
 * once a named, independent human asserts they reviewed the content.
 */

#include <stddef.h>

#define CFUSA_QB_RULE_A "FUSA-STUB001"
#define CFUSA_QB_RULE_B "FUSA-STUB002"

/* Rule A (MUST, x-FuSa spec §1.6.1) — deny-list scan for literal
 * placeholder/instructional text: bracket-wrapped instructional text
 * (e.g. "[describe asset]") or the case-insensitive substrings
 * "replace with", "example hazard", "tbd", "lorem ipsum", "fill in".
 * Returns 1 when `text` matches, 0 otherwise. */
int cfusa_qb_is_stub_text(const char *text);

/* Rule B (SHOULD, x-FuSa spec §1.6.1) — distinct-value-ratio check.
 * `values` is an array of `n` qualitative-field strings (one per entry).
 * Returns 1 (flagged) when n >= 10 and (distinct count / n) < 0.1. */
int cfusa_qb_rule_b_flagged(const char * const *values, int n);

/* An artifact-level attestation object (x-FuSa spec §1.6.2). */
typedef struct {
    int  present;                        /* 1 if an attestation object was found at all */
    char status[16];                     /* "heuristic" | "reviewed" */
    char implementation_author[128];
    char independent_reviewer[128];
    char reviewed_at[40];
    char content_hash[80];               /* "sha256:" + 64 lowercase hex */
} cfusa_attestation_t;

/* Extracts a top-level "attestation": {...} object out of a previously
 * generated artifact's raw JSON text (`json`, `len` bytes), if present.
 * Returns 1 when an attestation object was found (even if some fields are
 * missing — caller/cfusa_qb_attestation_valid() re-validates), 0 otherwise. */
int cfusa_qb_attestation_read(const char *json, size_t len, cfusa_attestation_t *out);

/* Validates independence + non-staleness (x-FuSa spec §1.6.2, MUST when
 * status: "reviewed"): independent_reviewer must differ from
 * implementation_author, and content_hash must match `fresh_hash` (the
 * artifact's current substantive-content hash — see cfusa_qb_content_hash()).
 * Returns 1 only for a genuinely independent, non-stale "reviewed"
 * attestation — i.e. exactly the condition that MUST suppress a Rule B
 * finding. Fail-safe: anything absent/malformed/self-attested/stale
 * returns 0 (treated as "heuristic"), never 1. */
int cfusa_qb_attestation_valid(const cfusa_attestation_t *att, const char *fresh_hash);

/* Rule-level disposition lookup — this repo's existing
 * .fusa-dispositions.json convention keys a disposition by ruleId (see
 * `cfusa disposition`), not by per-finding fingerprint. Returns 1 when at
 * least one disposition entry exists for `rule_id` under `dir`. Rule A is
 * suppressible only this way (never via attestation); Rule B is not
 * suppressible this way (only via a valid attestation), per §1.6.1. */
int cfusa_qb_rule_disposed(const char *dir, const char *rule_id);

/* Computes "sha256:<hex>" over a caller-assembled canonical JSON fragment
 * (RFC 8785-style: object members in ASCII-lexicographic key order, no
 * insignificant whitespace, over the artifact's substantive content only —
 * entries/hazards/threats/nodes/checklist/artifacts, excluding the
 * `attestation` object itself and `generatedAt`, per x-FuSa spec §1.6.2).
 * Because each artifact command constructs (rather than parses) its own
 * value tree, emitting members in sorted order while building the fragment
 * is sufficient to match a genuine RFC 8785 canonicalizer over the same
 * abstract value — no generic JSON parser is required. */
void cfusa_qb_content_hash(const char *canonical_json, size_t len, char hash_out[80]);

#endif /* CFUSA_QUALITYBAR_H */
