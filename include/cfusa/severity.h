#ifndef CFUSA_SEVERITY_H
#define CFUSA_SEVERITY_H

#include "cfusa/report.h"

/*
 * Shared DAL/ASIL integrity-level ranking and gate-severity derivation.
 *
 * Every ASIL/DAL-scaled gate c-FuSa has (or is gaining — see issues
 * #104-#107) needs the same two primitives: (1) rank a declared DAL or
 * ASIL string from least to most stringent, and (2) decide how strict a
 * gate should be at that level. Centralizing both here avoids each gate
 * inventing its own DAL/ASIL string table — exactly the duplication that
 * previously let cmd_comp.c's DAL-A..D threshold table and
 * cmd_safety_rules.c's separate local asil_rank() drift independently.
 *
 * Modeled on FuSaOps' trace.SeverityForDecomposition(enforce, dal, asil)
 * pattern (an --enforce auto|error|warn|off convention), so future
 * ASIL/DAL-scaled gates (independence, MC/DC-required, complexity
 * threshold, ...) can converge on one shape instead of diverging.
 */

/* Ranks a DAL string ("DAL-A".."DAL-E", case-insensitive) from most (4, A)
 * to least (0, E) stringent. Returns -1 for NULL/empty/unrecognized
 * input. */
int cfusa_dal_rank(const char *dal);

/* Ranks an ASIL string ("QM", "ASIL-A".."ASIL-D", case-insensitive) from
 * least (0, QM) to most (4, ASIL-D) stringent. Returns -1 for
 * NULL/empty/unrecognized input. */
int cfusa_asil_rank(const char *asil);

/*
 * Derives whether a gate should be enforced, and at what severity, from an
 * --enforce selection plus the project's declared DAL and/or ASIL.
 *
 *   enforce: "auto" (derive from dal/asil below), "error", "warn", or
 *            "off" (explicit override — dal/asil ignored regardless of
 *            what they are). NULL, empty, or any unrecognized value
 *            behaves as "auto".
 *   dal:     "DAL-A".."DAL-E", or NULL/empty if not declared.
 *   asil:    "QM"/"ASIL-A".."ASIL-D", or NULL/empty if not declared.
 *
 * "auto" mapping: rank(dal) and rank(asil) are computed on the same 0-4
 * scale (least to most stringent) and the more stringent of the two wins
 * when both are declared.
 *   rank 3-4 (DAL-A/DAL-B, ASIL-C/ASIL-D)  -> SEV_ERROR
 *   rank 1-2 (DAL-C/DAL-D, ASIL-A/ASIL-B)  -> SEV_WARNING
 *   rank 0 (DAL-E, QM), or neither declared -> gate is OFF (not
 *   applicable at this integrity level — DAL-E/QM both mean "no safety
 *   effect", not "low severity", so the gate doesn't fire at all rather
 *   than firing quietly).
 *
 * Returns 1 and sets *out_sev when the gate is active (caller should
 * enforce it at *out_sev); returns 0 when the gate is OFF (caller should
 * skip enforcement entirely — *out_sev is left unset).
 */
int cfusa_required_severity(const char *enforce, const char *dal,
                             const char *asil, cfusa_severity_t *out_sev);

#endif /* CFUSA_SEVERITY_H */
