#ifndef CFUSA_DISPOSITION_H
#define CFUSA_DISPOSITION_H

#include "cfusa/report.h"

/*
 * issue #122: wires .fusa-dispositions.json into cfusa check/lint
 * enforcement. Previously `cfusa disposition add` was a standalone audit
 * log — nothing ever read it back, so recording a disposition had no
 * effect on a later run's findings or exit code.
 *
 * Fingerprint-scoped, not rule-scoped: a disposition without a
 * fingerprint (recorded via the older --rule-only form of `disposition
 * add`, or any future entry someone adds by hand without one) is loaded
 * but never matches a finding — keying suppression off --rule alone would
 * silently exempt every future finding under that rule ID anywhere in the
 * codebase, forever, which is too coarse to be a real deviation gate.
 */

typedef struct {
    char id[16];          /* "DISP-0007" */
    char rule[64];         /* display/filtering only — NOT used to match findings */
    char fingerprint[72]; /* "sha256:" + 64 hex chars + NUL — the actual match key */
    char action[16];      /* accept | fix | mitigate */
} cfusa_disposition_t;

typedef struct {
    cfusa_disposition_t *items;
    int count;
    int cap;
} cfusa_disposition_list_t;

/* Loads dir/.fusa-dispositions.json (falling back to the legacy
 * dir/.cfusa-dispositions.json name). A missing file is NOT an error —
 * *list is zeroed and this returns 1, matching "no dispositions recorded
 * yet" as the normal case. Returns 0 only on a real allocation failure
 * partway through loading (a WARNING is also printed to stderr in that
 * case) — never silently truncates the list past a fixed cap. */
int cfusa_dispositions_load(const char *dir, cfusa_disposition_list_t *list);

/* Releases the array cfusa_dispositions_load() allocated. Safe on a
 * zeroed/already-freed list. */
void cfusa_dispositions_free(cfusa_disposition_list_t *list);

/* Cross-references every finding in `rpt` against `list` by fingerprint.
 * A finding matching an accept- or mitigate-action disposition is tagged
 * (disposition_id/disposition_action set on the finding) and excluded
 * from rpt->error_count/warning_count/info_count — moved instead into
 * rpt->dispositioned_count. A finding is never removed from
 * rpt->findings[]; a fix-action disposition is a historical note only and
 * never suppresses (the code presumably no longer matches, so there is
 * nothing live to suppress). Safe to call with an empty list (no-op). */
void cfusa_report_apply_dispositions(cfusa_report_t *rpt,
                                      const cfusa_disposition_list_t *list);

#endif /* CFUSA_DISPOSITION_H */
