#ifndef CFUSA_ASIL_H
#define CFUSA_ASIL_H

/*
 * ISO 26262-3:2018 Table 4 ASIL determination, with the C0 extension.
 *
 * Shared by `cfusa hara` (which computes it for the text-mode "stored ASIL
 * differs from computed" warning) and the `check` engine's HARA rules
 * (which gate on the same computation — x-FuSa spec §1.2.5's "ASIL
 * determination (MUST when standard: iso26262)"). Previously duplicated as
 * a static table inside cmd_hara.c; consolidated here so both call sites
 * are provably using the identical table.
 */

/* s: 1-3 (S1-S3), e: 1-4 (E1-E4), c: 0-3 (C0-C3). Returns "QM" for any
 * out-of-range input (fail-safe: never returns an ASIL for an unparseable
 * rating). */
const char *cfusa_compute_asil(int s, int e, int c);

#endif /* CFUSA_ASIL_H */
