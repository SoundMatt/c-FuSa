#ifndef CFUSA_VERSION_H
#define CFUSA_VERSION_H

#define CFUSA_VERSION_MAJOR  0
#define CFUSA_VERSION_MINOR  5
#define CFUSA_VERSION_PATCH  46
#define CFUSA_VERSION_STRING "0.5.46"
#define CFUSA_SCHEMA_VERSION "1.14.0"
/* Bumped from 1.11.0 to 1.14.0: adopts the x-FuSa master spec's §1.2.5/§9.2/
 * §9.3 evidence-artifact schema formalization (hara/fmea/tara/safety-case/
 * sas/sci field-level shapes — SFOP TARA impact, GSN safety-case node
 * types, HARA's three cross-referenced collections with MUST fssrRefs) and
 * the §1.6/§1.6.1/§1.6.2 content-quality baseline (FUSA-STUB001/002
 * detection, attestation, summary.coveragePct/--min-coverage on fmea/tara).
 * See issue #71. */
#define CFUSA_SPEC_VERSION   "1.14.0"

#endif /* CFUSA_VERSION_H */
