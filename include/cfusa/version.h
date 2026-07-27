#ifndef CFUSA_VERSION_H
#define CFUSA_VERSION_H

#define CFUSA_VERSION_MAJOR  0
#define CFUSA_VERSION_MINOR  5
#define CFUSA_VERSION_PATCH  44
#define CFUSA_VERSION_STRING "0.5.44"
#define CFUSA_SCHEMA_VERSION "1.11.0"
/* Bumped from 1.10.12 to match the x-FuSa master spec's additive §1.4.1
 * "requirement annotation completeness" MINOR bump (issue #62 item 3). The
 * new items are SHOULD-level, and c-FuSa v0.5.41 already implements the
 * corresponding --func-coverage gate and dangling-ID detection, so tracking
 * the spec version here is accurate rather than aspirational. */
#define CFUSA_SPEC_VERSION   "1.11.0"

#endif /* CFUSA_VERSION_H */
