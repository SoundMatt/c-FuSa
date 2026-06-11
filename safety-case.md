# c-FuSa Safety Case

**Project:** c-FuSa v0.5.0  
**Standard:** ISO 26262-8:2018 §11 (Tool Classification and Qualification)  
**Tool Classification:** TCL-3 (software tool affecting development output)  
**Generated:** 2026-06-11

---

## 1. Tool Purpose

c-FuSa (`cfusa`) is a command-line functional safety toolkit for C projects. It enforces coding standards (MISRA-C, CERT-C), computes traceability coverage, generates compliance gap reports for ISO 26262, IEC 61508, ISO 21434, IEC 62443, and DO-178C, and validates HARA documents.

## 2. Safety Claims

| ID | Claim |
|----|-------|
| SC-01 | c-FuSa correctly detects function length violations (L001) per the configured `max_function_lines` parameter |
| SC-02 | c-FuSa correctly detects goto statements (L002) per MISRA-C Rule 15.1 |
| SC-03 | c-FuSa correctly detects dynamic memory allocation (L003) per MISRA-C Rule 21.3 |
| SC-04 | c-FuSa HARA commands correctly validate S/E/C risk ratings per ISO 26262-3 Table 4 |
| SC-05 | c-FuSa trace matrix reports accurate requirement coverage statistics |
| SC-06 | c-FuSa qualify command verifies tool binary SHA-256 integrity |
| SC-07 | c-FuSa cyclomatic complexity rule (COMP001) uses V(G) = 1 + decision nodes |
| SC-08 | c-FuSa runtime library components operate correctly under unit test coverage |

## 3. Evidence

| Claim | Evidence | Location |
|-------|----------|----------|
| SC-01–SC-08 | Unit test suite (30 test suites, 100% pass) | `tests/` |
| SC-04 | ASIL table unit tests | `tests/test_asil_table.c` |
| SC-05 | Trace coverage tests | `tests/test_trace_req.c` |
| SC-06 | Qualify command tests | `tests/test_safety_commands.c` |
| SC-07 | Complexity rule tests | `tests/test_safety_rules.c` |
| SC-08 | Runtime library tests | `tests/test_runtime.c` |
| All | Tool qualification record | `.cfusa_qualification.json` |

## 4. Tool Qualification Summary

c-FuSa self-qualifies using `cfusa qualify`:
- Tests: 30 suites, all passing
- Binary integrity: SHA-256 verified
- Self-check: c-FuSa runs on its own source code

## 5. Limitations and Assumptions

1. c-FuSa performs static text analysis. It does not perform semantic analysis or type inference.
2. MISRA-C rule coverage is partial — see `cfusa misra` for gap report.
3. HARA S/E/C validation requires well-formed `.fusa-hara.json` input.
4. Coupling analysis operates on syntactic patterns; full coupling analysis requires a dedicated tool.
5. This tool must be re-qualified after any changes to rule implementations.
