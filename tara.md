# c-FuSa Threat Analysis and Risk Assessment (TARA)

**Project:** c-FuSa v0.5.0  
**Standard:** ISO 21434:2021 §9  
**Generated:** 2026-06-11

---

## 1. Item Definition

c-FuSa is a host-based static analysis and compliance reporting tool. It is not a vehicle-embedded component. It processes source code and configuration files and produces reports and JSON artifacts.

## 2. Asset Identification

| Asset ID | Asset | Security Property | Rationale |
|----------|-------|-------------------|-----------|
| A-01 | Source code under analysis | Integrity | Tampered source files could yield false-clean reports |
| A-02 | `.fusa-reqs.json` requirements registry | Integrity | Modified requirements affect traceability coverage |
| A-03 | `.fusa-hara.json` HARA document | Integrity | Tampered HARA affects ISO 26262 compliance evidence |
| A-04 | `cfusa` binary | Integrity | Compromised binary produces incorrect findings |
| A-05 | Check/qualify reports | Integrity | Falsified reports could support incorrect certification claims |
| A-06 | CI/CD pipeline configuration | Integrity | Modified CI could suppress safety checks |

## 3. Threat Scenarios

| ID | Asset | Threat | Attack Vector | CAL |
|----|-------|--------|---------------|-----|
| T-01 | A-01 | Adversary modifies source to suppress genuine findings | Supply chain / insider | CAL-2 |
| T-02 | A-02 | Requirements tampered to achieve false 100% coverage | Repository access | CAL-2 |
| T-03 | A-03 | HARA file manipulated to lower ASIL ratings | Repository access | CAL-3 |
| T-04 | A-04 | Binary replaced with version that skips checks | CI/CD compromise | CAL-3 |
| T-05 | A-05 | Report file overwritten with falsified results | Build artifact compromise | CAL-2 |

## 4. Risk Treatment Decisions

| Threat | Decision | Mitigation |
|--------|----------|------------|
| T-01 | Reduce | Code review policy; `cfusa sign` SHA-256 signing of reports |
| T-02 | Reduce | `cfusa qualify` binary hash verification; CI enforces qualification |
| T-03 | Reduce | HARA file reviewed and signed; HARA001-005 engine rules flag inconsistencies |
| T-04 | Reduce | `cfusa qualify --binary` verifies binary integrity; CI re-runs qualification |
| T-05 | Reduce | `cfusa sign` signs report files; report integrity checked before use |

## 5. Cybersecurity Goals

| CG-ID | Goal | CAL | Links |
|-------|------|-----|-------|
| CG-01 | The cfusa binary integrity must be verifiable prior to use in a safety process | CAL-2 | T-04 |
| CG-02 | Compliance reports must be authenticated before acceptance as certification evidence | CAL-2 | T-05 |
| CG-03 | HARA documents must be protected against unauthorised modification | CAL-3 | T-03 |
