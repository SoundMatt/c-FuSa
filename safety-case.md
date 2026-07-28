# Safety Case — c-FuSa v0.5.1

**Standard:** iso26262  |  **Generated:** 2026-07-28T19:47:39Z

---

## G1 — goal

> c-FuSa v0.5.1 has no unmitigated hazard from .fusa-hara.json and no unresolved ERROR finding from `cfusa check` at the iso26262 analysis boundary

## St1 — strategy

> Argue over hazard elimination and process confidence separately

## C1 — context

> Scope: c-FuSa source under ".", analyzed against iso26262 by c-FuSa v0.5.46

## A1 — assumption

> The underlying hardware/platform on which c-FuSa runs meets its own safety requirements independently of this software safety case

## G1.1 — goal

> Every hazard recorded in .fusa-hara.json is eliminated or controlled to its assigned ASIL (ISO 26262-3 Clause 6)

## G1.2 — goal

> The c-FuSa development process gives justified confidence: static analysis, FMEA/TARA, and tool qualification evidence are current

## Sn2 — solution

> Static analysis / lint / cyber self-check results

Evidence: `cfusa-self-check.json`

## Sn3 — solution

> Design FMEA

Evidence: `fmea.json`

## Sn4 — solution

> Threat analysis and risk assessment

Evidence: `tara.json`

## Sn5 — solution

> Tool qualification record

Evidence: `qualify-report.json`

---

## Argument Structure

| From | To | Relation |
|---|---|---|
| G1 | St1 | supportedBy |
| G1 | C1 | inContextOf |
| St1 | A1 | inContextOf |
| St1 | G1.1 | supportedBy |
| St1 | G1.2 | supportedBy |
| G1.2 | Sn2 | supportedBy |
| G1.2 | Sn3 | supportedBy |
| G1.2 | Sn4 | supportedBy |
| G1.2 | Sn5 | supportedBy |

_Completeness: 3 goal(s), 1 with cited evidence, 1 undeveloped._

---

## Evidence Index

| File | Present | SHA-256 |
|---|---|---|
| hara.md | absent | — |
| safety-plan.md | absent | — |
| tara.md | present | `dcfdbf0fe1239b5a9f1263b1e328d5d7f7938678f74d937ff382dfb1c846517a` |
| fmea.md | absent | — |
| test-evidence.md | absent | — |
| sas.md | absent | — |
| .fusa.json | present | `740787473985c81748b3962e330731f02ef1359f02bbb5e61a8e402b7c0e9595` |
