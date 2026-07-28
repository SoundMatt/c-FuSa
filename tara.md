# Threat Analysis and Risk Assessment (TARA)
## ISO/SAE 21434:2021 Clause 15 — c-FuSa v0.5.1
Generated: 2026-07-28T19:47:38Z

Assets and threats below were discovered by a keyword-based scan of public functions handling network, file, credential, or raw-memory input (see `assetInventoryMethod` in `tara.json`) — not a formal asset inventory.

---

| ID | Asset | Threat | Attack Vector | Feasibility | Safety | Financial | Operational | Privacy | Risk | Treatment |
|---|---|---|---|---|---|---|---|---|---|---|
| TARA-001 | Data handled by "strcpy (cmd_qualify.c) | An attacker supplies malformed/untrusted input to "strcpy, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | high | low | medium | low | high | mitigate |
| TARA-002 | Data handled by import_reqif (cmd_req.c) | An attacker supplies malformed/untrusted input to import_reqif, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-003 | Data handled by import_polarion_xml (cmd_req.c) | An attacker supplies malformed/untrusted input to import_polarion_xml, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-004 | Data handled by import_reqif (cmd_req.c) | An attacker supplies malformed/untrusted input to import_reqif, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-005 | Data handled by import_codebeamer_xml (cmd_req.c) | An attacker supplies malformed/untrusted input to import_codebeamer_xml, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-006 | Data handled by import_jama_xml (cmd_req.c) | An attacker supplies malformed/untrusted input to import_jama_xml, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-007 | Data handled by malloc (cmd_fix.c) | An attacker supplies malformed/untrusted input to malloc, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | high | low | medium | low | high | mitigate |
| TARA-008 | Data handled by malloc (cmd_fix.c) | An attacker supplies malformed/untrusted input to malloc, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | high | low | medium | low | high | mitigate |
| TARA-009 | Data handled by "strcpy (cmd_vuln.c) | An attacker supplies malformed/untrusted input to "strcpy, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | high | low | medium | low | high | mitigate |
| TARA-010 | Data handled by parse_sec_code (cmd_hara.c) | An attacker supplies malformed/untrusted input to parse_sec_code, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-011 | Data handled by cfusa_format_parse (report.c) | An attacker supplies malformed/untrusted input to cfusa_format_parse, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-012 | Data handled by cfusa_fopen_write (utils.c) | An attacker supplies malformed/untrusted input to cfusa_fopen_write, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |
| TARA-013 | Data handled by cfusa_config_load (config.c) | An attacker supplies malformed/untrusted input to cfusa_config_load, potentially causing incorrect behaviour, a crash, or information disclosure | local | medium | low | low | medium | low | medium | mitigate |

---
_Total assets analysed: 13 (100% of 13 discovered by the scan)_
