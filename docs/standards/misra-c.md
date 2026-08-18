# MISRA-C:2012 in c-FuSa

MISRA-C:2012 (Motor Industry Software Reliability Association) defines mandatory and advisory coding rules for safety-critical C software.

## Rule mapping

| cfusa Rule | MISRA-C Rule | Category |
|---|---|---|
| CFUSA-L001 | Rule 15.5 (analogue) | Mandatory |
| CFUSA-L002 | Rule 15.1 | Required |
| CFUSA-L003 | Rule 21.3 | Required |
| CFUSA-L004 | Rule 17.2 | Required |
| CFUSA-L005 | Rule 20.5 | Advisory |
| CFUSA-L006 | Rule 17.4 | Mandatory |
| CFUSA-L007 | Rule 8.9 | Advisory |
| CFUSA-L008 | Rule 11.5 | Advisory |
| CFUSA-L009 | Rule 20.10 | Advisory |
| CFUSA-L010 | Rule 22.8 | Required |
| CFUSA-L011 | Rule 7.1 | Required |
| CFUSA-L012 | Rule 20.4 | Required |

## Deviations

MISRA-C deviations must be formally documented. `cfusa disposition add --rule <ID> --fingerprint <sha256:...> --action accept|fix|mitigate --rationale <text> --reviewer <name>` records one in `.fusa-dispositions.json` (rationale, reviewer, timestamp — `cfusa disposition list`/`show` read it back).

**`cfusa check`/`cfusa lint` enforce accepted deviations** (as of [issue #122](https://github.com/SoundMatt/c-FuSa/issues/122)): a finding whose `fingerprint` (shown next to every finding in `cfusa check`/`cfusa lint` text output, and as `"fingerprint"` in JSON) matches an `accept`- or `mitigate`-action disposition is excluded from the exit-code gate — it never disappears from the report, it's tagged `[DISPOSITIONED accept: DISP-0007]` inline instead, and the JSON summary carries a separate `"dispositioned"` count so a reviewed-and-accepted deviation is never confused with an actual fix.

**Scoping is fingerprint-based, not rule-based.** `--rule` alone is never used to suppress — recording `--rule CFUSA-L003` without `--fingerprint` exempts nothing; it's an audit note only. Keying off `--rule` would silently exempt *every future finding under that rule ID, anywhere in the codebase*, which is too coarse for a real deviation record. A `fix`-action disposition also never suppresses (it's a historical note — the code presumably no longer matches, so there is nothing live to suppress).

## Note

c-FuSa implements a pattern-based subset of MISRA-C rules. For full compliance analysis at production ASIL level, supplement with an accredited MISRA-C tool (e.g., LDRA, PC-lint Plus, Polyspace).

**At ASIL-C/D this is not optional.** `cfusa misra` scales its own note accordingly: a project declaring `iso26262:ASIL-C` or `iso26262:ASIL-D` in `.fusa.json`'s `standards[]` gets a `REQUIRED` (not `RECOMMENDED`) accredited-tool note in both text and JSON (`accreditedToolNote`) output — c-FuSa's pattern-based subset alone is not sufficient evidence for a production ASIL-C/D MISRA-C compliance claim.
