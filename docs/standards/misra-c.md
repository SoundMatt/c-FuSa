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

MISRA-C deviations must be formally documented. c-FuSa's `check` exit code reflects whether deviations are acceptable under your safety plan.

## Note

c-FuSa implements a pattern-based subset of MISRA-C rules. For full compliance analysis at production ASIL level, supplement with an accredited MISRA-C tool (e.g., LDRA, PC-lint Plus, Polyspace).

**At ASIL-C/D this is not optional.** `cfusa misra` scales its own note accordingly: a project declaring `iso26262:ASIL-C` or `iso26262:ASIL-D` in `.fusa.json`'s `standards[]` gets a `REQUIRED` (not `RECOMMENDED`) accredited-tool note in both text and JSON (`accreditedToolNote`) output — c-FuSa's pattern-based subset alone is not sufficient evidence for a production ASIL-C/D MISRA-C compliance claim.
