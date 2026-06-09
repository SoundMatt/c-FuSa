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

## Deviations

MISRA-C deviations must be formally documented. c-FuSa's `check` exit code reflects whether deviations are acceptable under your safety plan.

## Note

c-FuSa implements a pattern-based subset of MISRA-C rules. For full compliance analysis at production ASIL level, supplement with an accredited MISRA-C tool (e.g., LDRA, PC-lint Plus, Polyspace).
