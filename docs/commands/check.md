# cfusa check

Runs all registered rules — lint (MISRA-C), analyze (CERT-C), and cyber (CWE/ISO 21434) — in a single pass.

## Usage

```
cfusa check [--dir <path>] [--format text|json|sarif|html|md]
            [--output <file>] [--strict]
```

## Options

| Flag | Default | Description |
|---|---|---|
| `--dir` | `.` | Project root directory |
| `--format` | `text` | Output format |
| `--output` | stdout | Write report to file |
| `--strict` | off | Exit 1 on any WARNING (not just ERROR) |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No errors (or no findings) |
| 1 | One or more ERRORs found (or WARNINGs with `--strict`) |

## Examples

```bash
# Basic check
cfusa check --dir src/

# SARIF for GitHub Security tab
cfusa check --dir src/ --format sarif --output results.sarif

# HTML report
cfusa check --dir src/ --format html --output report.html

# Fail on any warning
cfusa check --dir src/ --strict
```

## Rules run

All `CFUSA-L*`, `CFUSA-A*`, and `CFUSA-CY*` rules. See `cfusa lint --list`, `cfusa analyze --list`, `cfusa cyber --list`.
