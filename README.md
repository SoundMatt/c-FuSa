# c-FuSa

**C functional safety toolkit** — a CLI that reduces the cost of producing safety evidence for C projects throughout the development lifecycle.

[![CI](https://github.com/SoundMatt/c-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/c-FuSa/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SoundMatt/c-FuSa/actions/workflows/codeql.yml/badge.svg)](https://github.com/SoundMatt/c-FuSa/actions/workflows/codeql.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

> **c-FuSa is not a certification product.** It is an engineering accelerator — helping you produce and maintain safety evidence faster.

---

## Standards

| Standard | Coverage |
|---|---|
| ISO 26262 | HARA, FMEA, safety case, traceability |
| IEC 61508 | Functional safety lifecycle |
| ISO 21434 | TARA, CWE-mapped cyber rules |
| DO-178C | Annex A objectives, SAS, SCI, problem reports |
| MISRA-C:2012 | Lint rules (L001–L010) |
| CERT-C | Static analysis and cybersecurity rules |
| SLSA | Build provenance, SBOM |

---

## Install

### From source (CMake)

```bash
git clone https://github.com/SoundMatt/c-FuSa.git
cd c-FuSa
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
sudo cmake --install build        # installs to /usr/local/bin/cfusa
```

### Requirements
- C99 compiler (gcc ≥ 9 or clang ≥ 12)
- CMake ≥ 3.16

---

## Quick Start

```bash
# Initialise your C project
cfusa init --project my-ecu --standard iso26262,misra-c

# Run all safety checks
cfusa check --dir src/

# MISRA-C lint only
cfusa lint --dir src/ --format text

# Static analysis
cfusa analyze --dir src/

# Cybersecurity rules (ISO 21434 / CWE)
cfusa cyber --dir src/

# SARIF report for GitHub Security tab
cfusa check --dir src/ --format sarif --output results.sarif

# HTML report
cfusa report --dir src/ --format html --output report.html
```

---

## Commands

| Command | Description |
|---|---|
| `init` | Initialise `.cfusa.json` project config |
| `check` | Run all checks (exits 1 on errors; `--strict` on warnings too) |
| `lint` | MISRA-C:2012 / CERT-C coding standard rules |
| `analyze` | Static analysis — overflows, unchecked returns, pointer issues |
| `cyber` | CWE-mapped cybersecurity rules (ISO 21434) |
| `tara` | Threat Analysis & Risk Assessment skeleton (ISO 21434 §9) |
| `fmea` | Design FMEA skeleton from function signatures |
| `report` | Compliance report (text/json/sarif/html/md) |
| `template` | Safety doc templates (HARA, PSAC, safety-plan, test-evidence) |
| `trace` | Requirements traceability matrix from `// REQ:` annotations |
| `verify` | Collect and bundle test evidence |
| `release` | SBOM (SPDX-2.3), build provenance, artifact checksums |
| `qualify` | Tool self-test and qualification record |
| `safety-case` | GSN safety case skeleton + evidence index |
| `boundary` | Component dependency graph from `#include` directives |
| `vuln` | Known-vulnerable function pattern scan |
| `audit-pack` | Bundle all artifacts into audit package |
| `diff` | Compare two cfusa JSON reports |
| `badge` | SVG status badge from report |
| `req` | Show source locations for a requirement ID |
| `fix` | Apply mechanical auto-fixes |
| `hooks` | Install/remove git pre-commit hook |
| `sign` | HMAC-SHA256 file signing and verification |
| `do178` | DO-178C Annex A objective gap report |
| `sas` | Software Accomplishment Summary (DO-178C §11.20) |
| `sci` | Software Configuration Index with SHA-256 checksums |
| `coverage` | Structural coverage from gcov/lcov |
| `pr` | Problem report CRUD log (DO-178C §11.17) |
| `version` | Print version |

Run `cfusa <command> --help` for per-command options.

---

## Lint Rules (CFUSA-L series)

| ID | Rule | Standard |
|---|---|---|
| CFUSA-L001 | Function length > `max_function_lines` | MISRA-C:2012 R15.5 |
| CFUSA-L002 | Use of `goto` | MISRA-C:2012 R15.1 |
| CFUSA-L003 | Dynamic memory (`malloc`/`free`) | MISRA-C:2012 R21.3 |
| CFUSA-L004 | Recursive function call | MISRA-C:2012 R17.2 |
| CFUSA-L005 | Use of `#undef` | MISRA-C:2012 R20.5 |
| CFUSA-L006 | `setjmp`/`longjmp` | MISRA-C:2012 R17.4 |
| CFUSA-L007 | Mutable static variable | MISRA-C:2012 R8.9 |
| CFUSA-L008 | `void*` usage | MISRA-C:2012 R11.5 |
| CFUSA-L009 | `#pragma` directive | MISRA-C:2012 R20.10 |
| CFUSA-L010 | `errno` usage pattern | MISRA-C:2012 R22.8 |

## Analyze Rules (CFUSA-A series)

| ID | Rule | Standard |
|---|---|---|
| CFUSA-A001 | Unsafe string functions | CERT-C STR31-C |
| CFUSA-A002 | Unchecked allocation | CERT-C MEM32-C |
| CFUSA-A003 | Signed/unsigned comparison with `sizeof` | CERT-C INT02-C |
| CFUSA-A004 | Integer boundary constant without guard | CERT-C INT30-C |
| CFUSA-A005 | `assert()` in production | CERT-C MSC11-C |
| CFUSA-A006 | Pointer arithmetic | MISRA-C:2012 R18.4 |
| CFUSA-A007 | Unchecked system call return | CERT-C ERR33-C |

## Cyber Rules (CFUSA-CY series)

| ID | CWE | Rule |
|---|---|---|
| CFUSA-CY001 | CWE-120 | Buffer copy without size check |
| CFUSA-CY002 | CWE-134 | Uncontrolled format string |
| CFUSA-CY003 | CWE-78 | OS command injection |
| CFUSA-CY004 | CWE-476 | NULL pointer dereference after alloc |
| CFUSA-CY005 | CWE-190 | Integer overflow in allocation size |
| CFUSA-CY006 | CWE-416 | Use after free |
| CFUSA-CY007 | CWE-415 | Double free |
| CFUSA-CY008 | CWE-377 | Insecure temp file creation |
| CFUSA-CY009 | CWE-327 | Broken cryptographic algorithm |
| CFUSA-CY010 | CWE-676 | Potentially dangerous function |

---

## Configuration (`.cfusa.json`)

```json
{
  "project": "my-ecu",
  "version": "1.0.0",
  "strict": false,
  "max_function_lines": 50,
  "standards": ["iso26262", "misra-c", "do178c"],
  "exclude_dirs": ["build", "vendor", ".git"],
  "src_extensions": [".c", ".h"]
}
```

---

## Requirements Traceability

Annotate source with `// REQ:` comments:

```c
/* REQ: SRS-001, SRS-007 */
int compute_braking_force(int pedal_pos) { ... }
```

Then:

```bash
cfusa trace --dir src/ --format md --output RTM.md
cfusa req SRS-001 --dir src/
```

---

## DO-178C Support

```bash
cfusa do178 --dal a                      # DAL A objective gap report
cfusa sas --output SAS.md               # Software Accomplishment Summary
cfusa sci --output SCI.md               # Software Configuration Index
cfusa pr --new --title "divide by zero" --severity major
cfusa coverage --lcov coverage.info --mcdc  # MC/DC coverage
```

---

## GitHub Actions Integration

Add to `.github/workflows/ci.yml`:

```yaml
- name: cfusa safety check
  run: |
    cmake -B build && cmake --build build
    ./build/cfusa check --dir src/ --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Architecture

```
c-FuSa/
├── cmd/cfusa/       # 29 command files (one per command)
├── include/cfusa/   # Public headers
├── src/             # Core library (engine, report, config, utils + SHA-256)
├── tests/           # Unity test suite
├── vendor/unity/    # Unity test framework (MIT)
├── .github/         # CI, release, CodeQL workflows
└── CMakeLists.txt
```

Zero external runtime dependencies. SHA-256 / HMAC-SHA256 implemented in-tree.

---

## Related

- [go-FuSa](https://github.com/SoundMatt/go-FuSa) — the Go equivalent

---

## License

[Mozilla Public License 2.0](LICENSE)
