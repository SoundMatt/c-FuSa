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
| SLSA | Build provenance (SLSA v0.2), SPDX-3.0.1 SBOM |

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

### Docker

```bash
docker pull ghcr.io/soundmatt/c-fusa:latest
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/c-fusa check --dir /project/src
```

Or build locally:

```bash
docker build -t cfusa .
docker run --rm -v "$(pwd)":/project cfusa check --dir /project/src
```

### Requirements
- C99 compiler (gcc ≥ 9 or clang ≥ 12)
- CMake ≥ 3.16

---

## Quick Start

```bash
# Initialise your C project
cfusa init --project my-ecu --standard iso26262,misra-c

# Run all safety checks (exits 1 on errors)
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

# Auto-fix guidance — step-by-step remediation for every finding
cfusa fix --dir src/
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
| `fix` | Step-by-step remediation guidance for auto-fixable findings |
| `tara` | Threat Analysis & Risk Assessment → `tara.json` + `TARA.md` (ISO 21434 §9) |
| `fmea` | Design FMEA from function signatures → `fmea.json` + `fmea.csv` |
| `report` | Compliance report (text/json/sarif/html/md) |
| `template` | Safety doc templates (HARA, PSAC, safety-plan, test-evidence) |
| `trace` | Requirements traceability matrix from `.cfusa-reqs.json` |
| `req` | Show requirements and their impl/test source locations — `export`/`import` CSV/XML (DOORS/Polarion/Codebeamer/Jama) |
| `verify` | Collect and bundle test evidence |
| `release` | SBOM (SPDX-3.0.1 JSON), SLSA v0.2 provenance, artifact manifest |
| `qualify` | Tool self-test and qualification record |
| `safety-case` | GSN safety case skeleton + evidence index |
| `boundary` | Component dependency graph → `boundary.mermaid` + `boundary.dot` |
| `vuln` | Known-vulnerable function pattern scan (CWE/CVE) |
| `audit-pack` | Bundle all artifacts into audit package |
| `diff` | Compare two cfusa JSON reports |
| `badge` | SVG status badge from report |
| `hooks` | Install/remove git pre-commit hook |
| `sign` | HMAC-SHA256 file signing and verification |
| `do178` | DO-178C Annex A objective gap report |
| `sas` | Software Accomplishment Summary (DO-178C §11.20) |
| `sci` | Software Configuration Index with SHA-256 checksums |
| `coverage` | Structural coverage from gcov/lcov |
| `pr` | Problem report CRUD log (DO-178C §11.17) |
| `hara` | Hazard Analysis & Risk Assessment (ISO 26262-3 §6) — `init`/`show`/`asil` |
| `iso26262` | ISO 26262 Parts 6–11 compliance gap report (`--asil ASIL-A|B|C|D`) |
| `iec61508` | IEC 61508 Parts 1–3 compliance gap report (`--sil SIL-1|2|3|4`) |
| `misra` | MISRA C:2012 rule coverage mapping (`--gaps`) |
| `disposition` | Finding disposition tracking — `add`/`list`/`show` |
| `impact` | Change impact analysis on requirements (`--from`/`--to` git refs) |
| `metrics` | Safety metrics tracking over time — `record`/`show` |
| `coupling` | Data/control coupling analysis → `coupling-report.json` (DO-178C §6.4.4.3) |
| `iso21434` | ISO 21434 cybersecurity compliance gap report (`--cal CAL-1|2|3|4`) |
| `unece` | UN R.155 Annex 5 cybersecurity compliance gap report |
| `version` | Print version |

Run `cfusa <command> --help` for per-command options.

---

## Safety Runtime Library

`include/cfusa/runtime.h` provides five polling-based safety monitors for embedded C targets:

| Component | API | Purpose |
|-----------|-----|---------|
| `cfusa_watchdog_t` | `init / kick / check / stop` | Kick-based timeout detection (ISO 26262 ASIL-D, IEC 61508 SIL-4) |
| `cfusa_heartbeat_t` | `init / beat / check / stop` | Periodic beat health checking |
| `cfusa_state_mgr_t` | `init / get / transition` | Formal safe-state machine — 4 states, `EmergencyStop` is terminal (ISO 26262-4 §6.4.6) |
| `cfusa_diag_mgr_t` | `init / record / get / clear` | Bounded ring buffer of diagnostic events (CRITICAL/ERROR/WARNING/INFO) |
| `cfusa_fault_monitor_t` | `init / record / reset / count` | Per-fault occurrence counters with threshold callbacks |

All components are **thread-oblivious** (no internal threads — the caller drives the check loop), **zero-dependency** (only `<string.h>` and `<time.h>`), and suitable for MISRA-C:2012 environments.

```c
#include "cfusa/runtime.h"

/* Watchdog: fire safe state if not kicked within 100 ms */
static void on_expired(void *u) { (void)u; enter_safe_state(); }
cfusa_watchdog_t wd;
cfusa_watchdog_init(&wd, 0.1, on_expired, NULL);

/* In main loop */
cfusa_watchdog_kick(&wd);   /* reset from monitored task */
cfusa_watchdog_check(&wd);  /* check from scheduler tick */
```

---

## Requirements Traceability

Create a requirements registry at `.cfusa-reqs.json` (copy from `.cfusa-reqs.json.template`):

```json
{
  "requirements": [
    {
      "id": "REQ-ANA001",
      "title": "Null pointer check before dereference",
      "text": "The tool shall report any dereference of a pointer that is not checked for NULL.",
      "standard": "ISO 26262",
      "level": "ASIL-B"
    }
  ]
}
```

Annotate source with `//cfusa:` comments:

```c
//cfusa:req REQ-ANA001
int check_pointer(const void *p) {
    if (!p) return -1;    //cfusa:test REQ-ANA001
    return 0;
}
```

Then run:

```bash
cfusa trace --dir src/               # full traceability matrix
cfusa trace --gaps                   # requirements with no test annotation
cfusa trace --req-coverage 90        # exit 1 if <90% of requirements are traced
cfusa trace --sec-tested 80          # exit 1 if <80% of requirements are tested
cfusa req --dir src/                 # list all requirements with locations
cfusa req REQ-ANA001                 # show single requirement detail

# Import/export requirements as CSV
cfusa req export --output requirements.csv
cfusa req import requirements.csv
cfusa req import --format codebeamer cb-export.csv
cfusa req import --format jama jama-export.csv
cfusa req import --format doors requirements.reqif
```

Legacy `// REQ: ID` annotations are also supported. Use `--no-legacy` to disable.

---

## FMEA

```bash
cfusa fmea --dir src/                 # generates fmea.json + fmea.csv
cfusa fmea --dir src/ --cyber         # enriches with cybersecurity failure modes
cfusa fmea --dir src/ --format md     # generates FMEA.md only
cfusa fmea --output-dir artifacts/    # write to specific directory
```

Default output is both `fmea.json` (structured data) and `fmea.csv` (importable into Excel/JIRA).

---

## Release Artifacts

```bash
cfusa release --dir .                 # SPDX-3.0.1 SBOM + SLSA provenance
cfusa release --dir . --full          # + fmea, boundary, vuln, SHA256SUMS
```

Generates in `.cfusa_release/`:
- `<project>-<version>.spdx.json` — SPDX 3.0.1 JSON SBOM
- `provenance.json` — SLSA v0.2 provenance with git commit SHA
- `fmea.json` + `fmea.csv` (with `--full`)
- `boundary.mermaid` + `boundary.dot` (with `--full`)
- `vuln-report.json` (with `--full`)
- `SHA256SUMS` (with `--full`)

---

## Fix Guidance

```bash
cfusa fix --dir src/
```

Re-runs all checks and prints step-by-step remediation for every finding that has a deterministic fix, across 18 rules in LINT, ANALYZE, and CYBER categories.

---

## Hazard Analysis (HARA)

```bash
cfusa hara init --dir .                    # create .cfusa-hara.json skeleton
cfusa hara show --dir .                    # list hazards with ASIL ratings
cfusa hara asil --severity 3 --exposure 3 --controllability 2  # compute ASIL
```

ASIL is computed per ISO 26262-3:2018 Table 4 from severity (S1–S4), exposure (E1–E4), and controllability (C1–C3).

---

## Standards Gap Reports

```bash
cfusa iso26262 --asil ASIL-D              # ISO 26262 Part 6 gap report
cfusa iec61508 --sil SIL-3                # IEC 61508 Parts 1-3 gap report
cfusa misra --gaps                        # MISRA C:2012 uncovered rules only
```

---

## Finding Disposition Tracking

```bash
cfusa disposition add --rule CFUSA-L003 \
    --action accept \
    --rationale "Heap used only at startup under supervision" \
    --reviewer "jane.doe" \
    --ref "JIRA-123"
cfusa disposition list
cfusa disposition show DISP-0001
```

Dispositions are stored in `.cfusa-dispositions.json`.

---

## Change Impact Analysis

```bash
cfusa impact --from main --to HEAD        # requirements impacted by this branch
cfusa impact --from v1.0 --to v1.1       # requirements impacted between releases
```

Maps git-changed files back to `//cfusa:req` annotations and `.cfusa-reqs.json`.

---

## Safety Metrics Tracking

```bash
# Record after a cfusa check run
cfusa metrics record --errors 5 --warnings 12 --info 3 --label ci-build-42
cfusa metrics show
```

Metrics are appended to `.cfusa-metrics.jsonl` for trend analysis over time.

---

## Docker Compose Pipeline

```bash
# Run the full pipeline (check → trace → qualify → release)
docker compose run pipeline
```

Or run individual commands:

```bash
docker compose run cfusa check --dir /project/src
docker compose run cfusa hara show
```

---

## DO-178C Support

```bash
cfusa do178 --dal a                      # DAL A objective gap report
cfusa sas --output SAS.md               # Software Accomplishment Summary
cfusa sci --output SCI.md               # Software Configuration Index
cfusa pr --new --title "divide by zero" --severity major
cfusa coverage --lcov coverage.info --mcdc  # MC/DC coverage analysis
cfusa coverage --mutate-score 95            # Mutation score evidence (DO-178C DAL A/B)
```

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
| CFUSA-A001 | Unsafe string functions (`gets`, `strcpy`, …) | CERT-C STR31-C |
| CFUSA-A002 | Unchecked allocation return value | CERT-C MEM32-C |
| CFUSA-A003 | Signed/unsigned comparison | CERT-C INT02-C |
| CFUSA-A004 | Integer boundary constant without guard | CERT-C INT30-C |
| CFUSA-A005 | `assert()` in production code | CERT-C MSC11-C |
| CFUSA-A006 | Pointer arithmetic | MISRA-C:2012 R18.4 |
| CFUSA-A007 | Unchecked system call return value | CERT-C ERR33-C |

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

Copy `.cfusa.json.template` and `.cfusa-reqs.json.template` to start a new project.

---

## GitHub Actions Integration

```yaml
- name: cfusa safety check
  run: |
    cmake -B build && cmake --build build
    ./build/cfusa check --dir src/ --format sarif --output results.sarif
    ./build/cfusa trace --req-coverage 80 --sec-tested 70

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full matrix build (ubuntu-22.04/gcc, ubuntu-22.04/clang, macos-14/clang), coverage, and SARIF upload.

---

## Self-check

c-FuSa validates itself on every CI run:

```bash
cfusa check --dir . --format json --output cfusa-self-check.json
```

The self-check report is uploaded as a CI artifact on each build.

---

## Architecture

```
c-FuSa/
├── cmd/cfusa/       # 40 command files (one per command)
├── include/cfusa/   # Public headers
├── src/             # Core library (engine, report, config, utils + SHA-256)
├── tests/           # Unity test suite (28 suites, 500+ tests)
├── vendor/unity/    # Unity test framework (MIT)
├── .github/         # CI, CodeQL workflows
├── .cfusa.json              # Project config
├── .cfusa.json.template     # Template for new projects
├── .cfusa-reqs.json.template # Requirements registry template
└── CMakeLists.txt
```

Zero external runtime dependencies. SHA-256 / HMAC-SHA256 implemented in-tree.

---

## Related

- [go-FuSa](https://github.com/SoundMatt/go-FuSa) — the Go equivalent for Go projects

---

## License

[Mozilla Public License 2.0](LICENSE)
