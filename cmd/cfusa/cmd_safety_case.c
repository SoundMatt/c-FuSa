#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Generates a GSN (Goal Structuring Notation) safety case skeleton
 * and assembles available evidence into a safety case index.
 */

int cmd_safety_case(int argc, char **argv)
{
    const char *dir      = ".";
    const char *output   = "SAFETY_CASE.md";
    const char *standard = NULL;
    int gsn_only = 0;

    static const struct option long_opts[] = {
        {"dir",      required_argument, NULL, 'd'},
        {"output",   required_argument, NULL, 'o'},
        {"standard", required_argument, NULL, 'S'},
        {"gsn",      no_argument,       NULL, 'g'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:S:gh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg; break;
        case 'o': output   = optarg; break;
        case 'S': standard = optarg; break;
        case 'g': gsn_only = 1;     break;
        case 'h':
            printf("Usage: cfusa safety-case [--dir <path>] [--output SAFETY_CASE.md]\n"
                   "                          [--standard iso26262|do178c|iec61508]\n"
                   "                          [--gsn]\n\n"
                   "Generates a GSN safety case skeleton with evidence index.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    if (!standard) standard = cfg.standards_count ? cfg.standards[0] : "iso26262";

    char out_path[512];
    if (output[0]=='/') strncpy(out_path,output,sizeof(out_path)-1);
    else cfusa_path_join(out_path,sizeof(out_path),dir,output);

    FILE *f = fopen(out_path,"w");
    if (!f) { perror(out_path); return 1; }

    char ts[32]; cfusa_timestamp_now(ts);

    fprintf(f,
        "# Safety Case — %s v%s\n\n"
        "**Standard:** %s  |  **Generated:** %s\n\n"
        "---\n\n"
        "## G1 — Top-Level Goal\n\n"
        "> **%s is acceptably safe for its intended use in its intended environment**\n\n"
        "### Evidence for G1\n\n"
        "| Evidence Item | Source | Status |\n|---|---|---|\n"
        "| Hazard analysis complete | HARA.md | [ ] |\n"
        "| Safety requirements defined | SAFETY_PLAN.md | [ ] |\n"
        "| MISRA-C lint clean | cfusa lint | [ ] |\n"
        "| Static analysis clean | cfusa analyze | [ ] |\n"
        "| Cybersecurity analysis complete | cfusa cyber / TARA.md | [ ] |\n"
        "| Test evidence complete | cfusa verify | [ ] |\n"
        "| Coverage targets met | cfusa coverage | [ ] |\n"
        "| FMEA complete | FMEA.md | [ ] |\n"
        "| Tool qualification | cfusa qualify | [ ] |\n"
        "| SCI produced | cfusa sci | [ ] |\n\n"
        "---\n\n"
        "## G1.1 — Hazard Elimination\n\n"
        "> **All identified hazards are either eliminated or controlled to an acceptable level**\n\n"
        "- Context: C1 — Operating environment is [describe]\n"
        "- Strategy: S1 — Argue over identified hazardous events\n\n"
        "### G1.1 Sub-goals\n\n"
        "| ID | Sub-goal | Evidence |\n|---|---|---|\n"
        "| G1.1.1 | Hazardous event HE-001 risk is [ASIL] or below | HARA.md §2 |\n"
        "| G1.1.2 | Software contributes no additional hazards | cfusa check (exit 0) |\n\n"
        "---\n\n"
        "## G1.2 — Process Confidence\n\n"
        "> **The software development process is sufficient to give confidence in the result**\n\n"
        "- S2 — Argue over process compliance\n\n"
        "| ID | Sub-goal | Evidence |\n|---|---|---|\n"
        "| G1.2.1 | Coding standard followed | cfusa lint (exit 0) |\n"
        "| G1.2.2 | Requirements traced to code | cfusa trace |\n"
        "| G1.2.3 | Test coverage meets threshold | cfusa coverage |\n"
        "| G1.2.4 | All PRs resolved | cfusa pr --status open |\n\n"
        "---\n\n"
        "## Assumptions\n\n"
        "- A1: The hardware is assumed safe as per [HW safety case reference]\n"
        "- A2: The operating environment is as described in [SRS reference]\n\n"
        "---\n\n"
        "_Safety case owner: [name / role]_  \n"
        "_Last reviewed: [date]_  \n"
        "_Next review: [date]_\n",
        cfg.project, cfg.version, standard, ts, cfg.project);

    if (!gsn_only) {
        /* Check for existing evidence files */
        fprintf(f, "\n---\n\n## Evidence Index\n\n"
                "| File | Present | SHA-256 |\n|---|---|---|\n");

        static const char * const evidence_files[] = {
            "HARA.md","SAFETY_PLAN.md","TARA.md","FMEA.md",
            "TEST_EVIDENCE.md","SAS.md",".cfusa.json",NULL
        };
        for (int i=0; evidence_files[i]; i++) {
            char ep[512];
            cfusa_path_join(ep, sizeof(ep), dir, evidence_files[i]);
            if (cfusa_file_exists(ep)) {
                char hex[65];
                cfusa_sha256_file(ep, hex);
                fprintf(f,"| %s | ✓ | `%s` |\n", evidence_files[i], hex);
            } else {
                fprintf(f,"| %s | ✗ (missing) | — |\n", evidence_files[i]);
            }
        }
    }

    fclose(f);
    printf("Safety case written to %s\n", out_path);
    return 0;
}
