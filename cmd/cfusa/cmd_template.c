#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

typedef struct {
    const char *name;
    const char *filename;
    const char *description;
    const char *content;
} template_t;

static const template_t TEMPLATES[] = {
    {
        "safety-plan",
        "SAFETY_PLAN.md",
        "Software Safety Plan (ISO 26262 / IEC 61508)",
        "# Software Safety Plan\n\n"
        "**Project:** {PROJECT}  \n**Version:** {VERSION}  \n**Standard:** ISO 26262 Part 6\n\n"
        "## 1. Scope\n\n[Describe the software item and its safety context]\n\n"
        "## 2. Safety Requirements\n\n"
        "| ID | Requirement | ASIL | Rationale |\n|---|---|---|---|\n"
        "| SR-001 | [requirement] | [A/B/C/D] | [rationale] |\n\n"
        "## 3. Software Development Lifecycle\n\n"
        "- **Requirements phase**: [tools, review process]\n"
        "- **Design phase**: [architecture approach, design constraints]\n"
        "- **Implementation phase**: [coding standard: MISRA-C:2012]\n"
        "- **Verification**: [unit test framework, coverage target]\n\n"
        "## 4. Tool Qualification\n\nRun `cfusa qualify` to produce tool qualification evidence.\n\n"
        "## 5. Configuration Management\n\nAll source under version control. "
        "Run `cfusa sci` to produce Software Configuration Index.\n\n"
        "## 6. Deviations\n\n[Record any deviations from this plan here]\n"
    },
    {
        "test-evidence",
        "TEST_EVIDENCE.md",
        "Test Evidence Summary (DO-178C / ISO 26262)",
        "# Test Evidence Summary\n\n"
        "**Project:** {PROJECT}  \n**Version:** {VERSION}  \n**Generated:** {TIMESTAMP}\n\n"
        "## Test Environment\n\n"
        "| Item | Details |\n|---|---|\n"
        "| Host OS | [OS/version] |\n"
        "| Compiler | [gcc/clang version] |\n"
        "| Test framework | Unity vX.Y |\n"
        "| Coverage tool | gcov/lcov |\n\n"
        "## Test Results\n\nRun `cfusa verify --dir .` to collect test evidence.\n\n"
        "## Coverage\n\nRun `cfusa coverage --lcov coverage.info` for coverage report.\n\n"
        "## Discrepancies\n\n[List any test failures and their disposition]\n"
    },
    {
        "hara",
        "HARA.md",
        "Hazard Analysis and Risk Assessment (ISO 26262 Part 3)",
        "# Hazard Analysis and Risk Assessment (HARA)\n\n"
        "**Project:** {PROJECT}  \n**Version:** {VERSION}\n\n"
        "## 1. Hazardous Events\n\n"
        "| ID | Hazardous Event | Severity | Exposure | Controllability | ASIL |\n"
        "|---|---|---|---|---|---|\n"
        "| HE-001 | [describe] | [S0-S3] | [E0-E4] | [C0-C3] | [QM/A/B/C/D] |\n\n"
        "## 2. Safety Goals\n\n"
        "| ID | Safety Goal | ASIL | Ref |\n|---|---|---|---|\n"
        "| SG-001 | [safety goal] | [ASIL] | HE-001 |\n\n"
        "## 3. Safe States\n\n[Describe safe states for each hazardous event]\n"
    },
    {
        "psac",
        "PSAC.md",
        "Plan for Software Aspects of Certification (DO-178C §11.1)",
        "# Plan for Software Aspects of Certification (PSAC)\n\n"
        "**Project:** {PROJECT}  \n**Version:** {VERSION}  \n**DAL:** [A/B/C/D]\n\n"
        "## 1. System Overview\n\n[System description and software function]\n\n"
        "## 2. Software Overview\n\n[Software partitioning, interfaces, languages]\n\n"
        "## 3. Certification Basis\n\n[FAA order, TSO, etc.]\n\n"
        "## 4. Compliance Approach\n\n[How DO-178C objectives will be met]\n\n"
        "## 5. Software Life Cycle\n\n[Phases, transition criteria, reviews]\n\n"
        "## 6. Software Life Cycle Data\n\nRun `cfusa sas` to generate SAS skeleton.\n\n"
        "## 7. Schedule\n\n[Milestone dates]\n"
    },
    {NULL, NULL, NULL, NULL}
};

int cmd_template(int argc, char **argv)
{
    const char *dir  = ".";
    const char *name = NULL;
    int list = 0;

    static const struct option long_opts[] = {
        {"dir",  required_argument, NULL, 'd'},
        {"list", no_argument,       NULL, 'l'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:lh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir  = optarg; break;
        case 'l': list = 1;     break;
        case 'h':
            printf("Usage: cfusa template [--list] [--dir <path>] [<name>]\n\n"
                   "Available templates: safety-plan, test-evidence, hara, psac\n\n"
                   "Example: cfusa template safety-plan\n");
            return 0;
        default: return 1;
        }
    }
    if (optind < argc) name = argv[optind];

    if (list || !name) {
        printf("Available templates:\n\n");
        for (int i=0; TEMPLATES[i].name; i++)
            printf("  %-18s %s  →  %s\n",
                   TEMPLATES[i].name, TEMPLATES[i].description,
                   TEMPLATES[i].filename);
        printf("\nUsage: cfusa template <name>\n");
        return 0;
    }

    const template_t *tmpl = NULL;
    for (int i=0; TEMPLATES[i].name; i++)
        if (!strcmp(TEMPLATES[i].name, name)) { tmpl = &TEMPLATES[i]; break; }

    if (!tmpl) {
        fprintf(stderr,"cfusa template: unknown template '%s'\n",name);
        fprintf(stderr,"Run 'cfusa template --list' for available templates.\n");
        return 1;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char out_path[512];
    cfusa_path_join(out_path, sizeof(out_path), dir, tmpl->filename);

    FILE *f = fopen(out_path,"w");
    if (!f) { perror(out_path); return 1; }

    char ts[32]; cfusa_timestamp_now(ts);

    /* Simple substitution */
    const char *p = tmpl->content;
    while (*p) {
        if (strncmp(p,"{PROJECT}",9)==0)  { fputs(cfg.project,f); p+=9; }
        else if (strncmp(p,"{VERSION}",9)==0)  { fputs(cfg.version,f); p+=9; }
        else if (strncmp(p,"{TIMESTAMP}",11)==0){ fputs(ts,f); p+=11; }
        else fputc(*p++, f);
    }
    fclose(f);

    printf("Template '%s' written to %s\n", name, out_path);
    return 0;
}
