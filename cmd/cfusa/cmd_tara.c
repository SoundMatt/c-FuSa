#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Generates a Threat Analysis & Risk Assessment skeleton (ISO 21434 Clause 9) */

static const char *THREAT_TEMPLATE =
    "# Threat Analysis and Risk Assessment (TARA)\n"
    "## ISO 21434 Clause 9 — %s v%s\n"
    "Generated: %s\n\n"
    "---\n\n"
    "## 1. Asset Identification\n\n"
    "| Asset | Description | Security Property |\n"
    "|---|---|---|\n"
    "| ASSET-001 | [describe asset] | Confidentiality / Integrity / Availability |\n\n"
    "## 2. Threat Scenarios\n\n"
    "| ID | Asset | Threat | Attack Vector | Attacker Profile |\n"
    "|---|---|---|---|---|\n"
    "| TS-001 | ASSET-001 | [describe threat] | [local/remote/physical] | [profile] |\n\n"
    "## 3. Impact Assessment\n\n"
    "| Threat | Safety Impact | Financial Impact | Operational Impact | Privacy Impact |\n"
    "|---|---|---|---|---|\n"
    "| TS-001 | [none/low/med/high/severe] | [pct revenue] | [operational days] | [# subjects] |\n\n"
    "## 4. Attack Feasibility\n\n"
    "| Threat | Elapsed Time | Expertise | Knowledge | Equipment | Windows |\n"
    "|---|---|---|---|---|---|\n"
    "| TS-001 | [1day/1wk/1mo/3mo/>6mo] | [layman/proficient/expert/multiple] "
    "| [public/restricted/confidential/critical] | [std/specialised/bespoke/multiple] | [unlimited/easy/moderate/difficult] |\n\n"
    "## 5. Risk Determination\n\n"
    "| Threat | Impact | Feasibility | Risk Value | Risk Level |\n"
    "|---|---|---|---|---|\n"
    "| TS-001 | [1-4] | [1-4] | [Impact x Feasibility] | [LOW/MEDIUM/HIGH/CRITICAL] |\n\n"
    "## 6. Risk Treatment\n\n"
    "| Threat | Treatment | Cybersecurity Goal | Requirement Ref |\n"
    "|---|---|---|---|\n"
    "| TS-001 | [avoid/reduce/share/accept] | [goal] | [SRS-xxx] |\n\n"
    "---\n"
    "_Document owner: [name]_  \n"
    "_Review date: [date]_  \n"
    "_Standard: ISO 21434:2021 Clause 9_\n";

int cmd_tara(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = "TARA.md";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa tara [--dir <path>] [--output TARA.md]\n\n"
                   "Generates an ISO 21434 Clause 9 TARA document skeleton.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char ts[32];
    cfusa_timestamp_now(ts);

    char out_path[512];
    cfusa_path_join(out_path, sizeof(out_path),
                    (output[0]=='/') ? "" : dir, output);
    if (output[0]=='/') strncpy(out_path, output, sizeof(out_path)-1);

    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    fprintf(f, THREAT_TEMPLATE, cfg.project, cfg.version, ts);
#pragma clang diagnostic pop
    fclose(f);

    printf("TARA skeleton written to %s\n", out_path);
    printf("Complete per ISO 21434:2021 Clause 9.\n");
    return 0;
}
