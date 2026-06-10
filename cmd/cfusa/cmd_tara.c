#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Generates a Threat Analysis & Risk Assessment skeleton (ISO 21434 Clause 9) */

static const char *THREAT_TEMPLATE_MD =
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
    "| [public/restricted/confidential/critical] | [std/specialised/bespoke/multiple]"
    " | [unlimited/easy/moderate/difficult] |\n\n"
    "## 5. Risk Determination\n\n"
    "| Threat | Impact | Feasibility | Risk Value | Risk Level |\n"
    "|---|---|---|---|---|\n"
    "| TS-001 | [1-4] | [1-4] | [Impact x Feasibility] | [LOW/MEDIUM/HIGH/CRITICAL] |\n\n"
    "## 6. Risk Treatment\n\n"
    "| Threat | Treatment | Cybersecurity Goal | Requirement Ref |\n"
    "|---|---|---|\n"
    "| TS-001 | [avoid/reduce/share/accept] | [goal] | [SRS-xxx] |\n\n"
    "---\n"
    "_Document owner: [name]_  \n"
    "_Review date: [date]_  \n"
    "_Standard: ISO 21434:2021 Clause 9_\n";

static void write_tara_json(FILE *f, const char *project,
                             const char *version, const char *ts)
{
    fprintf(f,
        "{\n"
        "  \"tool\": \"cfusa tara\",\n"
        "  \"project\": \"%s\",\n"
        "  \"version\": \"%s\",\n"
        "  \"generated\": \"%s\",\n"
        "  \"standard\": \"ISO 21434:2021 Clause 9\",\n"
        "  \"assets\": [\n"
        "    {\"id\":\"ASSET-001\",\"description\":\"[describe asset]\","
        "\"property\":\"CIA\"}\n"
        "  ],\n"
        "  \"threats\": [\n"
        "    {\n"
        "      \"id\": \"TS-001\",\n"
        "      \"asset\": \"ASSET-001\",\n"
        "      \"threat\": \"[describe threat]\",\n"
        "      \"attack_vector\": \"[local/remote/physical]\",\n"
        "      \"impact\": \"[none/low/med/high/severe]\",\n"
        "      \"feasibility\": \"[1-4]\",\n"
        "      \"risk_level\": \"[LOW/MEDIUM/HIGH/CRITICAL]\",\n"
        "      \"treatment\": \"[avoid/reduce/share/accept]\",\n"
        "      \"cybersecurity_goal\": \"[goal]\",\n"
        "      \"requirement_ref\": \"[SRS-xxx]\"\n"
        "    }\n"
        "  ]\n"
        "}\n",
        project, version, ts);
}

int cmd_tara(int argc, char **argv)
{
    const char *dir       = ".";
    const char *output    = NULL;
    const char *output_dir= NULL;
    const char *fmt_s     = NULL;  /* NULL = both tara.json + TARA.md */

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"output",     required_argument, NULL, 'o'},
        {"output-dir", required_argument, NULL, 'D'},
        {"format",     required_argument, NULL, 'f'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:D:f:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir        = optarg; break;
        case 'o': output     = optarg; break;
        case 'D': output_dir = optarg; break;
        case 'f': fmt_s      = optarg; break;
        case 'h':
            printf("Usage: cfusa tara [--dir <path>] [--output tara.md]\n"
                   "                  [--output-dir <dir>] [--format md|json]\n\n"
                   "Generates an ISO 21434 Clause 9 TARA document skeleton.\n"
                   "Default: writes both tara.json and tara.md.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char ts[32];
    cfusa_timestamp_now(ts);

    const char *base = output_dir ? output_dir : dir;

    /* Specific output file requested */
    if (output) {
        FILE *f = fopen(output, "w");
        if (!f) { perror(output); return 1; }
        if (fmt_s && !strcmp(fmt_s, "json")) {
            write_tara_json(f, cfg.project, cfg.version, ts);
        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
            fprintf(f, THREAT_TEMPLATE_MD, cfg.project, cfg.version, ts);
#pragma clang diagnostic pop
        }
        fclose(f);
        printf("TARA written to %s\n", output);
        return 0;
    }

    /* Single format */
    if (fmt_s) {
        char out_path[512];
        const char *fname = !strcmp(fmt_s,"json") ? "tara.json" : "tara.md";
        cfusa_path_join(out_path, sizeof(out_path), base, fname);
        FILE *f = fopen(out_path, "w");
        if (!f) { perror(out_path); return 1; }
        if (!strcmp(fmt_s, "json")) {
            write_tara_json(f, cfg.project, cfg.version, ts);
        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
            fprintf(f, THREAT_TEMPLATE_MD, cfg.project, cfg.version, ts);
#pragma clang diagnostic pop
        }
        fclose(f);
        printf("TARA written to %s\n", out_path);
        return 0;
    }

    /* Default: write both tara.json and TARA.md */
    char json_path[512], md_path[512];
    cfusa_path_join(json_path, sizeof(json_path), base, "tara.json");
    cfusa_path_join(md_path,   sizeof(md_path),   base, "tara.md");

    FILE *jf = fopen(json_path, "w");
    if (!jf) { perror(json_path); return 1; }
    write_tara_json(jf, cfg.project, cfg.version, ts);
    fclose(jf);
    printf("TARA skeleton written to %s\n", json_path);

    FILE *mf = fopen(md_path, "w");
    if (!mf) { perror(md_path); return 1; }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    fprintf(mf, THREAT_TEMPLATE_MD, cfg.project, cfg.version, ts);
#pragma clang diagnostic pop
    fclose(mf);
    printf("TARA skeleton written to %s\n", md_path);
    printf("Complete per ISO 21434:2021 Clause 9.\n");
    return 0;
}
