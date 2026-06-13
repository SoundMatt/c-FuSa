#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * IEC 62443-4-2 Component Security Requirements gap report.
 * Maps CFUSA rules to IEC 62443 Foundational Requirements (FR 1–7)
 * by Security Level (SL 1–4).
 */

//cfusa:req REQ-IEC62443-001 REQ-IEC62443-002 REQ-IEC62443-003 REQ-IEC62443-004

#define IEC62443_FILE        ".fusa-iec62443.json"
#define IEC62443_FILE_LEGACY ".cfusa-iec62443.json"

typedef struct {
    const char *cr;        /* component requirement, e.g. "CR 3.5" */
    const char *fr;        /* foundational requirement tag */
    const char *title;
    const char *cfusa_rule; /* NULL = not yet covered */
    int         sl1;        /* 1=required (M), 2=recommended (R), 0=N/A */
    int         sl2;
    int         sl3;
    int         sl4;
} iec62443_row_t;

/* 1=required (M), 2=recommended (R), 0=not applicable (-) */
static const iec62443_row_t REQUIREMENTS[] = {
    /* FR 1 — Identification and Authentication Control (IAC) */
    {"CR 1.1",  "FR1", "Human user identification and authentication",   NULL,           1,1,1,1},
    {"CR 1.2",  "FR1", "Software process identification and authentication", NULL,       0,1,1,1},
    {"CR 1.5",  "FR1", "Authenticator management",                       NULL,           1,1,1,1},
    {"CR 1.7",  "FR1", "Strength of password-based authentication",      "CFUSA-CY008", 1,1,1,1},
    {"CR 1.11", "FR1", "Unsuccessful login attempts",                    NULL,           0,1,1,1},

    /* FR 2 — Use Control (UC) */
    {"CR 2.1",  "FR2", "Authorization enforcement",                      NULL,           1,1,1,1},
    {"CR 2.8",  "FR2", "Auditable events",                               NULL,           0,1,1,1},
    {"CR 2.11", "FR2", "Timestamps",                                     NULL,           1,1,1,1},

    /* FR 3 — System Integrity (SI) */
    {"CR 3.1",  "FR3", "Communication integrity",                        "CFUSA-CY004", 1,1,1,1},
    {"CR 3.2",  "FR3", "Malicious code protection",                      "CFUSA-CY001", 1,1,1,1},
    {"CR 3.3",  "FR3", "Security functionality verification",            "CFUSA-QUALIFY",1,1,1,1},
    {"CR 3.4",  "FR3", "Software and information integrity",             "CFUSA-SIGN",   0,1,1,1},
    {"CR 3.5",  "FR3", "Input validation",                               "CFUSA-A002",  1,1,1,1},
    {"CR 3.7",  "FR3", "Error handling",                                 "CFUSA-A002",  1,1,1,1},
    {"CR 3.8",  "FR3", "Session integrity",                              NULL,           0,1,1,1},
    {"CR 3.9",  "FR3", "Protection of audit information",                NULL,           0,0,1,1},

    /* FR 4 — Data Confidentiality (DC) */
    {"CR 4.1",  "FR4", "Information confidentiality",                    "CFUSA-CY004", 0,1,1,1},
    {"CR 4.3",  "FR4", "Use of cryptography",                            "CFUSA-CY008", 0,1,1,1},

    /* FR 5 — Restricted Data Flow (RDF) */
    {"CR 5.1",  "FR5", "Network segmentation",                           NULL,           0,1,1,1},
    {"CR 5.2",  "FR5", "Zone boundary protection",                       NULL,           0,0,1,1},
    {"CR 5.4",  "FR5", "Application partitioning",                       "CFUSA-L007",  0,0,1,1},

    /* FR 6 — Timely Response to Events (TRE) */
    {"CR 6.1",  "FR6", "Audit log accessibility",                        NULL,           1,1,1,1},
    {"CR 6.2",  "FR6", "Continuous monitoring",                          NULL,           0,1,1,1},

    /* FR 7 — Resource Availability (RA) */
    {"CR 7.1",  "FR7", "Denial of service protection",                   NULL,           0,1,1,1},
    {"CR 7.2",  "FR7", "Resource management",                            "CFUSA-L003",  0,1,1,1},
    {"CR 7.3",  "FR7", "Control system backup",                          NULL,           0,1,1,1},
    {"CR 7.7",  "FR7", "Least functionality",                            "CFUSA-L007",  0,0,1,1},
    {NULL,NULL,NULL,NULL,0,0,0,0}
};

static int sl_level(const char *sl)
{
    if (!sl) return 0;
    if (!strcmp(sl, "SL-1") || !strcmp(sl, "1")) return 1;
    if (!strcmp(sl, "SL-2") || !strcmp(sl, "2")) return 2;
    if (!strcmp(sl, "SL-3") || !strcmp(sl, "3")) return 3;
    if (!strcmp(sl, "SL-4") || !strcmp(sl, "4")) return 4;
    return 0;
}

int cmd_iec62443(int argc, char **argv)
{
    const char *dir    = ".";
    const char *sl     = "SL-2";
    const char *fmt_s  = "text";
    const char *output = NULL;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"sl",     required_argument, NULL, 's'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:s:f:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 's': sl     = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa iec62443 [--dir <path>] [--sl SL-1|2|3|4]\n"
                   "                      [--format text|json] [--output <file>]\n\n"
                   "IEC 62443-4-2 Component Security Requirements gap report.\n"
                   "Checks which CRs are covered by active cfusa rules.\n");
            return 0;
        default: return 2;
        }
    }

    int level = sl_level(sl);
    if (level == 0) {
        fprintf(stderr, "cfusa iec62443: unknown SL '%s' (use SL-1|2|3|4)\n", sl);
        return 2;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    /* Check for .fusa-iec62443.json config */
    char cfg_path[512];
    cfusa_path_join(cfg_path, sizeof(cfg_path), dir, IEC62443_FILE);
    int has_cfg = cfusa_file_exists(cfg_path);
    if (!has_cfg) {
        cfusa_path_join(cfg_path, sizeof(cfg_path), dir, IEC62443_FILE_LEGACY);
        has_cfg = cfusa_file_exists(cfg_path);
    }

    int covered = 0, gaps_m = 0, gaps_r = 0, na = 0;
    for (int i = 0; REQUIREMENTS[i].cr; i++) {
        const iec62443_row_t *r = &REQUIREMENTS[i];
        int req = (level==1) ? r->sl1 :
                  (level==2) ? r->sl2 :
                  (level==3) ? r->sl3 : r->sl4;
        if (req == 0) { na++; continue; }
        if (r->cfusa_rule) covered++;
        else if (req == 2) gaps_r++;
        else gaps_m++;
    }

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 3; } }

    if (!strcmp(fmt_s, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"gap-report\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"projectRoot\": \"%s\",\n"
            "  \"standard\": \"iec62443\",\n"
            "  \"project\": \"%s\",\n"
            "  \"sl\": \"%s\",\n"
            "  \"hasProjectConfig\": %s,\n"
            "  \"covered\": %d,\n"
            "  \"mandatoryGaps\": %d,\n"
            "  \"recommendedGaps\": %d,\n"
            "  \"na\": %d,\n"
            "  \"objectives\": [\n",
            ts, dir, cfg.project, sl,
            has_cfg ? "true" : "false",
            covered, gaps_m, gaps_r, na);
        int first = 1;
        for (int i = 0; REQUIREMENTS[i].cr; i++) {
            const iec62443_row_t *r = &REQUIREMENTS[i];
            int req = (level==1) ? r->sl1 :
                      (level==2) ? r->sl2 :
                      (level==3) ? r->sl3 : r->sl4;
            if (req == 0) continue;
            const char *level_str = (req == 1) ? "mandatory" : "recommended";
            const char *status    = r->cfusa_rule ? "satisfied" :
                                    (req == 2)    ? "partial" : "gap";
            if (!first) fprintf(out, ",\n");
            fprintf(out,
                "    {\"id\": \"%s\", \"fr\": \"%s\", \"title\": \"%s\","
                " \"findings\": [%s%s%s], \"level\": \"%s\", \"status\": \"%s\"}",
                r->cr, r->fr, r->title,
                r->cfusa_rule ? "\"" : "", r->cfusa_rule ? r->cfusa_rule : "",
                r->cfusa_rule ? "\"" : "",
                level_str, status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else if (!strcmp(fmt_s, "text")) {
        fprintf(out, "IEC 62443-4-2 Gap Report — %s (target %s)\n", cfg.project, sl);
        fprintf(out, "==================================================\n\n");
        if (!has_cfg)
            fprintf(out, "NOTE: no %s found — run 'cfusa iec62443 init' to create\n\n",
                    IEC62443_FILE);
        fprintf(out, "%-8s %-6s %-45s %-15s %-10s %s\n",
                "CR", "FR", "Requirement", "cfusa Rule", "Reqmt", "Status");
        fprintf(out, "%-8s %-6s %-45s %-15s %-10s %s\n",
                "--------", "------",
                "---------------------------------------------",
                "---------------", "----------", "------");

        for (int i = 0; REQUIREMENTS[i].cr; i++) {
            const iec62443_row_t *r = &REQUIREMENTS[i];
            int req = (level==1) ? r->sl1 :
                      (level==2) ? r->sl2 :
                      (level==3) ? r->sl3 : r->sl4;
            if (req == 0) continue;
            const char *reqmt  = (req == 1) ? "Mandatory" : "Recommended";
            const char *status = r->cfusa_rule ? "COVERED" :
                                 (req == 2)    ? "GAP (R)" : "GAP (M)";
            fprintf(out, "%-8s %-6s %-45s %-15s %-10s %s\n",
                   r->cr, r->fr, r->title,
                   r->cfusa_rule ? r->cfusa_rule : "-", reqmt, status);
        }

        fprintf(out, "\nSummary: %d covered, %d mandatory gap(s), %d recommended gap(s), "
               "%d not applicable for %s\n",
               covered, gaps_m, gaps_r, na, sl);
        if (!has_cfg)
            fprintf(out, "Create %s to enable IEC62443-001..004 engine rules.\n",
                    IEC62443_FILE);
    } else {
        if (output && out != stdout) fclose(out);
        fprintf(stderr, "cfusa iec62443: unknown format '%s' (text or json)\n", fmt_s);
        return 3;
    }

    if (output && out != stdout) fclose(out);
    return (gaps_m > 0) ? 1 : 0;
}
