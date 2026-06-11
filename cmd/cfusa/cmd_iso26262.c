#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * ISO 26262 Parts 6–11 compliance gap report.
 * Maps CFUSA rules and evidence files to objectives by ASIL.
 */

typedef struct {
    const char *clause;
    const char *title;
    const char *cfusa_rule;    /* NULL = not covered by a rule */
    const char *evidence_file; /* NULL = no file check; checked on disk if set */
    int         asil_a;
    int         asil_b;
    int         asil_c;
    int         asil_d;
} iso26262_row_t;

static const iso26262_row_t OBJECTIVES[] = {
    /* Part 6 — Software at the system level */
    {"6.5",  "General software requirements specification",   NULL,         NULL,                   1,1,1,1},
    {"6.6",  "Software architectural design",                 NULL,         NULL,                   1,1,1,1},
    {"6.7",  "Software unit design",                          "CFUSA-L001", NULL,                   1,1,1,1},
    {"6.8",  "Software unit implementation and verification", "CFUSA-L002", NULL,                   1,1,1,1},
    {"6.9",  "Software integration and testing",              "CFUSA-A007", NULL,                   1,1,1,1},
    {"6.10", "Software qualification testing",                NULL,         NULL,                   0,1,1,1},
    {"6.11", "Software safety requirements verification",     "CFUSA-A002", NULL,                   1,1,1,1},
    {"6.12", "Software configuration management",             "CFUSA-SCI",  NULL,                   1,1,1,1},
    {"6.4.1","No recursion",                                  "CFUSA-L004", NULL,                   0,0,1,1},
    {"6.4.2","No dynamic memory allocation",                  "CFUSA-L003", NULL,                   0,0,1,1},
    {"6.4.3","No use of setjmp/longjmp",                      "CFUSA-L006", NULL,                   1,1,1,1},
    {"6.4.4","No goto statement",                             "CFUSA-L002", NULL,                   0,1,1,1},
    {"6.4.5","No multiple exit points from functions",        NULL,         NULL,                   0,0,1,1},
    {"6.4.6","No unstructured code",                          "CFUSA-L001", NULL,                   0,1,1,1},
    {"6.4.7","No dead code",                                  NULL,         NULL,                   0,1,1,1},
    {"6.4.8","No code complexity exceeds limit",              "COMP001",    NULL,                   0,1,1,1},
    {"6.4.9","No use of non-standardised language ext.",      NULL,         NULL,                   1,1,1,1},
    {"6.4.10","No implicit type conversions",                 "CFUSA-A003", NULL,                   0,1,1,1},
    {"6.4.11","No hiding of data flow",                       "CFUSA-L007", NULL,                   0,0,1,1},
    {"6.4.12","No use of global variables",                   "CFUSA-L007", NULL,                   0,2,1,1},
    {"6.4.13","No side-effects in conditions",                NULL,         NULL,                   0,0,1,1},
    {"6.4.14","No obsolete/deprecated functions",             "CFUSA-A001", NULL,                   1,1,1,1},
    /* Part 7 — Production and operation (item integration and testing) */
    {"7.3",  "Hazard analysis and risk assessment (HARA)",    "HARA001",    ".fusa-hara.json",       1,1,1,1},
    {"7.4",  "Functional safety concept",                     NULL,         NULL,                   0,1,1,1},
    {"7.5",  "Safety goals",                                  "HARA003",    NULL,                   1,1,1,1},
    /* Part 10 — Guideline on ISO 26262 */
    {"10.4", "Software component interaction (SCI) evidence", "CFUSA-SCI",  "sci.json",             0,1,1,1},
    /* Part 11 — Guidelines on application of ISO 26262 to semiconductors */
    {"11.3", "Software coupling analysis evidence",           "COUP003",    "coupling-report.json", 0,0,1,1},
    {NULL,NULL,NULL,NULL,0,0,0,0}
};

static int file_exists_in_dir(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    /* also check .cfusa_release/ */
    snprintf(path, sizeof(path), "%s/.cfusa_release/%s", dir, name);
    f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

static int asil_level(const char *asil)
{
    if (!asil) return 0;
    if (!strcmp(asil,"ASIL-A") || !strcmp(asil,"a") || !strcmp(asil,"A")) return 1;
    if (!strcmp(asil,"ASIL-B") || !strcmp(asil,"b") || !strcmp(asil,"B")) return 2;
    if (!strcmp(asil,"ASIL-C") || !strcmp(asil,"c") || !strcmp(asil,"C")) return 3;
    if (!strcmp(asil,"ASIL-D") || !strcmp(asil,"d") || !strcmp(asil,"D")) return 4;
    return 0;
}

int cmd_iso26262(int argc, char **argv)
{
    const char *dir    = ".";
    const char *asil   = "ASIL-D";
    const char *fmt_s  = "text";
    const char *output = NULL;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"asil",   required_argument, NULL, 'a'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:a:f:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'a': asil   = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa iso26262 [--dir <path>] [--asil ASIL-A|B|C|D]\n"
                   "                      [--format text|json] [--output <file>]\n\n"
                   "ISO 26262 Part 6 compliance gap report.\n"
                   "Checks which Part 6 objectives are covered by active cfusa rules.\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    int level = asil_level(asil);
    if (level == 0) {
        fprintf(stderr, "cfusa iso26262: unknown ASIL '%s' (use ASIL-A|B|C|D)\n", asil);
        return 2;
    }

    int covered = 0, gaps = 0, na = 0;
    for (int i = 0; OBJECTIVES[i].clause; i++) {
        const iso26262_row_t *r = &OBJECTIVES[i];
        int req = (level==1) ? r->asil_a :
                  (level==2) ? r->asil_b :
                  (level==3) ? r->asil_c : r->asil_d;
        if (req == 0) { na++; continue; }
        int ok = r->cfusa_rule != NULL;
        if (!ok && r->evidence_file) ok = file_exists_in_dir(dir, r->evidence_file);
        if (ok) covered++; else gaps++;
    }

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 3; } }

    if (!strcmp(fmt_s, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"iso26262-gap\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"projectRoot\": \"%s\",\n"
            "  \"standard\": \"ISO 26262\",\n"
            "  \"project\": \"%s\",\n"
            "  \"asil\": \"%s\",\n"
            "  \"covered\": %d,\n"
            "  \"gaps\": %d,\n"
            "  \"na\": %d,\n"
            "  \"objectives\": [\n",
            ts, dir, cfg.project, asil, covered, gaps, na);
        int first = 1;
        for (int i = 0; OBJECTIVES[i].clause; i++) {
            const iso26262_row_t *r = &OBJECTIVES[i];
            int req = (level==1) ? r->asil_a :
                      (level==2) ? r->asil_b :
                      (level==3) ? r->asil_c : r->asil_d;
            if (req == 0) continue;
            int ok = r->cfusa_rule != NULL;
            if (!ok && r->evidence_file) ok = file_exists_in_dir(dir, r->evidence_file);
            const char *status = ok ? "covered" : (req == 2) ? "gap-recommended" : "gap";
            const char *rule_s = r->cfusa_rule ? r->cfusa_rule : "null";
            if (!first) fprintf(out, ",\n");
            fprintf(out,
                "    {\"id\": \"%s\", \"title\": \"%s\","
                " \"rule\": %s%s%s, \"status\": \"%s\"}",
                r->clause, r->title,
                r->cfusa_rule ? "\"" : "", rule_s,
                r->cfusa_rule ? "\"" : "",
                status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else {
        fprintf(out, "ISO 26262 Parts 6-11 Gap Report — %s (target %s)\n",
                cfg.project, asil);
        fprintf(out, "=======================================================\n\n");
        fprintf(out, "%-8s %-45s %-14s %s\n", "Clause", "Objective", "cfusa Rule", "Status");
        fprintf(out, "%-8s %-45s %-14s %s\n",
               "--------", "---------------------------------------------",
               "--------------", "------");

        for (int i = 0; OBJECTIVES[i].clause; i++) {
            const iso26262_row_t *r = &OBJECTIVES[i];
            int req = (level==1) ? r->asil_a :
                      (level==2) ? r->asil_b :
                      (level==3) ? r->asil_c : r->asil_d;
            if (req == 0) continue;
            int ok = r->cfusa_rule != NULL;
            if (!ok && r->evidence_file) ok = file_exists_in_dir(dir, r->evidence_file);
            const char *status = ok ? "COVERED" : (req == 2) ? "GAP (REC)" : "GAP";
            const char *rule_s = r->cfusa_rule ? r->cfusa_rule :
                                 (r->evidence_file ? r->evidence_file : "-");
            fprintf(out, "%-8s %-45s %-14s %s\n",
                   r->clause, r->title, rule_s, status);
        }

        fprintf(out, "\nSummary: %d covered, %d gap(s), %d not applicable for %s\n",
               covered, gaps, na, asil);
        if (gaps > 0)
            fprintf(out, "Review gaps and add manual evidence or custom cfusa rules.\n");
    }

    if (output && out != stdout) fclose(out);
    return (gaps > 0) ? 1 : 0;
}
