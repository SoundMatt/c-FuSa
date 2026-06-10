#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * ISO 26262 Part 6 compliance gap report.
 * Maps CFUSA rules to Part 6 objectives and identifies gaps for the given ASIL.
 */

typedef struct {
    const char *clause;
    const char *title;
    const char *cfusa_rule;  /* NULL = not yet covered */
    int         asil_a;
    int         asil_b;
    int         asil_c;
    int         asil_d;
} iso26262_row_t;

static const iso26262_row_t OBJECTIVES[] = {
    {"6.5",  "General software requirements specification",   NULL,          1,1,1,1},
    {"6.6",  "Software architectural design",                 NULL,          1,1,1,1},
    {"6.7",  "Software unit design",                          "CFUSA-L001",  1,1,1,1},
    {"6.8",  "Software unit implementation and verification", "CFUSA-L002",  1,1,1,1},
    {"6.9",  "Software integration and testing",              "CFUSA-A007",  1,1,1,1},
    {"6.10", "Software qualification testing",                NULL,          0,1,1,1},
    {"6.11", "Software safety requirements verification",     "CFUSA-A002",  1,1,1,1},
    {"6.12", "Software configuration management",             "CFUSA-SCI",   1,1,1,1},
    {"6.4.1","No recursion",                                  "CFUSA-L004",  0,0,1,1},
    {"6.4.2","No dynamic memory allocation",                  "CFUSA-L003",  0,0,1,1},
    {"6.4.3","No use of setjmp/longjmp",                      "CFUSA-L006",  1,1,1,1},
    {"6.4.4","No goto statement",                             "CFUSA-L002",  0,1,1,1},
    {"6.4.5","No multiple exit points from functions",        NULL,          0,0,1,1},
    {"6.4.6","No unstructured code",                          "CFUSA-L001",  0,1,1,1},
    {"6.4.7","No dead code",                                  NULL,          0,1,1,1},
    {"6.4.8","No code complexity exceeds limit",              "CFUSA-L001",  0,1,1,1},
    {"6.4.9","No use of non-standardised language ext.",      NULL,          1,1,1,1},
    {"6.4.10","No implicit type conversions",                 "CFUSA-A003",  0,1,1,1},
    {"6.4.11","No hiding of data flow",                       "CFUSA-L007",  0,0,1,1},
    {"6.4.12","No use of global variables",                   "CFUSA-L007",  0,2,1,1},
    {"6.4.13","No side-effects in conditions",                NULL,          0,0,1,1},
    {"6.4.14","No obsolete/deprecated functions",             "CFUSA-A001",  1,1,1,1},
    {NULL,NULL,NULL,0,0,0,0}
};

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
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    int level = asil_level(asil);
    if (level == 0) {
        fprintf(stderr, "cfusa iso26262: unknown ASIL '%s' (use ASIL-A|B|C|D)\n", asil);
        return 1;
    }

    int covered = 0, gaps = 0, na = 0;
    for (int i = 0; OBJECTIVES[i].clause; i++) {
        const iso26262_row_t *r = &OBJECTIVES[i];
        int req = (level==1) ? r->asil_a :
                  (level==2) ? r->asil_b :
                  (level==3) ? r->asil_c : r->asil_d;
        if (req == 0) { na++; continue; }
        if (r->cfusa_rule) covered++; else gaps++;
    }

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 1; } }

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
            const char *status = r->cfusa_rule ? "COVERED" :
                                 (req == 2)     ? "GAP (REC)" : "GAP";
            if (!first) fprintf(out, ",\n");
            if (r->cfusa_rule)
                fprintf(out,
                    "    {\"clause\": \"%s\", \"title\": \"%s\","
                    " \"cfusaRule\": \"%s\", \"status\": \"%s\"}",
                    r->clause, r->title, r->cfusa_rule, status);
            else
                fprintf(out,
                    "    {\"clause\": \"%s\", \"title\": \"%s\","
                    " \"cfusaRule\": null, \"status\": \"%s\"}",
                    r->clause, r->title, status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else {
        fprintf(out, "ISO 26262 Part 6 Gap Report — %s (target %s)\n", cfg.project, asil);
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
            const char *status = r->cfusa_rule ? "COVERED" :
                                 (req == 2)     ? "GAP (REC)" : "GAP";
            fprintf(out, "%-8s %-45s %-14s %s\n",
                   r->clause, r->title,
                   r->cfusa_rule ? r->cfusa_rule : "-", status);
        }

        fprintf(out, "\nSummary: %d covered, %d gap(s), %d not applicable for %s\n",
               covered, gaps, na, asil);
        if (gaps > 0)
            fprintf(out, "Review gaps and add manual evidence or custom cfusa rules.\n");
    }

    if (output && out != stdout) fclose(out);
    return (gaps > 0) ? 1 : 0;
}
