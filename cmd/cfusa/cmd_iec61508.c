#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * IEC 61508 Parts 1-3 compliance gap report.
 * Maps CFUSA rules to IEC 61508-3 software objectives by SIL level.
 */

typedef struct {
    const char *clause;
    const char *title;
    const char *cfusa_rule;
    int         sil1;
    int         sil2;
    int         sil3;
    int         sil4;
} iec61508_row_t;

/* 1=required (M), 2=recommended (R), 0=not applicable (-) */
static const iec61508_row_t OBJECTIVES[] = {
    {"7.2.2",  "Structured programming",           "CFUSA-L001",  2,1,1,1},
    {"7.2.2",  "No dynamic objects / memory",       "CFUSA-L003",  0,2,1,1},
    {"7.2.2",  "No recursion",                      "CFUSA-L004",  0,2,1,1},
    {"7.2.2",  "No goto",                            "CFUSA-L002",  2,1,1,1},
    {"7.2.2",  "No setjmp/longjmp",                 "CFUSA-L006",  2,1,1,1},
    {"7.2.2",  "Limited use of interrupts",         NULL,           2,2,1,1},
    {"7.3.2",  "Defensive programming",             "CFUSA-A002",  1,1,1,1},
    {"7.3.2",  "Fault detection/recovery routines", NULL,           1,1,1,1},
    {"7.3.2",  "Safety bag techniques",             NULL,           0,2,1,1},
    {"7.4.2",  "Static analysis",                   "CFUSA-A003",  2,1,1,1},
    {"7.4.2",  "Dynamic analysis and testing",      NULL,           2,1,1,1},
    {"7.4.2",  "Data recording and analysis",       NULL,           2,1,1,1},
    {"7.4.4",  "Diverse programming",               NULL,           0,0,2,1},
    {"7.4.4",  "Multi-version dissimilar SW",       NULL,           0,0,2,1},
    {"7.4.7",  "Formal methods",                    NULL,           0,0,2,2},
    {"7.5.1",  "Software module testing",           "CFUSA-A007",  1,1,1,1},
    {"7.5.2",  "Statement coverage",               "CFUSA-COV",    1,1,1,1},
    {"7.5.2",  "Branch coverage",                  "CFUSA-COV",    0,1,1,1},
    {"7.5.2",  "MC/DC coverage",                   "CFUSA-COV",    0,0,2,1},
    {"7.6",    "Software integration testing",     NULL,            1,1,1,1},
    {"7.7",    "Programmable electronics",         NULL,            1,1,1,1},
    {"7.8",    "Software safety validation",       "CFUSA-QUALIFY", 1,1,1,1},
    {"7.9",    "Software modification",            NULL,            1,1,1,1},
    {"7.10",   "Software verification",            "CFUSA-TRACE",   1,1,1,1},
    {NULL,NULL,NULL,0,0,0,0}
};

static int sil_level(const char *sil)
{
    if (!sil) return 0;
    if (!strcmp(sil,"SIL-1") || !strcmp(sil,"1")) return 1;
    if (!strcmp(sil,"SIL-2") || !strcmp(sil,"2")) return 2;
    if (!strcmp(sil,"SIL-3") || !strcmp(sil,"3")) return 3;
    if (!strcmp(sil,"SIL-4") || !strcmp(sil,"4")) return 4;
    return 0;
}

int cmd_iec61508(int argc, char **argv)
{
    const char *dir    = ".";
    const char *sil    = "SIL-3";
    const char *fmt_s  = "text";
    const char *output = NULL;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"sil",    required_argument, NULL, 's'},
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
        case 's': sil    = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa iec61508 [--dir <path>] [--sil SIL-1|2|3|4]\n"
                   "                      [--format text|json] [--output <file>]\n\n"
                   "IEC 61508 Parts 1-3 compliance gap report.\n"
                   "Checks which IEC 61508-3 objectives are covered by active cfusa rules.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    int level = sil_level(sil);
    if (level == 0) {
        fprintf(stderr, "cfusa iec61508: unknown SIL '%s' (use SIL-1|2|3|4)\n", sil);
        return 1;
    }

    int covered = 0, gaps_m = 0, gaps_r = 0, na = 0;
    for (int i = 0; OBJECTIVES[i].clause; i++) {
        const iec61508_row_t *r = &OBJECTIVES[i];
        int req = (level==1) ? r->sil1 :
                  (level==2) ? r->sil2 :
                  (level==3) ? r->sil3 : r->sil4;
        if (req == 0) { na++; continue; }
        if (r->cfusa_rule) covered++;
        else if (req == 2) gaps_r++;
        else gaps_m++;
    }

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 1; } }

    if (!strcmp(fmt_s, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"iec61508-gap\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"project\": \"%s\",\n"
            "  \"sil\": \"%s\",\n"
            "  \"covered\": %d,\n"
            "  \"mandatoryGaps\": %d,\n"
            "  \"recommendedGaps\": %d,\n"
            "  \"na\": %d,\n"
            "  \"objectives\": [\n",
            ts, cfg.project, sil, covered, gaps_m, gaps_r, na);
        int first = 1;
        for (int i = 0; OBJECTIVES[i].clause; i++) {
            const iec61508_row_t *r = &OBJECTIVES[i];
            int req = (level==1) ? r->sil1 :
                      (level==2) ? r->sil2 :
                      (level==3) ? r->sil3 : r->sil4;
            if (req == 0) continue;
            const char *reqmt  = (req == 1) ? "mandatory" : "recommended";
            const char *status = r->cfusa_rule ? "COVERED" :
                                 (req == 2)    ? "GAP (R)" : "GAP (M)";
            if (!first) fprintf(out, ",\n");
            if (r->cfusa_rule)
                fprintf(out,
                    "    {\"clause\": \"%s\", \"title\": \"%s\","
                    " \"cfusaRule\": \"%s\", \"reqmt\": \"%s\", \"status\": \"%s\"}",
                    r->clause, r->title, r->cfusa_rule, reqmt, status);
            else
                fprintf(out,
                    "    {\"clause\": \"%s\", \"title\": \"%s\","
                    " \"cfusaRule\": null, \"reqmt\": \"%s\", \"status\": \"%s\"}",
                    r->clause, r->title, reqmt, status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else {
        fprintf(out, "IEC 61508 Parts 1-3 Gap Report — %s (target %s)\n", cfg.project, sil);
        fprintf(out, "=====================================================\n\n");
        fprintf(out, "%-8s %-45s %-15s %-10s %s\n", "Clause", "Objective", "cfusa Rule", "Reqmt", "Status");
        fprintf(out, "%-8s %-45s %-15s %-10s %s\n",
               "--------", "---------------------------------------------",
               "---------------", "----------", "------");

        for (int i = 0; OBJECTIVES[i].clause; i++) {
            const iec61508_row_t *r = &OBJECTIVES[i];
            int req = (level==1) ? r->sil1 :
                      (level==2) ? r->sil2 :
                      (level==3) ? r->sil3 : r->sil4;
            if (req == 0) continue;
            const char *reqmt  = (req == 1) ? "Mandatory" : "Recommended";
            const char *status = r->cfusa_rule ? "COVERED" :
                                 (req == 2)    ? "GAP (R)" : "GAP (M)";
            fprintf(out, "%-8s %-45s %-15s %-10s %s\n",
                   r->clause, r->title,
                   r->cfusa_rule ? r->cfusa_rule : "-", reqmt, status);
        }

        fprintf(out, "\nSummary: %d covered, %d mandatory gap(s), %d recommended gap(s), "
               "%d not applicable for %s\n",
               covered, gaps_m, gaps_r, na, sil);
    }

    if (output && out != stdout) fclose(out);
    return (gaps_m > 0) ? 1 : 0;
}
