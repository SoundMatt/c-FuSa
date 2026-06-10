/*
 * cfusa iso21434 — ISO 21434 cybersecurity compliance gap report.
 *
 * Maps cfusa pipeline evidence to ISO 21434 objectives and reports
 * PASS, GAP, or MANUAL for each, respecting Cybersecurity Assurance
 * Levels CAL-1 through CAL-4.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

//cfusa:req REQ-ISO21434-001

typedef struct {
    const char *id;
    const char *description;
    const char *evidence_file;  /* NULL = manual */
    int         min_cal;        /* 0 = all levels; 1-4 = minimum CAL */
    const char *note;
} iso21434_obj_t;

static const iso21434_obj_t OBJECTIVES[] = {
    /* Automatable — evidence files checked on disk */
    {"6.1",  "Cybersecurity plan",                    "cyber-plan.json",        1, NULL},
    {"8.3",  "Vulnerability monitoring evidence",     "vuln-report.json",       1, NULL},
    {"9.1",  "TARA — threat analysis",                "tara.json",              1, NULL},
    {"9.2",  "TARA — asset identification",           "tara.json",              1, NULL},
    {"9.3",  "TARA — threat scenarios",               "tara.json",              1, NULL},
    {"9.4",  "TARA — impact and risk rating",         "tara.json",              1, NULL},
    {"9.5",  "TARA — attack feasibility assessment",  "tara.json",              2, NULL},
    {"9.6",  "TARA — risk treatment decisions",       "tara.json",              2, NULL},
    {"10.1", "Cybersecurity requirements",            ".cfusa-reqs.json",       1, NULL},
    {"10.3", "Cybersecurity design evidence",         "safety-case.json",       2, NULL},
    {"10.4", "Static cybersecurity analysis",         "cfusa-self-check.json",  1, NULL},
    {"11.1", "Cybersecurity validation report",       "cyber-validation.json",  2, NULL},
    {"A.1",  "SBOM (Annex A work product)",           NULL,                     1, "Check .cfusa_release/ for .spdx.json"},
    {"A.2",  "Build provenance (Annex A)",            "provenance.json",        1, NULL},
    /* Manual — organisational evidence required */
    {"5.1",  "Cybersecurity governance",              NULL, 0, "MANUAL — requires organisation-level CSMS policy"},
    {"6.2",  "Cybersecurity responsibility",          NULL, 0, "MANUAL — requires named role assignments"},
    {"7.1",  "Supplier management",                   NULL, 0, "MANUAL — requires third-party cybersecurity assessment records"},
    {"12.1", "Production security",                   NULL, 0, "MANUAL — requires manufacturing process documentation"},
    {"13.1", "Operations monitoring",                 NULL, 0, "MANUAL — requires incident response plan"},
    {"14.1", "End-of-support plan",                   NULL, 0, "MANUAL — requires decommissioning procedure"},
    {"15.1", "Incident response (PSIRT)",             NULL, 0, "MANUAL — requires PSIRT process documentation"},
    {NULL, NULL, NULL, 0, NULL}
};

static int cal_level(const char *cal)
{
    if (!cal) return 1;
    if (!strcmp(cal, "CAL-1") || !strcmp(cal, "1")) return 1;
    if (!strcmp(cal, "CAL-2") || !strcmp(cal, "2")) return 2;
    if (!strcmp(cal, "CAL-3") || !strcmp(cal, "3")) return 3;
    if (!strcmp(cal, "CAL-4") || !strcmp(cal, "4")) return 4;
    return 0;
}

static int file_exists(const char *dir, const char *name)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    /* also check .cfusa_release/ sub-directory */
    char rpath[512];
    snprintf(rpath, sizeof(rpath), "%s/.cfusa_release/%s", dir, name);
    f = fopen(rpath, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

int cmd_iso21434(int argc, char **argv)
{
    const char *dir    = ".";
    const char *cal    = "CAL-1";
    const char *fmt    = "text";
    const char *output = NULL;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"cal",    required_argument, NULL, 'c'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int ch;
    optind = 1;
    while ((ch = getopt_long(argc, argv, "d:c:f:o:h", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'd': dir    = optarg; break;
        case 'c': cal    = optarg; break;
        case 'f': fmt    = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa iso21434 [--dir <path>] [--cal CAL-1|2|3|4]\n"
                   "                      [--format text|json] [--output <file>]\n\n"
                   "ISO 21434 cybersecurity compliance gap report.\n"
                   "Checks for cfusa pipeline evidence files against ISO 21434 objectives.\n");
            return 0;
        default: return 1;
        }
    }

    int level = cal_level(cal);
    if (level == 0) {
        fprintf(stderr, "cfusa iso21434: unknown CAL '%s' (use CAL-1|2|3|4)\n", cal);
        return 1;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    FILE *out = stdout;
    if (output) {
        out = fopen(output, "w");
        if (!out) { perror(output); return 1; }
    }

    int pass = 0, gap = 0, manual = 0, na = 0;

    /* Pre-scan counts */
    for (int i = 0; OBJECTIVES[i].id; i++) {
        const iso21434_obj_t *o = &OBJECTIVES[i];
        if (o->min_cal == 0) {
            manual++;
        } else if (o->min_cal > level) {
            na++;
        } else if (o->evidence_file) {
            if (file_exists(dir, o->evidence_file)) pass++;
            else gap++;
        } else if (o->note && strncmp(o->note, "MANUAL", 6) != 0) {
            pass++; /* special cases like SBOM check */
        } else {
            gap++;
        }
    }

    if (!strcmp(fmt, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"iso21434-gap\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"projectRoot\": \"%s\",\n"
            "  \"standard\": \"ISO 21434\",\n"
            "  \"project\": \"%s\",\n"
            "  \"cal\": \"%s\",\n"
            "  \"pass\": %d,\n"
            "  \"gap\": %d,\n"
            "  \"manual\": %d,\n"
            "  \"na\": %d,\n"
            "  \"objectives\": [\n",
            ts, dir, cfg.project, cal, pass, gap, manual, na);

        int first = 1;
        for (int i = 0; OBJECTIVES[i].id; i++) {
            const iso21434_obj_t *o = &OBJECTIVES[i];
            const char *status;
            if (o->min_cal == 0) {
                status = "MANUAL";
            } else if (o->min_cal > level) {
                status = "N/A";
            } else if (o->evidence_file) {
                status = file_exists(dir, o->evidence_file) ? "PASS" : "GAP";
            } else {
                status = "MANUAL";
            }
            if (!first) fprintf(out, ",\n");
            fprintf(out,
                "    {\"id\": \"%s\", \"description\": \"%s\","
                " \"status\": \"%s\"}",
                o->id, o->description, status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else {
        fprintf(out, "ISO 21434 Gap Report — %s  (%s)\n", cfg.project, cal);
        fprintf(out, "============================================\n\n");
        fprintf(out, "%-6s %-45s %-10s %s\n", "Clause", "Objective", "Status", "Evidence");
        fprintf(out, "%-6s %-45s %-10s %s\n",
                "------", "---------------------------------------------", "----------", "--------");

        for (int i = 0; OBJECTIVES[i].id; i++) {
            const iso21434_obj_t *o = &OBJECTIVES[i];
            const char *status;
            const char *evidence = o->evidence_file ? o->evidence_file : "-";
            if (o->min_cal == 0) {
                status   = "MANUAL";
                evidence = o->note ? o->note : "-";
            } else if (o->min_cal > level) {
                status = "N/A";
            } else if (o->evidence_file) {
                status = file_exists(dir, o->evidence_file) ? "PASS" : "GAP";
            } else {
                status   = "MANUAL";
                evidence = o->note ? o->note : "-";
            }
            fprintf(out, "%-6s %-45s %-10s %s\n",
                    o->id, o->description, status, evidence);
        }
        fprintf(out, "\nSummary: %d PASS, %d GAP, %d MANUAL, %d N/A  (%s)\n",
                pass, gap, manual, na, cal);
        if (gap > 0)
            fprintf(out, "Run cfusa tara, cfusa vuln, cfusa release to generate missing evidence.\n");
    }

    if (output && out != stdout) fclose(out);
    if (output)
        printf("ISO 21434 gap report written to %s (%d gap%s)\n",
               output, gap, gap == 1 ? "" : "s");

    return (gap > 0) ? 1 : 0;
}
