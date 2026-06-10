/*
 * cfusa unece — UN R.155 cybersecurity compliance gap report.
 *
 * Maps cfusa pipeline evidence to UN Regulation No. 155 (UN R.155)
 * Annex 5 threat categories and reports PASS, GAP, or MANUAL for each.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

//cfusa:req REQ-UNECE-001

typedef struct {
    const char *id;
    const char *description;
    const char *iso21434_clauses;
    const char *evidence_file;   /* NULL = manual */
    const char *note;
} unece_cat_t;

static const unece_cat_t CATEGORIES[] = {
    /* Automatable — evidence files checked on disk */
    {"TC-1",  "Vehicle communication security",       "9.1, 9.3", "tara.json",              NULL},
    {"TC-2",  "Update mechanism security",            "A.2",      "provenance.json",         NULL},
    {"TC-3",  "Unintended physical access",           "9.1",      "tara.json",               NULL},
    {"TC-4",  "External connectivity threats",        "10.4",     "cfusa-self-check.json",   NULL},
    {"TC-5",  "Supply chain integrity",               "A.1",      NULL,                      "Check .cfusa_release/ for .spdx.json"},
    {"TC-6",  "Data storage and privacy threats",     "9.4",      "tara.json",               NULL},
    {"TC-7",  "Unintended software updates",          "A.2",      "provenance.json",         NULL},
    {"TC-8",  "Unintended software activation",       "10.4",     "cfusa-self-check.json",   NULL},
    {"TC-9",  "Cryptographic algorithm weakness",     "10.4",     "cfusa-self-check.json",   NULL},
    {"TC-10", "Denial of service",                    "9.3",      "tara.json",               NULL},
    /* Manual — organisational controls required */
    {"TC-11", "Insider attack",                       "6.2",      NULL, "MANUAL — requires access control and HR procedures"},
    {"TC-12", "Stolen cryptographic keys",            "12.1",     NULL, "MANUAL — requires key management procedures"},
    {"TC-13", "Counterfeit components",               "7.1",      NULL, "MANUAL — requires supplier audit records"},
    {NULL, NULL, NULL, NULL, NULL}
};

static int file_exists(const char *dir, const char *name)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    char rpath[512];
    snprintf(rpath, sizeof(rpath), "%s/.cfusa_release/%s", dir, name);
    f = fopen(rpath, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

int cmd_unece(int argc, char **argv)
{
    const char *dir    = ".";
    const char *fmt    = "text";
    const char *output = NULL;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int ch;
    optind = 1;
    while ((ch = getopt_long(argc, argv, "d:f:o:h", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'd': dir    = optarg; break;
        case 'f': fmt    = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa unece [--dir <path>]\n"
                   "                   [--format text|json] [--output <file>]\n\n"
                   "UN R.155 Annex 5 cybersecurity compliance gap report.\n"
                   "Checks for cfusa pipeline evidence against UN R.155 threat categories.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    FILE *out = stdout;
    if (output) {
        out = fopen(output, "w");
        if (!out) { perror(output); return 1; }
    }

    int pass = 0, gap = 0, manual = 0;
    for (int i = 0; CATEGORIES[i].id; i++) {
        const unece_cat_t *cat = &CATEGORIES[i];
        if (!cat->evidence_file && cat->note && strncmp(cat->note, "MANUAL", 6) == 0) {
            manual++;
        } else if (cat->evidence_file) {
            if (file_exists(dir, cat->evidence_file)) pass++;
            else gap++;
        } else {
            gap++;  /* special note cases like TC-5 SBOM */
        }
    }

    if (!strcmp(fmt, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"unece-r155-gap\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"regulation\": \"UN R.155\",\n"
            "  \"project\": \"%s\",\n"
            "  \"pass\": %d,\n"
            "  \"gap\": %d,\n"
            "  \"manual\": %d,\n"
            "  \"categories\": [\n",
            ts, cfg.project, pass, gap, manual);

        int first = 1;
        for (int i = 0; CATEGORIES[i].id; i++) {
            const unece_cat_t *cat = &CATEGORIES[i];
            const char *status;
            if (!cat->evidence_file && cat->note && strncmp(cat->note, "MANUAL", 6) == 0) {
                status = "MANUAL";
            } else if (cat->evidence_file) {
                status = file_exists(dir, cat->evidence_file) ? "PASS" : "GAP";
            } else {
                status = "GAP";
            }
            if (!first) fprintf(out, ",\n");
            fprintf(out,
                "    {\"id\": \"%s\", \"description\": \"%s\","
                " \"iso21434\": \"%s\", \"status\": \"%s\"}",
                cat->id, cat->description,
                cat->iso21434_clauses ? cat->iso21434_clauses : "",
                status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else {
        fprintf(out, "UN R.155 Gap Report — %s\n", cfg.project);
        fprintf(out, "====================================\n\n");
        fprintf(out, "%-6s %-40s %-10s %-12s %s\n",
                "Cat.", "Description", "Status", "ISO 21434", "Evidence");
        fprintf(out, "%-6s %-40s %-10s %-12s %s\n",
                "------", "----------------------------------------",
                "----------", "------------", "--------");

        for (int i = 0; CATEGORIES[i].id; i++) {
            const unece_cat_t *cat = &CATEGORIES[i];
            const char *status;
            const char *evidence;
            if (!cat->evidence_file && cat->note && strncmp(cat->note, "MANUAL", 6) == 0) {
                status   = "MANUAL";
                evidence = cat->note;
            } else if (cat->evidence_file) {
                status   = file_exists(dir, cat->evidence_file) ? "PASS" : "GAP";
                evidence = cat->evidence_file;
            } else {
                status   = "GAP";
                evidence = cat->note ? cat->note : "-";
            }
            fprintf(out, "%-6s %-40s %-10s %-12s %s\n",
                    cat->id, cat->description, status,
                    cat->iso21434_clauses ? cat->iso21434_clauses : "-",
                    evidence);
        }
        fprintf(out, "\nSummary: %d PASS, %d GAP, %d MANUAL\n", pass, gap, manual);
        if (gap > 0)
            fprintf(out, "Run cfusa tara, cfusa vuln, cfusa release to generate missing evidence.\n");
    }

    if (output && out != stdout) fclose(out);
    if (output)
        printf("UN R.155 gap report written to %s (%d gap%s)\n",
               output, gap, gap == 1 ? "" : "s");

    return (gap > 0) ? 1 : 0;
}
