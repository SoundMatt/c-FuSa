#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

//cfusa:req REQ-SLSA001 REQ-SLSA002 REQ-SLSA003 REQ-SLSA004

/*
 * SLSA provenance gap report.
 * Maps SLSA v1.0 requirements (levels 1-4) to evidence files or cfusa rules.
 * Spec §9.3: objectives[] with id/title/status + summary{}.
 */

typedef struct {
    const char *id;
    const char *title;
    const char *evidence_file; /* checked on disk; NULL = manual */
    int         min_level;     /* minimum SLSA level this applies from */
} slsa_obj_t;

static int slsa_file_exists(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

static const slsa_obj_t OBJECTIVES[] = {
    /* Level 1 — scripted build + provenance */
    {"SLSA-L1-1", "Build process is fully scripted/automated (e.g. CMake, Makefile)",
     NULL, 1},
    {"SLSA-L1-2", "Build provenance document exists",
     ".cfusa_release/provenance.json", 1},
    {"SLSA-L1-3", "SBOM (Software Bill of Materials) exists",
     ".cfusa_release/my-project-0.1.0.spdx.json", 1},

    /* Level 2 — hosted source + authenticated provenance */
    {"SLSA-L2-1", "Source is hosted on a version control platform (git)",
     NULL, 2},
    {"SLSA-L2-2", "Build is performed by a hosted CI/CD service",
     ".github/workflows/ci.yml", 2},
    {"SLSA-L2-3", "Provenance is authenticated (signed or produced by trusted builder)",
     NULL, 2},

    /* Level 3 — hardened build platform */
    {"SLSA-L3-1", "Source changes require code review before merge",
     NULL, 3},
    {"SLSA-L3-2", "Build platform is hardened (isolated, ephemeral build environment)",
     NULL, 3},
    {"SLSA-L3-3", "Provenance is non-falsifiable (cannot be forged by build)",
     NULL, 3},
    {"SLSA-L3-4", "All build dependencies are pinned by hash",
     NULL, 3},

    /* Level 4 — two-party review + hermetic build */
    {"SLSA-L4-1", "Two-party review enforced for all source changes",
     NULL, 4},
    {"SLSA-L4-2", "Build is hermetic (no network access, all inputs declared)",
     NULL, 4},
    {"SLSA-L4-3", "Build is reproducible (same inputs produce identical output)",
     NULL, 4},

    {NULL, NULL, NULL, 0}
};

int cmd_slsa(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = NULL;
    const char *fmt_s  = "text";
    int         level  = 1;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"level",  required_argument, NULL, 'l'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:l:f:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'l': level  = atoi(optarg); break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa slsa [--dir <path>] [--level 1|2|3|4]\n"
                   "                  [--format text|md|json] [--output <file>]\n\n"
                   "Reports SLSA v1.0 provenance gap status for the given level.\n");
            return 0;
        default: return 2;
        }
    }

    if (level < 1 || level > 4) {
        fprintf(stderr, "cfusa slsa: invalid level '%d' — must be 1-4\n", level);
        return 2;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    /* Count objectives applicable at requested level */
    int total = 0, satisfied = 0;
    for (int i = 0; OBJECTIVES[i].id; i++) {
        if (OBJECTIVES[i].min_level > level) continue;
        total++;
        if (OBJECTIVES[i].evidence_file &&
            slsa_file_exists(dir, OBJECTIVES[i].evidence_file))
            satisfied++;
    }
    int gaps = total - satisfied;

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 3; } }

    char ts[32]; cfusa_timestamp_now(ts);

    if (!strcmp(fmt_s, "json")) {
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"gap-report\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"projectRoot\": \"%s\",\n"
            "  \"standard\": \"slsa\",\n"
            "  \"level\": %d,\n"
            "  \"objectives\": [\n",
            ts, dir, level);
        int first = 1;
        for (int i = 0; OBJECTIVES[i].id; i++) {
            if (OBJECTIVES[i].min_level > level) continue;
            int ok = OBJECTIVES[i].evidence_file &&
                     slsa_file_exists(dir, OBJECTIVES[i].evidence_file);
            const char *status = ok ? "satisfied" : "gap";
            if (!first) fprintf(out, ",\n");
            fprintf(out,
                "    {\"id\": \"%s\", \"title\": \"%s\","
                " \"findings\": [], \"status\": \"%s\"}",
                OBJECTIVES[i].id, OBJECTIVES[i].title, status);
            first = 0;
        }
        fprintf(out,
            "\n  ],\n"
            "  \"summary\": {\n"
            "    \"total\": %d,\n"
            "    \"satisfied\": %d,\n"
            "    \"gaps\": %d\n"
            "  }\n"
            "}\n",
            total, satisfied, gaps);
    } else if (!strcmp(fmt_s, "md")) {
        fprintf(out,
            "# SLSA v1.0 Gap Report\n\n"
            "**Project:** %s v%s  |  **Level:** %d  |  **Generated:** %s\n\n"
            "Satisfied: **%d / %d** objectives\n\n"
            "| ID | Objective | Status |\n|---|---|---|\n",
            cfg.project, cfg.version, level, ts, satisfied, total);
        for (int i = 0; OBJECTIVES[i].id; i++) {
            if (OBJECTIVES[i].min_level > level) continue;
            int ok = OBJECTIVES[i].evidence_file &&
                     slsa_file_exists(dir, OBJECTIVES[i].evidence_file);
            fprintf(out, "| %s | %s | %s |\n",
                    OBJECTIVES[i].id, OBJECTIVES[i].title,
                    ok ? "[x] Satisfied" : "[ ] Gap");
        }
    } else {
        fprintf(out, "SLSA v1.0 Gap Report\n"
                "Project: %s v%s   Level: %d   Generated: %s\n"
                "Satisfied: %d / %d objectives  (%d gaps)\n\n",
                cfg.project, cfg.version, level, ts,
                satisfied, total, gaps);
        fprintf(out, "%-12s %-60s %s\n", "ID", "OBJECTIVE", "STATUS");
        fprintf(out, "%-12s %-60s %s\n",
                "------------",
                "------------------------------------------------------------",
                "---------");
        for (int i = 0; OBJECTIVES[i].id; i++) {
            if (OBJECTIVES[i].min_level > level) continue;
            int ok = OBJECTIVES[i].evidence_file &&
                     slsa_file_exists(dir, OBJECTIVES[i].evidence_file);
            fprintf(out, "%-12s %-60s %s\n",
                    OBJECTIVES[i].id, OBJECTIVES[i].title,
                    ok ? "[x] SATISFIED" : "[ ] GAP");
        }
        fprintf(out, "\nProvide evidence files or update CI to close remaining gaps.\n");
    }

    if (output && out != stdout) fclose(out);
    return gaps > 0 ? 1 : 0;
}
