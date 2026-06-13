#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * Hazard Analysis and Risk Assessment (ISO 26262-3:2018 Clause 6).
 *
 * Subcommands:
 *   init  — write a .cfusa-hara.json skeleton
 *   show  — display all hazard entries with ASIL rating
 *   asil  — compute ASIL from S/E/C parameters
 */

#define HARA_FILE        ".fusa-hara.json"
#define HARA_FILE_LEGACY ".cfusa-hara.json"

/*
 * ISO 26262-3:2018 Table 4 ASIL determination.
 * Indices: [S1-S3][E1-E4][C1-C3]  (C0 always QM, omitted)
 */
//cfusa:req REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005 REQ-HARA006 REQ-HARA007 REQ-HARA008 REQ-HARA009
static const char *asil_table[3][4][3] = {
    /* S1: slight to moderate injuries */
    {
        {"QM","QM","QM"},      /* E1 */
        {"QM","QM","QM"},      /* E2 */
        {"QM","QM","ASIL-A"},  /* E3 */
        {"QM","ASIL-A","ASIL-B"}  /* E4 */
    },
    /* S2: severe/life-threatening injuries, survival probable */
    {
        {"QM","QM","QM"},         /* E1 */
        {"QM","QM","ASIL-A"},     /* E2 */
        {"QM","ASIL-A","ASIL-B"}, /* E3 */
        {"ASIL-A","ASIL-B","ASIL-C"}  /* E4 */
    },
    /* S3: life-threatening injuries, survival uncertain / fatal */
    {
        {"QM","QM","ASIL-A"},     /* E1 */
        {"QM","ASIL-A","ASIL-B"}, /* E2 */
        {"ASIL-A","ASIL-B","ASIL-C"},  /* E3 */
        {"ASIL-B","ASIL-C","ASIL-D"}   /* E4 */
    }
};

static const char *compute_asil(int s, int e, int c)
{
    /* s: 1-3 (S1-S3), e: 1-4 (E1-E4), c: 1-3 (C1-C3) */
    if (s < 1 || s > 3 || e < 1 || e > 4 || c < 1 || c > 3) return "QM";
    return asil_table[s - 1][e - 1][c - 1];
}

static void do_asil(int s, int e, int c)
{
    printf("ASIL Determination (ISO 26262-3:2018 Table 4)\n");
    printf("  Severity     S%d\n", s);
    printf("  Exposure     E%d\n", e);
    printf("  Controllability C%d\n", c);
    printf("  Result       %s\n", compute_asil(s, e, c));
}

static void do_init(const char *dir, const char *project, const char *version)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, HARA_FILE);

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return; }

    char ts[32]; cfusa_timestamp_now(ts);

    fprintf(f,
        "{\n"
        "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
        "  \"kind\": \"hara\",\n"
        "  \"tool\": \"c-FuSa\",\n"
        "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
        "  \"language\": \"c\",\n"
        "  \"generatedAt\": \"%s\",\n"
        "  \"project\": \"%s\",\n"
        "  \"version\": \"%s\",\n"
        "  \"standard\": \"ISO 26262-3:2018\",\n"
        "  \"hazards\": [\n"
        "    {\n"
        "      \"id\": \"HAZ-001\",\n"
        "      \"item\": \"[item under analysis]\",\n"
        "      \"hazardous_event\": \"[describe hazardous event]\",\n"
        "      \"severity\": 3,\n"
        "      \"exposure\": 3,\n"
        "      \"controllability\": 2,\n"
        "      \"asil\": \"ASIL-C\",\n"
        "      \"safe_state\": \"[describe safe state]\",\n"
        "      \"safety_goal\": \"[derive safety goal]\",\n"
        "      \"ftti_ms\": 100\n"
        "    }\n"
        "  ]\n"
        "}\n",
        ts, project, version);
    fclose(f);

    printf("HARA skeleton written to %s\n", path);
    printf("Edit hazards and run 'cfusa hara show' to review.\n");
}

static void do_show_json(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, HARA_FILE);
    size_t len;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, HARA_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) {
        fprintf(stderr, "cfusa hara: no %s found — run 'cfusa hara init' first\n", HARA_FILE);
        return;
    }
    fwrite(content, 1, len, stdout);
    if (len > 0 && content[len - 1] != '\n') putchar('\n');
    free(content);
}

static void do_show_md(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, HARA_FILE);
    size_t len;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, HARA_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) {
        fprintf(stderr, "cfusa hara: no %s found — run 'cfusa hara init' first\n", HARA_FILE);
        return;
    }

    printf("# Hazard Analysis and Risk Assessment (HARA)\n\n");
    printf("| ID | Hazardous Event | S | E | C | ASIL | Safety Goal |\n");
    printf("|---|---|---|---|---|---|---|\n");

    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[32]="", event[128]="", asil[16]="", goal[128]="";
        int sev=0, exp=0, ctl=0;
        char *blk = p;
        char *end = strstr(blk + 1, "\"id\"");
        if (!end) end = content + len;
        { char *fp = strstr(blk,"\"id\":");          if (fp) { fp+=5; while(*fp==' ') fp++; if(*fp=='"') fp++; sscanf(fp,"%31[^\"]",id); } }
        { char *fp = strstr(blk,"\"hazardous_event\":"); if (fp) { fp+=18; while(*fp==' ') fp++; if(*fp=='"') fp++; sscanf(fp,"%127[^\"]",event); } }
        { char *fp = strstr(blk,"\"asil\":");         if (fp) { fp+=7;  while(*fp==' ') fp++; if(*fp=='"') fp++; sscanf(fp,"%15[^\"]",asil); } }
        { char *fp = strstr(blk,"\"safety_goal\":");  if (fp) { fp+=14; while(*fp==' ') fp++; if(*fp=='"') fp++; sscanf(fp,"%127[^\"]",goal); } }
        { char *fp = strstr(blk,"\"severity\":");  if (fp) sscanf(fp,"\"severity\": %d",&sev); }
        { char *fp = strstr(blk,"\"exposure\":");  if (fp) sscanf(fp,"\"exposure\": %d",&exp); }
        { char *fp = strstr(blk,"\"controllability\":"); if (fp) sscanf(fp,"\"controllability\": %d",&ctl); }
        printf("| %s | %s | %d | %d | %d | %s | %s |\n", id, event, sev, exp, ctl, asil, goal);
        p = end;
    }
    free(content);
}

static void do_show(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, HARA_FILE);

    size_t len;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        /* legacy fallback */
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, HARA_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
        if (content) {
            strncpy(path, legacy, sizeof(path) - 1);
        } else {
            fprintf(stderr, "cfusa hara: no %s found — run 'cfusa hara init' first\n",
                    HARA_FILE);
            return;
        }
    }

    printf("Hazard Analysis and Risk Assessment\n");
    printf("=====================================\n");

    /* Simple extraction: find each hazard block */
    int count = 0;
    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[32]="", event[128]="", asil[16]="", goal[128]="", safe[128]="";
        int sev=0, exp=0, ctl=0, ftti=0;
        char *blk = p;

        /* Scan ahead to collect fields in this block */
        char *end = strstr(blk+1, "\"id\"");
        if (!end) end = content + len;

        if (strstr(blk, "\"id\"")) {
            char *fp = strstr(blk, "\"id\":");
            if (fp) { fp += 5; while(*fp==' '||*fp=='\t') fp++; if(*fp=='"') fp++; sscanf(fp, "%31[^\"]", id); }
        }
        {
            char *fp = strstr(blk, "\"hazardous_event\":");
            if (fp) { fp += 18; while(*fp==' '||*fp=='\t') fp++; if(*fp=='"') fp++; sscanf(fp, "%127[^\"]", event); }
        }
        {
            char *fp = strstr(blk, "\"asil\":");
            if (fp) { fp += 7; while(*fp==' '||*fp=='\t') fp++; if(*fp=='"') fp++; sscanf(fp, "%15[^\"]", asil); }
        }
        {
            char *fp = strstr(blk, "\"safety_goal\":");
            if (fp) { fp += 14; while(*fp==' '||*fp=='\t') fp++; if(*fp=='"') fp++; sscanf(fp, "%127[^\"]", goal); }
        }
        {
            char *fp = strstr(blk, "\"safe_state\":");
            if (fp) { fp += 13; while(*fp==' '||*fp=='\t') fp++; if(*fp=='"') fp++; sscanf(fp, "%127[^\"]", safe); }
        }
        {
            char *fp = strstr(blk, "\"severity\":");
            if (fp) sscanf(fp, "\"severity\": %d", &sev);
        }
        {
            char *fp = strstr(blk, "\"exposure\":");
            if (fp) sscanf(fp, "\"exposure\": %d", &exp);
        }
        {
            char *fp = strstr(blk, "\"controllability\":");
            if (fp) sscanf(fp, "\"controllability\": %d", &ctl);
        }
        {
            char *fp = strstr(blk, "\"ftti_ms\":");
            if (fp) sscanf(fp, "\"ftti_ms\": %d", &ftti);
        }

        printf("\n%s  [%s]\n", id, asil);
        printf("  Event:       %s\n", event);
        printf("  S%d/E%d/C%d   Safety Goal: %s\n", sev, exp, ctl, goal);
        printf("  Safe State:  %s\n", safe);
        if (ftti > 0)
            printf("  FTTI:        %d ms\n", ftti);

        /* Recompute ASIL from parameters to verify */
        const char *computed = compute_asil(sev, exp, ctl);
        if (strcmp(computed, asil) != 0)
            printf("  WARNING: stored ASIL %s differs from computed %s\n",
                   asil, computed);
        count++;
        p = end;
    }

    free(content);

    if (count == 0) {
        printf("No hazard entries found in %s\n", path);
    } else {
        printf("\n%d hazard(s) listed.\n", count);
    }
}

int cmd_hara(int argc, char **argv)
{
    const char *subcmd  = "show";
    const char *dir     = ".";
    const char *format  = "text";
    int s = 0, e = 0, c = 0;

    static const struct option long_opts[] = {
        {"dir",            required_argument, NULL, 'd'},
        {"format",         required_argument, NULL, 'F'},
        {"severity",       required_argument, NULL, 's'},
        {"exposure",       required_argument, NULL, 'e'},
        {"controllability",required_argument, NULL, 'c'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    /* First non-option arg is subcommand */
    if (argc >= 2 && argv[1][0] != '-') {
        subcmd = argv[1];
        argv++;
        argc--;
    }

    int opt;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "d:F:s:e:c:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd': dir    = optarg; break;
        case 'F': format = optarg; break;
        case 's': s = atoi(optarg); break;
        case 'e': e = atoi(optarg); break;
        case 'c': c = atoi(optarg); break;
        case 'h':
            printf("Usage: cfusa hara <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  init   Write a .fusa-hara.json skeleton\n"
                   "  show   Display all hazard entries with ASIL rating\n"
                   "  asil   Compute ASIL from S/E/C parameters\n\n"
                   "Options for 'show':\n"
                   "  --format text|json|markdown  Output format (default: text)\n\n"
                   "Options for 'asil':\n"
                   "  --severity N        Severity class S1-S3 (1-3, per ISO 26262-3 Table 4)\n"
                   "  --exposure N        Exposure class E1-E4 (1-4)\n"
                   "  --controllability N Controllability class C1-C3 (1-3)\n\n"
                   "ISO 26262-3:2018 Clause 6 — Hazard Analysis and Risk Assessment.\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "init")) {
        do_init(dir, cfg.project, cfg.version);
    } else if (!strcmp(subcmd, "asil")) {
        if (s == 0 || e == 0 || c == 0) {
            fprintf(stderr, "cfusa hara asil: requires --severity, --exposure, --controllability\n");
            return 1;
        }
        do_asil(s, e, c);
    } else if (!strcmp(format, "json")) {
        do_show_json(dir);
    } else if (!strcmp(format, "markdown") || !strcmp(format, "md")) {
        do_show_md(dir);
    } else {
        do_show(dir);
    }

    return 0;
}
