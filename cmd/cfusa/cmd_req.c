/*
 * cfusa req — Requirements registry management.
 *
 * With no IDs: lists all requirements from .cfusa-reqs.json with their
 * source and test locations.
 * With one or more IDs: shows details and locations for those requirements.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

#define REQS_FILE  ".cfusa-reqs.json"
#define MAX_REQS   1024
#define MAX_TAGS   4096
#define MAX_ID     64
#define MAX_TITLE  128

#define KIND_IMPL     0
#define KIND_TEST     1
#define KIND_SEC_TEST 2

typedef struct { char id[MAX_ID]; char title[MAX_TITLE];
                 char text[512];  char standard[64];
                 char level[32];  } req_t;
typedef struct { char req_id[MAX_ID]; char file[256];
                 int  line; int kind; } tag_t;

static req_t g_reqs[MAX_REQS]; static int g_req_count;
static tag_t g_tags[MAX_TAGS]; static int g_tag_count;

static void jfield(const char *obj, const char *key, char *out, size_t sz)
{
    out[0] = '\0';
    char pat[96]; snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(obj, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ') p++;
    if (*p != '"') return; p++;
    size_t i = 0;
    while (*p && *p != '"' && i < sz - 1) {
        if (*p == '\\') { p++; if (!*p) break; }
        out[i++] = *p++;
    }
    out[i] = '\0';
}

static void load_reqs(const char *dir)
{
    char path[512]; cfusa_path_join(path, sizeof(path), dir, REQS_FILE);
    size_t len; char *json = cfusa_read_file(path, &len);
    if (!json) return;
    const char *p = strstr(json, "\"requirements\"");
    if (p) p = strchr(p, '[');
    if (!p) { free(json); return; }
    p++;
    while (*p && *p != ']' && g_req_count < MAX_REQS) {
        const char *bs = strchr(p, '{'); if (!bs) break;
        const char *be = strchr(bs, '}'); if (!be) break;
        char obj[2048] = "";
        size_t ol = (size_t)(be - bs + 1);
        if (ol > sizeof(obj) - 1) ol = sizeof(obj) - 1;
        memcpy(obj, bs, ol);
        jfield(obj, "id",       g_reqs[g_req_count].id,       MAX_ID);
        jfield(obj, "title",    g_reqs[g_req_count].title,    MAX_TITLE);
        jfield(obj, "text",     g_reqs[g_req_count].text,     512);
        jfield(obj, "standard", g_reqs[g_req_count].standard, 64);
        jfield(obj, "level",    g_reqs[g_req_count].level,    32);
        if (g_reqs[g_req_count].id[0]) g_req_count++;
        p = be + 1;
    }
    free(json);
}

static void add_tag(const char *path, int lineno, const char *ids, int kind)
{
    char buf[512]; strncpy(buf, ids, sizeof(buf) - 1);
    char *end = strpbrk(buf, "\n\r"); if (end) *end = '\0';
    char *tok = strtok(buf, " \t,");
    while (tok && g_tag_count < MAX_TAGS) {
        char *t = cfusa_str_trim(tok);
        if (*t && *t != '*' && *t != '/') {
            strncpy(g_tags[g_tag_count].req_id, t,    MAX_ID - 1);
            strncpy(g_tags[g_tag_count].file,   path, 255);
            g_tags[g_tag_count].line = lineno;
            g_tags[g_tag_count].kind = kind;
            g_tag_count++;
        }
        tok = strtok(NULL, " \t,");
    }
}

static void scan_line(const char *path, int lineno,
                       const char *line, void *vctx)
{
    (void)vctx;
    const char *p;
    if ((p = strstr(line, "//cfusa:req ")))
        add_tag(path, lineno, p + 12, KIND_IMPL);
    if ((p = strstr(line, "//cfusa:test ")))
        add_tag(path, lineno, p + 13, KIND_TEST);
    if ((p = strstr(line, "//cfusa:sec-test ")))
        add_tag(path, lineno, p + 17, KIND_SEC_TEST);
    /* legacy */
    if ((p = strstr(line, "REQ:"))) {
        p += 4;
        while (*p == ' ' || *p == '\t') p++;
        char buf[512]; strncpy(buf, p, sizeof(buf) - 1);
        char *e = strpbrk(buf, "*/\n"); if (e) *e = '\0';
        char *tok = strtok(buf, ", \t");
        while (tok && g_tag_count < MAX_TAGS) {
            char *t = cfusa_str_trim(tok);
            if (*t) add_tag(path, lineno, t, KIND_IMPL);
            tok = strtok(NULL, ", \t");
        }
    }
}

static int scan_file(const char *path, void *v)
{ cfusa_scan_lines(path, scan_line, v); return 0; }

int cmd_req(int argc, char **argv)
{
    const char *dir = ".";

    static const struct option lo[] = {
        {"dir",  required_argument, NULL, 'd'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "d:h", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir = optarg; break;
        case 'h':
            printf("Usage: cfusa req [--dir <path>] [REQ-ID ...]\n\n"
                   "List requirements and their source/test locations.\n"
                   "With no IDs, lists all requirements from .cfusa-reqs.json.\n"
                   "With IDs, filters to the named requirements.\n");
            return 0;
        default: return 1;
        }
    }

    g_req_count = g_tag_count = 0;
    load_reqs(dir);

    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, scan_file, NULL);

    /* build filter set from remaining args */
    int nfilter = argc - optind;
    char **filter = &argv[optind];

    if (g_req_count == 0) {
        /* No registry — fall back to showing all tags */
        if (g_tag_count == 0) {
            printf("No requirements found. Create %s/%s to register requirements.\n",
                   dir, REQS_FILE);
            return 1;
        }
        printf("Annotations (no %s):\n\n", REQS_FILE);
        for (int j = 0; j < g_tag_count; j++) {
            const char *k = g_tags[j].kind == KIND_IMPL ? "impl" :
                            g_tags[j].kind == KIND_TEST ? "test" : "sec-test";
            printf("  %-20s  [%s]  %s:%d\n",
                   g_tags[j].req_id, k,
                   cfusa_basename(g_tags[j].file), g_tags[j].line);
        }
        return 0;
    }

    int printed = 0, rc = 0;
    for (int i = 0; i < g_req_count; i++) {
        /* apply filter */
        if (nfilter > 0) {
            int match = 0;
            for (int k = 0; k < nfilter; k++)
                if (!strcmp(filter[k], g_reqs[i].id)) { match = 1; break; }
            if (!match) continue;
        }
        printed++;
        printf("%s  %s\n", g_reqs[i].id, g_reqs[i].title);
        if (g_reqs[i].text[0])
            printf("  %s\n", g_reqs[i].text);
        if (g_reqs[i].standard[0]) {
            printf("  Standard: %s", g_reqs[i].standard);
            if (g_reqs[i].level[0])
                printf("  Level: %s", g_reqs[i].level);
            printf("\n");
        }
        int any = 0;
        for (int j = 0; j < g_tag_count; j++) {
            if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                const char *k = g_tags[j].kind == KIND_IMPL ? "impl" :
                                g_tags[j].kind == KIND_TEST ? "test" : "sec-test";
                printf("  %-10s  %s:%d\n", k,
                       g_tags[j].file, g_tags[j].line);
                any = 1;
            }
        }
        if (!any) printf("  (no annotations found)\n");
        printf("\n");
    }

    if (nfilter > 0 && printed == 0) {
        for (int k = 0; k < nfilter; k++)
            fprintf(stderr, "cfusa req: requirement %s not found\n", filter[k]);
        rc = 1;
    }
    if (printed == 0 && nfilter == 0) {
        printf("No requirements in %s/%s\n", dir, REQS_FILE);
        rc = 1;
    }
    return rc;
}
