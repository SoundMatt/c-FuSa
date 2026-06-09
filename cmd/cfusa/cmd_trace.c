/*
 * cfusa trace — Requirements traceability matrix.
 *
 * Reads requirements from .cfusa-reqs.json and scans C source files for:
 *   //cfusa:req REQ-ID       implementation reference
 *   //cfusa:test REQ-ID      test reference
 *   //cfusa:sec-test REQ-ID  security-test reference
 *   // REQ: REQ-ID           legacy annotation (still supported unless --no-legacy)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/report.h"
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
                 char standard[64]; char level[32]; } req_t;
typedef struct { char req_id[MAX_ID]; char file[256];
                 int line; int kind; } tag_t;

static req_t g_reqs[MAX_REQS];  static int g_req_count;
static tag_t g_tags[MAX_TAGS];  static int g_tag_count;

/* ---- minimal JSON field extractor for { ... } objects ---- */
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

/* Load requirements from .cfusa-reqs.json (graceful if absent) */
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
        char obj[1024] = "";
        size_t ol = (size_t)(be - bs + 1);
        if (ol > sizeof(obj) - 1) ol = sizeof(obj) - 1;
        memcpy(obj, bs, ol);
        jfield(obj, "id",       g_reqs[g_req_count].id,       MAX_ID);
        jfield(obj, "title",    g_reqs[g_req_count].title,    MAX_TITLE);
        jfield(obj, "standard", g_reqs[g_req_count].standard, 64);
        jfield(obj, "level",    g_reqs[g_req_count].level,    32);
        if (g_reqs[g_req_count].id[0]) g_req_count++;
        p = be + 1;
    }
    free(json);
}

/* ---- annotation scanner ---- */
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

typedef struct { int legacy; } scan_ctx_t;

static void trace_line_cb(const char *path, int lineno,
                           const char *line, void *vctx)
{
    scan_ctx_t *ctx = vctx;
    const char *p;
    if ((p = strstr(line, "//cfusa:req ")))
        add_tag(path, lineno, p + 12, KIND_IMPL);
    if ((p = strstr(line, "//cfusa:test ")))
        add_tag(path, lineno, p + 13, KIND_TEST);
    if ((p = strstr(line, "//cfusa:sec-test ")))
        add_tag(path, lineno, p + 17, KIND_SEC_TEST);
    if (ctx->legacy && (p = strstr(line, "REQ:"))) {
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

static int trace_file_cb(const char *path, void *v)
{ cfusa_scan_lines(path, trace_line_cb, v); return 0; }

/* Compute coverage for known requirements */
static void compute_coverage(int *traced, int *tested)
{
    *traced = *tested = 0;
    for (int i = 0; i < g_req_count; i++) {
        int hi = 0, ht = 0;
        for (int j = 0; j < g_tag_count; j++) {
            if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                if (g_tags[j].kind == KIND_IMPL) hi = 1;
                else ht = 1;
            }
        }
        if (hi) (*traced)++;
        if (ht) (*tested)++;
    }
}

int cmd_trace(int argc, char **argv)
{
    const char *dir  = ".";
    const char *out_path = NULL;
    const char *fmt_s    = "text";
    int show_gaps    = 0;
    int req_coverage = 0;
    int sec_tested   = 0;
    int legacy       = 1;

    static const struct option lo[] = {
        {"dir",          required_argument, NULL, 'd'},
        {"output",       required_argument, NULL, 'o'},
        {"format",       required_argument, NULL, 'f'},
        {"gaps",         no_argument,       NULL, 'g'},
        {"req-coverage", required_argument, NULL, 'r'},
        {"sec-tested",   required_argument, NULL, 's'},
        {"no-legacy",    no_argument,       NULL, 'L'},
        {"help",         no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:f:gr:s:Lh", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir          = optarg;        break;
        case 'o': out_path     = optarg;        break;
        case 'f': fmt_s        = optarg;        break;
        case 'g': show_gaps    = 1;             break;
        case 'r': req_coverage = atoi(optarg);  break;
        case 's': sec_tested   = atoi(optarg);  break;
        case 'L': legacy       = 0;             break;
        case 'h':
            printf("Usage: cfusa trace [--dir <path>] [--format text|json|md]\n"
                   "                   [--output <file>] [--gaps]\n"
                   "                   [--req-coverage <N%%>] [--sec-tested <N%%>]\n\n"
                   "Builds a requirements traceability matrix from .cfusa-reqs.json\n"
                   "and source annotations:\n"
                   "  //cfusa:req REQ-ID       — implementation reference\n"
                   "  //cfusa:test REQ-ID      — test reference\n"
                   "  //cfusa:sec-test REQ-ID  — security-test reference\n\n"
                   "  --gaps           list requirements with no //cfusa:test tag\n"
                   "  --req-coverage N exit 1 if <N%% of requirements have impl traces\n"
                   "  --sec-tested N   exit 1 if <N%% of requirements have test traces\n");
            return 0;
        default: return 1;
        }
    }

    g_req_count = g_tag_count = 0;
    load_reqs(dir);

    scan_ctx_t sctx = {legacy};
    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, trace_file_cb, &sctx);

    int total = g_req_count;
    int traced, tested;
    compute_coverage(&traced, &tested);

    /* --- coverage gates --- */
    if (req_coverage > 0 && total > 0) {
        int pct = traced * 100 / total;
        printf("req-coverage: %d%% (%d/%d requirements have implementation traces)\n",
               pct, traced, total);
        if (pct < req_coverage) {
            fprintf(stderr,
                    "cfusa trace: req-coverage gate failed: %d%% < required %d%%\n",
                    pct, req_coverage);
            return 1;
        }
        return 0;
    }
    if (sec_tested > 0 && total > 0) {
        int pct = tested * 100 / total;
        printf("sec-tested: %d%% (%d/%d requirements have test traces)\n",
               pct, tested, total);
        if (pct < sec_tested) {
            fprintf(stderr,
                    "cfusa trace: sec-tested gate failed: %d%% < required %d%%\n",
                    pct, sec_tested);
            return 1;
        }
        return 0;
    }

    /* --- --gaps mode --- */
    if (show_gaps) {
        int gaps = 0;
        printf("Test coverage gaps:\n\n");
        for (int i = 0; i < g_req_count; i++) {
            int ht = 0;
            for (int j = 0; j < g_tag_count; j++)
                if (!strcmp(g_tags[j].req_id, g_reqs[i].id) &&
                    g_tags[j].kind != KIND_IMPL) ht = 1;
            if (!ht) {
                printf("  %-24s  %s\n", g_reqs[i].id, g_reqs[i].title);
                gaps++;
            }
        }
        printf("\n%d / %d requirements untested\n", gaps, g_req_count);
        return (gaps > 0) ? 1 : 0;
    }

    /* --- output --- */
    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    FILE *out = stdout;
    if (out_path) { out = fopen(out_path, "w"); if (!out) { perror(out_path); return 1; } }

    if (fmt == FMT_JSON) {
        fprintf(out,
            "{\n  \"total\": %d, \"traced\": %d, \"tested\": %d,\n"
            "  \"matrix\": [\n", total, traced, tested);
        for (int i = 0; i < g_req_count; i++) {
            fprintf(out, "    {\"id\": \"%s\", \"title\": \"%s\", \"tags\": [",
                    g_reqs[i].id, g_reqs[i].title);
            int first = 1;
            for (int j = 0; j < g_tag_count; j++) {
                if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                    const char *k = g_tags[j].kind == KIND_IMPL ? "impl" :
                                    g_tags[j].kind == KIND_TEST ? "test" : "sec-test";
                    fprintf(out, "%s{\"kind\":\"%s\",\"file\":\"%s\",\"line\":%d}",
                            first ? "" : ",", k, g_tags[j].file, g_tags[j].line);
                    first = 0;
                }
            }
            fprintf(out, "]}%s\n", (i < g_req_count - 1) ? "," : "");
        }
        fprintf(out, "  ]\n}\n");
    } else if (fmt == FMT_MD) {
        fprintf(out, "# Requirements Traceability Matrix\n\n");
        if (g_req_count > 0) {
            fprintf(out, "| Req ID | Title | Impl | Test |\n|---|---|---|---|\n");
            for (int i = 0; i < g_req_count; i++) {
                char iloc[64] = "(none)", tloc[64] = "(none)";
                int hi = 0, ht = 0;
                for (int j = 0; j < g_tag_count; j++) {
                    if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                        if (g_tags[j].kind == KIND_IMPL && !hi) {
                            snprintf(iloc, sizeof(iloc), "%s:%d",
                                cfusa_basename(g_tags[j].file), g_tags[j].line);
                            hi = 1;
                        } else if (!ht) {
                            snprintf(tloc, sizeof(tloc), "%s:%d",
                                cfusa_basename(g_tags[j].file), g_tags[j].line);
                            ht = 1;
                        }
                    }
                }
                fprintf(out, "| %s | %s | %s | %s |\n",
                        g_reqs[i].id, g_reqs[i].title, iloc, tloc);
            }
        } else {
            fprintf(out, "| Annotation | File | Line | Kind |\n|---|---|---|---|\n");
            for (int j = 0; j < g_tag_count; j++) {
                const char *k = g_tags[j].kind == KIND_IMPL ? "impl" :
                                g_tags[j].kind == KIND_TEST ? "test" : "sec-test";
                fprintf(out, "| %s | %s | %d | %s |\n",
                        g_tags[j].req_id,
                        cfusa_basename(g_tags[j].file),
                        g_tags[j].line, k);
            }
        }
        fprintf(out, "\n**Coverage:** %d/%d traced, %d/%d tested\n",
                traced, total, tested, total);
    } else {
        /* text */
        fprintf(out, "Requirements Traceability Matrix\n");
        if (g_req_count > 0) {
            fprintf(out, "%-24s  %-32s  %-22s  %-22s\n",
                    "REQUIREMENT", "TITLE", "IMPL", "TEST");
            fprintf(out, "%-24s  %-32s  %-22s  %-22s\n",
                    "------------------------",
                    "--------------------------------",
                    "----------------------","----------------------");
            for (int i = 0; i < g_req_count; i++) {
                char iloc[64] = "(none)", tloc[64] = "(none)";
                int hi = 0, ht = 0;
                for (int j = 0; j < g_tag_count; j++) {
                    if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                        if (g_tags[j].kind == KIND_IMPL && !hi) {
                            snprintf(iloc, sizeof(iloc), "%s:%d",
                                cfusa_basename(g_tags[j].file), g_tags[j].line);
                            hi = 1;
                        } else if (!ht) {
                            snprintf(tloc, sizeof(tloc), "%s:%d",
                                cfusa_basename(g_tags[j].file), g_tags[j].line);
                            ht = 1;
                        }
                    }
                }
                fprintf(out, "%-24s  %-32.32s  %-22s  %-22s\n",
                        g_reqs[i].id, g_reqs[i].title, iloc, tloc);
            }
            fprintf(out, "\nCoverage: %d/%d requirements traced, %d/%d tested\n",
                    traced, total, tested, total);
        } else if (g_tag_count > 0) {
            fprintf(out, "\n%-24s  %-40s  %s\n", "ANNOTATION", "FILE", "LINE");
            fprintf(out, "%-24s  %-40s  %s\n",
                    "------------------------",
                    "----------------------------------------", "----");
            for (int j = 0; j < g_tag_count; j++)
                fprintf(out, "%-24s  %-40s  %d\n",
                        g_tags[j].req_id,
                        cfusa_basename(g_tags[j].file), g_tags[j].line);
            fprintf(out, "\nTotal: %d annotation(s)  "
                    "(create .cfusa-reqs.json to register requirements)\n",
                    g_tag_count);
        } else {
            fprintf(out,
                "\nNo annotations found. Annotate with //cfusa:req REQ-ID in source.\n");
        }
    }

    if (out_path && out != stdout) fclose(out);
    return 0;
}
