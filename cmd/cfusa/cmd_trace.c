/*
 * cfusa trace — Requirements traceability matrix.
 *
 * Reads requirements from .cfusa-reqs.json and scans C source files for:
 *   //cfusa:req REQ-ID       implementation reference
 *   //cfusa:test REQ-ID      test reference
 *   //cfusa:sec-test REQ-ID  security-test reference
 *   // REQ: REQ-ID           legacy annotation (still supported unless --no-legacy)
 */
#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include "cfusa/report.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

#define REQS_FILE        ".fusa-reqs.json"
#define REQS_FILE_LEGACY ".cfusa-reqs.json"
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
static char  g_dir_abs[512];    /* resolved absolute project root for path relativization */

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

/* Load requirements — try .fusa-reqs.json first, fall back to legacy .cfusa-reqs.json */
static void load_reqs(const char *dir)
{
    char path[512]; cfusa_path_join(path, sizeof(path), dir, REQS_FILE);
    size_t len; char *json = cfusa_read_file(path, &len);
    if (!json) {
        cfusa_path_join(path, sizeof(path), dir, REQS_FILE_LEGACY);
        json = cfusa_read_file(path, &len);
        if (json)
            fprintf(stderr, "cfusa trace: WARNING: %s is deprecated; rename to %s\n",
                    REQS_FILE_LEGACY, REQS_FILE);
    }
    if (!json) return;

    /* §1.2.2: check for duplicate requirement ids and emit ERRORs */
    /* (collected after loading; detected via second pass below) */

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

    /* §1.2.2: duplicate-id MUST surface as ERROR to stderr */
    for (int i = 0; i < g_req_count; i++) {
        for (int j = i + 1; j < g_req_count; j++) {
            if (!strcmp(g_reqs[i].id, g_reqs[j].id))
                fprintf(stderr,
                        "cfusa trace: ERROR: duplicate requirement id '%s' in %s\n",
                        g_reqs[i].id, REQS_FILE);
        }
    }
}

/* ---- annotation scanner ---- */
static void add_tag(const char *path, int lineno, const char *ids, int kind)
{
    /* Relativize path against project root (§5 tags[].file MUST be project-relative) */
    const char *rel = path;
    if (g_dir_abs[0]) {
        size_t prlen = strlen(g_dir_abs);
        if (strncmp(path, g_dir_abs, prlen) == 0 &&
            (path[prlen] == '/' || path[prlen] == '\0'))
            rel = path + prlen + (path[prlen] == '/');
    }
    while (rel[0] == '.' && rel[1] == '/') rel += 2;
    const char *relpath = rel[0] ? rel : path;

    char buf[512]; strncpy(buf, ids, sizeof(buf) - 1);
    char *end = strpbrk(buf, "\n\r\""); if (end) *end = '\0';
    char *tok = strtok(buf, " \t,");
    while (tok && g_tag_count < MAX_TAGS) {
        char *t = cfusa_str_trim(tok);
        /* Only accept valid IDs: non-empty, alphanumeric + '-'/'_' */
        int valid = t[0] != '\0';
        for (const char *p = t; *p && valid; p++) {
            unsigned char c = (unsigned char)*p;
            if (!isalnum(c) && c != '-' && c != '_') valid = 0;
        }
        if (valid) {
            strncpy(g_tags[g_tag_count].req_id, t,       MAX_ID - 1);
            strncpy(g_tags[g_tag_count].file,   relpath, 255);
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

/* Compute coverage per §5 counting rules */
static void compute_coverage(int *traced, int *tested, int *sec_tested)
{
    *traced = *tested = *sec_tested = 0;
    for (int i = 0; i < g_req_count; i++) {
        int any = 0, ht = 0, hst = 0;
        for (int j = 0; j < g_tag_count; j++) {
            if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                any = 1;
                if (g_tags[j].kind == KIND_TEST)     ht  = 1;
                if (g_tags[j].kind == KIND_SEC_TEST) { ht = 1; hst = 1; }
            }
        }
        if (any) (*traced)++;
        if (ht)  (*tested)++;
        if (hst) (*sec_tested)++;
    }
}

/* ---- Metric 2: function annotation density ---- */

#define MAX_FUNCS 512

static char g_func_names[MAX_FUNCS][192];
static int  g_func_covered[MAX_FUNCS];
static int  g_func_count;
static int  g_func_covered_count;

static int is_test_file(const char *path)
{
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (strncmp(b, "test_", 5) == 0) return 1;
    size_t n = strlen(b);
    return n > 7 && strcmp(b + n - 7, "_test.c") == 0;
}

static int looks_like_funcdef(const char *line, char *name, size_t sz)
{
    if (!line[0] || (!isalpha((unsigned char)line[0]) && line[0] != '_'))
        return 0;
    static const char *kws[] = {"typedef ", "struct ", "enum ", "//", "/*",
                                  "static ", "extern ", NULL};
    for (int i = 0; kws[i]; i++)
        if (strncmp(line, kws[i], strlen(kws[i])) == 0) return 0;
    const char *paren = strchr(line, '(');
    if (!paren) return 0;
    const char *p = paren - 1;
    while (p > line && (*p == ' ' || *p == '\t' || *p == '*')) p--;
    const char *end = p + 1;
    while (p > line && (isalnum((unsigned char)*(p - 1)) || *(p - 1) == '_')) p--;
    size_t n = (size_t)(end - p);
    if (n == 0 || n >= sz) return 0;
    if (!isalpha((unsigned char)*p) && *p != '_') return 0;
    memcpy(name, p, n);
    name[n] = '\0';
    return 1;
}

typedef struct { const char *relpath; int annotated; } fscan_ctx_t;

static void func_line_cb(const char *path, int lineno, const char *line, void *v)
{
    (void)path; (void)lineno;
    fscan_ctx_t *ctx = v;
    char name[128];
    if (g_func_count < MAX_FUNCS && looks_like_funcdef(line, name, sizeof(name))) {
        snprintf(g_func_names[g_func_count], 192, "%s:%s", ctx->relpath, name);
        g_func_covered[g_func_count] = ctx->annotated;
        if (ctx->annotated) g_func_covered_count++;
        g_func_count++;
    }
}

static int funcfile_cb(const char *path, void *v)
{
    (void)v;
    if (is_test_file(path)) return 0;
    const char *rel = path;
    if (g_dir_abs[0]) {
        size_t pl = strlen(g_dir_abs);
        if (strncmp(path, g_dir_abs, pl) == 0 &&
            (path[pl] == '/' || path[pl] == '\0'))
            rel = path + pl + (path[pl] == '/');
    }
    while (rel[0] == '.' && rel[1] == '/') rel += 2;
    const char *relpath = rel[0] ? rel : path;

    int ann = 0;
    for (int i = 0; i < g_tag_count && !ann; i++)
        if (g_tags[i].kind == KIND_IMPL && strcmp(g_tags[i].file, relpath) == 0)
            ann = 1;

    fscan_ctx_t ctx = {relpath, ann};
    cfusa_scan_lines(path, func_line_cb, &ctx);
    return 0;
}

static void do_scan_funcs(const char *root)
{
    g_func_count = g_func_covered_count = 0;
    static const char * const fexts[] = {".c"};
    cfusa_walk_sources(root, fexts, 1, funcfile_cb, NULL);
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
        default: return 2;
        }
    }

    g_req_count = g_tag_count = 0;
    g_dir_abs[0] = '\0';
    {
        char *tmp = realpath(dir, NULL);
        if (tmp) { strncpy(g_dir_abs, tmp, sizeof(g_dir_abs) - 1); free(tmp); }
        else strncpy(g_dir_abs, dir, sizeof(g_dir_abs) - 1);
    }
    load_reqs(dir);

    scan_ctx_t sctx = {legacy};
    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, trace_file_cb, &sctx);

    int total = g_req_count;
    int traced, tested, sec_tested_count;
    compute_coverage(&traced, &tested, &sec_tested_count);

    /* --- req-coverage gate (metric 1 + metric 2) --- */
    if (req_coverage > 0) {
        printf("Requirement Coverage Report\n\n");

        /* Metric 1: requirement traceability */
        int m1na = (total == 0);
        int req_pct = 0;
        if (m1na) {
            printf("Metric 1 — Requirement traceability:  N/A (no requirements defined)\n");
        } else {
            req_pct = traced * 100 / total;
            printf("Metric 1 — Requirement traceability:  %d%% (%d/%d requirements traced)\n",
                   req_pct, traced, total);
            for (int i = 0; i < g_req_count; i++) {
                int found = 0;
                for (int j = 0; j < g_tag_count && !found; j++)
                    if (g_tags[j].kind == KIND_IMPL &&
                        strcmp(g_tags[j].req_id, g_reqs[i].id) == 0) found = 1;
                if (!found)
                    printf("  UNTRACED  %-20s  %s\n", g_reqs[i].id, g_reqs[i].title);
            }
        }

        /* Metric 2: function annotation density — use same root as trace scan */
        do_scan_funcs(dir);
        int m2na = (g_func_count == 0);
        int func_pct = m2na ? 0 : g_func_covered_count * 100 / g_func_count;
        if (m2na) {
            printf("\nMetric 2 — Function annotation density: N/A (no exported functions found)\n");
        } else {
            printf("\nMetric 2 — Function annotation density: %d%% (%d/%d functions in annotated files)\n",
                   func_pct, g_func_covered_count, g_func_count);
            int shown = 0;
            for (int i = 0; i < g_func_count; i++) {
                if (g_func_covered[i]) continue;
                if (shown >= 20) {
                    int rem = 0;
                    for (int k = i; k < g_func_count; k++) if (!g_func_covered[k]) rem++;
                    printf("  ... and %d more\n", rem);
                    break;
                }
                printf("  UNANNOTATED  %s\n", g_func_names[i]);
                shown++;
            }
        }

        int failed = 0;
        if (!m1na && req_pct < req_coverage) {
            fprintf(stderr,
                    "cfusa trace: req-coverage gate failed (metric 1: %d%% < required %d%%)\n",
                    req_pct, req_coverage);
            failed = 1;
        }
        if (!m2na && func_pct < req_coverage) {
            fprintf(stderr,
                    "cfusa trace: req-coverage gate failed (metric 2: %d%% < required %d%%)\n",
                    func_pct, req_coverage);
            failed = 1;
        }
        return failed ? 1 : 0;
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

    /* --- output --- */
    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    FILE *out = stdout;
    if (out_path) { out = fopen(out_path, "w"); if (!out) { perror(out_path); return 3; } }

    if (fmt == FMT_JSON) {
        char ts[32]; cfusa_timestamp_now(ts);

        /* spec §5: requirements[] + tags[] + coverage{}, §3.2 projectRoot */
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"trace-matrix\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"projectRoot\": \"%s\",\n", ts, g_dir_abs);

        /* requirements[] */
        fprintf(out, "  \"requirements\": [\n");
        for (int i = 0; i < g_req_count; i++) {
            char esc_id[MAX_ID*2], esc_title[MAX_TITLE*2],
                 esc_std[128], esc_lvl[64];
            cfusa_str_escape_json(g_reqs[i].id,       esc_id,    sizeof(esc_id));
            cfusa_str_escape_json(g_reqs[i].title,    esc_title, sizeof(esc_title));
            cfusa_str_escape_json(g_reqs[i].standard, esc_std,   sizeof(esc_std));
            cfusa_str_escape_json(g_reqs[i].level,    esc_lvl,   sizeof(esc_lvl));
            fprintf(out, "    {\"id\": \"%s\", \"title\": \"%s\"",
                    esc_id, esc_title);
            if (esc_std[0])
                fprintf(out, ", \"standard\": \"%s\"", esc_std);
            if (esc_lvl[0])
                fprintf(out, ", \"level\": \"%s\"",    esc_lvl);
            fprintf(out, "}%s\n", (i < g_req_count - 1) ? "," : "");
        }
        fprintf(out, "  ],\n");

        /* tags[] */
        fprintf(out, "  \"tags\": [\n");
        for (int j = 0; j < g_tag_count; j++) {
            char esc_rid[MAX_ID*2], esc_file[512];
            cfusa_str_escape_json(g_tags[j].req_id, esc_rid,  sizeof(esc_rid));
            cfusa_str_escape_json(g_tags[j].file,   esc_file, sizeof(esc_file));
            const char *kind_s = (g_tags[j].kind == KIND_TEST)    ? "test"
                               : (g_tags[j].kind == KIND_SEC_TEST) ? "sec-test"
                               :                                      "impl";
            fprintf(out,
                "    {\"requirementId\": \"%s\", \"file\": \"%s\","
                " \"line\": %d, \"kind\": \"%s\"}%s\n",
                esc_rid, esc_file, g_tags[j].line, kind_s,
                (j < g_tag_count - 1) ? "," : "");
        }
        fprintf(out, "  ],\n");

        /* coverage{} */
        fprintf(out,
            "  \"coverage\": {\n"
            "    \"totalRequirements\": %d,\n"
            "    \"tracedRequirements\": %d,\n"
            "    \"testedRequirements\": %d,\n"
            "    \"secTestedRequirements\": %d\n"
            "  }\n"
            "}\n",
            total, traced, tested, sec_tested_count);
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
        if (show_gaps) {
            /* --gaps text mode: list untested requirements */
            int gaps = 0;
            fprintf(out, "Test coverage gaps:\n\n");
            for (int i = 0; i < g_req_count; i++) {
                int ht = 0;
                for (int j = 0; j < g_tag_count; j++)
                    if (!strcmp(g_tags[j].req_id, g_reqs[i].id) &&
                        g_tags[j].kind != KIND_IMPL) ht = 1;
                if (!ht) {
                    fprintf(out, "  %-24s  %s\n", g_reqs[i].id, g_reqs[i].title);
                    gaps++;
                }
            }
            fprintf(out, "\n%d / %d requirements untested\n", gaps, g_req_count);
            if (out_path && out != stdout) fclose(out);
            return (gaps > 0) ? 1 : 0;
        }

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
                    "(create .fusa-reqs.json to register requirements)\n",
                    g_tag_count);
        } else {
            fprintf(out,
                "\nNo annotations found. Annotate with //cfusa:req REQ-ID in source.\n");
        }
    }

    if (out_path && out != stdout) fclose(out);
    return 0;
}
