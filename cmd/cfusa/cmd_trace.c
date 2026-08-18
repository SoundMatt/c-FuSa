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
#define MAX_ID     64
#define MAX_TITLE  128

#define KIND_IMPL     0
#define KIND_TEST     1
#define KIND_SEC_TEST 2

typedef struct { char id[MAX_ID]; char title[MAX_TITLE];
                 char standard[64]; char level[32];
                 char parent_id[MAX_ID]; } req_t; /* parent_id: LLR→HLR link (REQ-HLR001) */
typedef struct { char req_id[MAX_ID]; char file[256];
                 int line; int kind; } tag_t;

static req_t *g_reqs; static int g_req_count; static int g_req_cap;
static tag_t *g_tags; static int g_tag_count; static int g_tag_cap;
/* Set when a tag fails to grow g_tags (OOM) — checked by the caller after
 * the source scan so a partial tag set is never mistaken for a complete
 * one (same rationale as reqs_reserve() below). */
static int g_tag_alloc_failed;
static char g_dir_abs[512];    /* resolved absolute project root for path relativization */

/*
 * Requirements and tags arrays both grow dynamically via realloc — neither
 * has a fixed cap. Compile-time array sizes here previously caused
 * .fusa-reqs.json files (or source trees with many //cfusa:req/test tags)
 * larger than the cap to be silently truncated mid-parse/mid-scan, which
 * let genuinely-incomplete data read as fully loaded (false 100% coverage)
 * to every downstream consumer (project issue #100). A growth failure
 * (OOM) is reported to the caller instead of silently dropping entries.
 */
#define REQS_INITIAL_CAP 128
#define TAGS_INITIAL_CAP 256

static int reqs_reserve(int need)
{
    if (need <= g_req_cap) return 1;
    int new_cap = g_req_cap ? g_req_cap : REQS_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    req_t *tmp = realloc(g_reqs, (size_t)new_cap * sizeof(req_t));
    if (!tmp) return 0;
    g_reqs = tmp;
    g_req_cap = new_cap;
    return 1;
}

static int tags_reserve(int need)
{
    if (need <= g_tag_cap) return 1;
    int new_cap = g_tag_cap ? g_tag_cap : TAGS_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    tag_t *tmp = realloc(g_tags, (size_t)new_cap * sizeof(tag_t));
    if (!tmp) return 0;
    g_tags = tmp;
    g_tag_cap = new_cap;
    return 1;
}

/* ---- HLR/LLR decomposition state (REQ-HLR001) ---- */
/* issue #167: these five arrays were fixed at a compile-time MAX_HLR_LLR
 * cap and silently stopped accumulating once full, with no warning —
 * exactly the "fixed-cap silent truncation" pattern eliminated from
 * g_reqs/g_tags above for issue #100. Now grow dynamically via realloc,
 * the same pattern as reqs_reserve()/tags_reserve(). */
#define HLR_LLR_INITIAL_CAP 64
static char (*g_hlr_ids)[MAX_ID];      static int g_hlr_count,       g_hlr_cap;
static char (*g_llr_ids)[MAX_ID];
static char (*g_llr_parents)[MAX_ID];  static int g_llr_count,       g_llr_cap;
static char (*g_orphaned)[MAX_ID];     static int g_orphaned_count,  g_orphaned_cap;
static char (*g_uncovered)[MAX_ID];    static int g_uncovered_count, g_uncovered_cap;

static int hlr_reserve(int need)
{
    if (need <= g_hlr_cap) return 1;
    int new_cap = g_hlr_cap ? g_hlr_cap : HLR_LLR_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    char (*tmp)[MAX_ID] = realloc(g_hlr_ids, (size_t)new_cap * sizeof(*g_hlr_ids));
    if (!tmp) return 0;
    g_hlr_ids = tmp;
    g_hlr_cap = new_cap;
    return 1;
}

static int llr_reserve(int need)
{
    if (need <= g_llr_cap) return 1;
    int new_cap = g_llr_cap ? g_llr_cap : HLR_LLR_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    char (*tmp_ids)[MAX_ID] = realloc(g_llr_ids, (size_t)new_cap * sizeof(*g_llr_ids));
    if (!tmp_ids) return 0;
    g_llr_ids = tmp_ids;
    char (*tmp_parents)[MAX_ID] = realloc(g_llr_parents, (size_t)new_cap * sizeof(*g_llr_parents));
    if (!tmp_parents) return 0;
    g_llr_parents = tmp_parents;
    g_llr_cap = new_cap;
    return 1;
}

static int orphaned_reserve(int need)
{
    if (need <= g_orphaned_cap) return 1;
    int new_cap = g_orphaned_cap ? g_orphaned_cap : HLR_LLR_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    char (*tmp)[MAX_ID] = realloc(g_orphaned, (size_t)new_cap * sizeof(*g_orphaned));
    if (!tmp) return 0;
    g_orphaned = tmp;
    g_orphaned_cap = new_cap;
    return 1;
}

static int uncovered_reserve(int need)
{
    if (need <= g_uncovered_cap) return 1;
    int new_cap = g_uncovered_cap ? g_uncovered_cap : HLR_LLR_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    char (*tmp)[MAX_ID] = realloc(g_uncovered, (size_t)new_cap * sizeof(*g_uncovered));
    if (!tmp) return 0;
    g_uncovered = tmp;
    g_uncovered_cap = new_cap;
    return 1;
}

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

/* Load requirements — try .fusa-reqs.json first, fall back to legacy
 * .cfusa-reqs.json. Returns 1 on a complete parse, 0 if the catalog could
 * not be loaded in full (allocation failure) — never truncates silently. */
static int load_reqs(const char *dir)
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
    if (!json) return 1;

    /* §1.2.2: check for duplicate requirement ids and emit ERRORs */
    /* (collected after loading; detected via second pass below) */

    const char *p = strstr(json, "\"requirements\"");
    if (p) p = strchr(p, '[');
    if (!p) { free(json); return 1; }
    p++;

    int ok = 1;
    while (*p && *p != ']') {
        const char *bs = strchr(p, '{'); if (!bs) break;
        const char *be = strchr(bs, '}'); if (!be) break;
        if (!reqs_reserve(g_req_count + 1)) {
            fprintf(stderr,
                    "cfusa trace: out of memory loading %s — only %d "
                    "requirement(s) loaded; results are INCOMPLETE\n",
                    REQS_FILE, g_req_count);
            ok = 0;
            break;
        }
        /* Heap-allocate to the exact object length so requirement objects
         * longer than a fixed stack buffer are no longer silently truncated
         * (which dropped id/title/parent fields past ~1KB). */
        size_t ol = (size_t)(be - bs + 1);
        char *obj = malloc(ol + 1);
        if (!obj) break;
        memcpy(obj, bs, ol);
        obj[ol] = '\0';
        jfield(obj, "id",       g_reqs[g_req_count].id,        MAX_ID);
        jfield(obj, "title",    g_reqs[g_req_count].title,     MAX_TITLE);
        jfield(obj, "standard", g_reqs[g_req_count].standard,  64);
        jfield(obj, "level",    g_reqs[g_req_count].level,     32);
        //cfusa:req REQ-HLR004
        /* x-FuSa spec §1.2.2: the canonical LLR->HLR link key is "parent";
         * accept the legacy "parentId" only as a fallback alias. */
        jfield(obj, "parent", g_reqs[g_req_count].parent_id, MAX_ID);
        if (!g_reqs[g_req_count].parent_id[0])
            jfield(obj, "parentId", g_reqs[g_req_count].parent_id, MAX_ID);
        if (g_reqs[g_req_count].id[0]) g_req_count++;
        free(obj);
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
    return ok;
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
    while (tok) {
        char *t = cfusa_str_trim(tok);
        /* Only accept valid IDs: non-empty, alphanumeric + '-'/'_' */
        int valid = t[0] != '\0';
        for (const char *p = t; *p && valid; p++) {
            unsigned char c = (unsigned char)*p;
            if (!isalnum(c) && c != '-' && c != '_') valid = 0;
        }
        if (valid) {
            if (!tags_reserve(g_tag_count + 1)) {
                g_tag_alloc_failed = 1;
            } else {
                strncpy(g_tags[g_tag_count].req_id, t,       MAX_ID - 1);
                strncpy(g_tags[g_tag_count].file,   relpath, 255);
                g_tags[g_tag_count].line = lineno;
                g_tags[g_tag_count].kind = kind;
                g_tag_count++;
            }
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
    /* issue #180: identifier-boundary + string-literal-aware match —
     * without it, this fired on any text merely containing the substring
     * "REQ:" (e.g. a plain "// SAMPLE_FREQ: 48000" comment, or this very
     * file's own --help string literal mentioning "//cfusa:req REQ-ID"),
     * fabricating bogus requirement tags. */
    if (ctx->legacy && (p = cfusa_find_token_outside_string(line, "REQ:"))) {
        p += 4;
        while (*p == ' ' || *p == '\t') p++;
        char buf[512]; strncpy(buf, p, sizeof(buf) - 1);
        char *e = strpbrk(buf, "*/\n"); if (e) *e = '\0';
        char *tok = strtok(buf, ", \t");
        while (tok) {
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
        /* issue #166: this used to set `any` (and therefore *traced) on
         * ANY tag kind, while the itemized UNTRACED listing a few lines
         * below (in the req-coverage report) filters strictly on
         * KIND_IMPL — the two disagreed on what "traced" means within
         * the same report, so a requirement with only a test tag (no
         * implementation tag) could silently satisfy a 100%
         * traceability gate while simultaneously being listed as
         * UNTRACED directly below it. `has_impl` now matches the
         * UNTRACED listing's semantics exactly. */
        int has_impl = 0, ht = 0, hst = 0;
        for (int j = 0; j < g_tag_count; j++) {
            if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                if (g_tags[j].kind == KIND_IMPL)     has_impl = 1;
                if (g_tags[j].kind == KIND_TEST)     ht  = 1;
                if (g_tags[j].kind == KIND_SEC_TEST) { ht = 1; hst = 1; }
            }
        }
        if (has_impl) (*traced)++;
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

/* issue #125: g_func_covered[] above is file-level (every function in a
 * file inherits one shared "does this file have >=1 //cfusa:req tag
 * anywhere" flag) — that's --func-coverage's original, still-unchanged
 * contract. g_func_strict_covered[] is the new, genuinely per-function
 * metric behind --func-coverage-strict: a function counts as covered
 * only when a //cfusa:req tag sits in the contiguous run of blank/
 * comment lines directly above it, with no other code line in between —
 * matching the convention most call sites already follow by hand. Shipped
 * as a separate opt-in flag rather than changing --func-coverage's
 * existing behavior, since repos gate CI on its current (weaker)
 * semantics and a silent tightening would newly fail them without
 * warning. */
static int g_func_strict_covered[MAX_FUNCS];
static int g_func_strict_covered_count;

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

typedef struct {
    const char *relpath;
    int annotated;         /* file-level flag — --func-coverage (unchanged) */
    int pending_impl_tag;  /* per-function state — --func-coverage-strict (issue #125) */
    int in_block_comment;
} fscan_ctx_t;

static void func_line_cb(const char *path, int lineno, const char *line, void *v)
{
    (void)path; (void)lineno;
    fscan_ctx_t *ctx = v;

    const char *t = line;
    while (*t == ' ' || *t == '\t') t++;

    if (ctx->in_block_comment) {
        if (strstr(t, "*/")) ctx->in_block_comment = 0;
        return; /* whole line is comment content: neither breaks nor sets
                    pending_impl_tag, and can't be a function definition */
    }
    if (strstr(t, "//cfusa:req ")) {
        ctx->pending_impl_tag = 1;
        return;
    }
    if (strncmp(t, "//", 2) == 0) {
        return; /* any other line comment (incl. //cfusa:test) — doesn't
                    break a pending tag, but doesn't set one either */
    }
    if (strncmp(t, "/*", 2) == 0) {
        if (!strstr(t + 2, "*/")) ctx->in_block_comment = 1;
        return;
    }
    if (*t == '\0') {
        return; /* blank line — tolerated between a tag/comment and the
                    function it annotates */
    }

    /* Real code line — matched against the original (untrimmed) `line`
     * to preserve looks_like_funcdef()'s existing column-0 requirement. */
    char name[128];
    if (g_func_count < MAX_FUNCS && looks_like_funcdef(line, name, sizeof(name))) {
        snprintf(g_func_names[g_func_count], 192, "%s:%s", ctx->relpath, name);
        g_func_covered[g_func_count] = ctx->annotated;
        if (ctx->annotated) g_func_covered_count++;
        g_func_strict_covered[g_func_count] = ctx->pending_impl_tag;
        if (ctx->pending_impl_tag) g_func_strict_covered_count++;
        g_func_count++;
    }
    ctx->pending_impl_tag = 0; /* any real code line consumes/breaks the pending tag */
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

    fscan_ctx_t ctx = {relpath, ann, 0, 0};
    cfusa_scan_lines(path, func_line_cb, &ctx);
    return 0;
}

static void do_scan_funcs(const char *root)
{
    g_func_count = g_func_covered_count = g_func_strict_covered_count = 0;
    static const char * const fexts[] = {".c"};
    cfusa_walk_sources(root, fexts, 1, funcfile_cb, NULL);
}

/* ---- HLR/LLR decomposition analysis (REQ-HLR001, REQ-HLR002, REQ-HLR003) ---- */
/* Returns 1 on a complete computation, 0 if a growth failure (OOM)
 * occurred partway through — never silently truncates (issue #167). */
//cfusa:req REQ-HLR001
static int compute_hlr_llr(void)
{
    g_hlr_count = g_llr_count = g_orphaned_count = g_uncovered_count = 0;

    /* Classify requirements by level field (case-insensitive HLR / LLR) */
    for (int i = 0; i < g_req_count; i++) {
        char lvl[33];
        strncpy(lvl, g_reqs[i].level, sizeof(lvl) - 1);
        lvl[sizeof(lvl)-1] = '\0';
        for (char *p = lvl; *p; p++) *p = (char)toupper((unsigned char)*p);

        if (!strcmp(lvl, "HLR")) {
            if (!hlr_reserve(g_hlr_count + 1)) return 0;
            strncpy(g_hlr_ids[g_hlr_count++], g_reqs[i].id, MAX_ID - 1);
        } else if (!strcmp(lvl, "LLR")) {
            if (!llr_reserve(g_llr_count + 1)) return 0;
            strncpy(g_llr_ids[g_llr_count],    g_reqs[i].id,        MAX_ID - 1);
            strncpy(g_llr_parents[g_llr_count], g_reqs[i].parent_id, MAX_ID - 1);
            g_llr_count++;
        }
    }

    /* REQ-HLR002: every LLR must reference an existing HLR */
    for (int i = 0; i < g_llr_count; i++) {
        int valid = 0;
        if (g_llr_parents[i][0]) {
            for (int j = 0; j < g_hlr_count; j++) {
                if (!strcmp(g_llr_parents[i], g_hlr_ids[j])) { valid = 1; break; }
            }
        }
        if (!valid) {
            if (!orphaned_reserve(g_orphaned_count + 1)) return 0;
            strncpy(g_orphaned[g_orphaned_count++], g_llr_ids[i], MAX_ID - 1);
        }
    }

    /* REQ-HLR003: every HLR must have at least one LLR child */
    for (int j = 0; j < g_hlr_count; j++) {
        int covered = 0;
        for (int i = 0; i < g_llr_count; i++) {
            if (!strcmp(g_llr_parents[i], g_hlr_ids[j])) { covered = 1; break; }
        }
        if (!covered) {
            if (!uncovered_reserve(g_uncovered_count + 1)) return 0;
            strncpy(g_uncovered[g_uncovered_count++], g_hlr_ids[j], MAX_ID - 1);
        }
    }
    return 1;
}

int cmd_trace(int argc, char **argv)
{
    const char *dir  = ".";
    const char *out_path = NULL;
    const char *fmt_s    = "text";
    int show_gaps    = 0;
    int req_coverage = 0;
    int sec_tested   = 0;
    int func_coverage = 0; /* REQ-FUNCCOV001 */
    int func_coverage_strict = 0; /* REQ-FUNCCOV002, issue #125 */
    int legacy       = 1;
    int strict_hlr_llr = 0; /* REQ-HLR001 */

    static const struct option lo[] = {
        {"dir",            required_argument, NULL, 'd'},
        {"output",         required_argument, NULL, 'o'},
        {"format",         required_argument, NULL, 'f'},
        {"gaps",           no_argument,       NULL, 'g'},
        {"req-coverage",   required_argument, NULL, 'r'},
        {"sec-tested",     required_argument, NULL, 's'},
        {"func-coverage",  required_argument, NULL, 'F'}, /* REQ-FUNCCOV001 */
        {"func-coverage-strict", required_argument, NULL, 'K'}, /* REQ-FUNCCOV002 */
        {"no-legacy",      no_argument,       NULL, 'L'},
        {"strict-hlr-llr", no_argument,       NULL, 'H'}, /* REQ-HLR001 */
        {"help",           no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:o:f:gr:s:F:K:LHh", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir          = optarg;        break;
        case 'o': out_path     = optarg;        break;
        case 'f': fmt_s        = optarg;        break;
        case 'g': show_gaps    = 1;             break;
        case 'r': req_coverage = atoi(optarg);  break;
        case 's': sec_tested   = atoi(optarg);  break;
        case 'F': func_coverage = atoi(optarg); break; /* REQ-FUNCCOV001 */
        case 'K': func_coverage_strict = atoi(optarg); break; /* REQ-FUNCCOV002 */
        case 'L': legacy       = 0;             break;
        case 'H': strict_hlr_llr = 1;          break; /* REQ-HLR001 */
        case 'h':
            printf("Usage: cfusa trace [--dir <path>] [--format text|json|md]\n"
                   "                   [--output <file>] [--gaps]\n"
                   "                   [--req-coverage <N%%>] [--sec-tested <N%%>]\n"
                   "                   [--func-coverage <N%%>] [--func-coverage-strict <N%%>]\n"
                   "                   [--strict-hlr-llr]\n\n"
                   "Builds a requirements traceability matrix from .cfusa-reqs.json\n"
                   "and source annotations:\n"
                   "  //cfusa:req REQ-ID       — implementation reference\n"
                   "  //cfusa:test REQ-ID      — test reference\n"
                   "  //cfusa:sec-test REQ-ID  — security-test reference\n\n"
                   "  --gaps             list requirements with no //cfusa:test tag\n"
                   "  --req-coverage N   exit 1 if <N%% of requirements have impl traces\n"
                   "  --sec-tested N     exit 1 if <N%% of requirements have test traces\n"
                   "  --func-coverage N  exit 1 if <N%% of public functions are in a file\n"
                   "                     carrying >=1 //cfusa:req tag (x-FuSa spec 1.4.1).\n"
                   "                     File-level: any function in a tagged file counts,\n"
                   "                     even if untagged itself — kept for backward\n"
                   "                     compatibility with existing CI gates (issue #125).\n"
                   "  --func-coverage-strict N  exit 1 if <N%% of public functions each\n"
                   "                     individually carry a //cfusa:req tag directly\n"
                   "                     above their own definition. Stricter, genuinely\n"
                   "                     per-function measurement — prefer this for new\n"
                   "                     CI gates.\n"
                   "  --strict-hlr-llr   exit 1 if any HLR/LLR decomposition violations\n");
            return 0;
        default: return 2;
        }
    }

    g_req_count = g_tag_count = 0;
    g_tag_alloc_failed = 0;
    g_dir_abs[0] = '\0';
    g_hlr_count = g_llr_count = g_orphaned_count = g_uncovered_count = 0;
    {
        char *tmp = realpath(dir, NULL);
        if (tmp) { strncpy(g_dir_abs, tmp, sizeof(g_dir_abs) - 1); free(tmp); }
        else strncpy(g_dir_abs, dir, sizeof(g_dir_abs) - 1);
    }
    if (!load_reqs(dir)) {
        fprintf(stderr,
                "cfusa trace: ERROR: requirement catalog failed to load in "
                "full (out of memory) — refusing to report a coverage "
                "result that could be mistaken for complete\n");
        return 1;
    }

    scan_ctx_t sctx = {legacy};
    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, trace_file_cb, &sctx);
    if (g_tag_alloc_failed) {
        fprintf(stderr,
                "cfusa trace: ERROR: annotation scan failed to complete in "
                "full (out of memory) — refusing to report a coverage "
                "result that could be mistaken for complete\n");
        return 1;
    }

    //cfusa:req REQ-TESTDANGLE001
    /* §1.4.1 item 3 (REQ-TESTDANGLE001): a //cfusa:test or //cfusa:sec-test
     * tag whose ID is not registered in .fusa-reqs.json is a dangling
     * reference — treat it the same as a malformed annotation (a WARNING,
     * never silently accepted). Only checked when a requirements registry
     * was actually loaded: with no registry at all there is nothing for a
     * reference to dangle against. */
    if (g_req_count > 0) {
        for (int i = 0; i < g_tag_count; i++) {
            if (g_tags[i].kind != KIND_TEST && g_tags[i].kind != KIND_SEC_TEST)
                continue;
            int found = 0;
            for (int j = 0; j < g_req_count && !found; j++)
                if (!strcmp(g_tags[i].req_id, g_reqs[j].id)) found = 1;
            if (!found)
                fprintf(stderr,
                        "cfusa trace: WARNING: dangling test reference '%s' at %s:%d "
                        "(no such requirement in %s)\n",
                        g_tags[i].req_id, g_tags[i].file, g_tags[i].line, REQS_FILE);
        }
    }

    if (!compute_hlr_llr()) { /* REQ-HLR001 */
        fprintf(stderr, "cfusa trace: aborting — HLR/LLR decomposition analysis "
                "failed to complete in full (out of memory)\n");
        return 3;
    }

    int total = g_req_count;
    int traced, tested, sec_tested_count;
    compute_coverage(&traced, &tested, &sec_tested_count);

    /* REQ-HLR001: --strict-hlr-llr gate */
    if (strict_hlr_llr) {
        if (g_hlr_count == 0 && g_llr_count == 0) {
            printf("HLR/LLR: no hierarchical requirements defined"
                   " (no level HLR or LLR in requirements)\n");
            return 0;
        }
        printf("HLR/LLR Decomposition\n");
        printf("HLRs: %d  LLRs: %d  Orphaned: %d  Uncovered: %d\n",
               g_hlr_count, g_llr_count, g_orphaned_count, g_uncovered_count);
        for (int i = 0; i < g_orphaned_count; i++)
            printf("  ORPHANED LLR  %s  (parentId missing or invalid)\n",
                   g_orphaned[i]);
        for (int i = 0; i < g_uncovered_count; i++)
            printf("  UNCOVERED HLR %s  (no LLR children)\n", g_uncovered[i]);
        if (g_orphaned_count > 0 || g_uncovered_count > 0) {
            fprintf(stderr,
                    "cfusa trace: --strict-hlr-llr gate failed: "
                    "%d orphaned LLR(s), %d uncovered HLR(s)\n",
                    g_orphaned_count, g_uncovered_count);
            return 1;
        }
        return 0;
    }

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
        /* issue #147: this used to read `tested` (set for ANY test tag,
         * including a plain //cfusa:test with no //cfusa:sec-test) instead
         * of `sec_tested_count` (set only for //cfusa:sec-test) — so the
         * --sec-tested gate silently reduced to the ordinary test-coverage
         * gate and never actually checked for security-test coverage. */
        int pct = sec_tested_count * 100 / total;
        printf("sec-tested: %d%% (%d/%d requirements have security-test traces)\n",
               pct, sec_tested_count, total);
        if (pct < sec_tested) {
            fprintf(stderr,
                    "cfusa trace: sec-tested gate failed: %d%% < required %d%%\n",
                    pct, sec_tested);
            return 1;
        }
        return 0;
    }

    //cfusa:req REQ-FUNCCOV001
    /* --- func-coverage gate (REQ-FUNCCOV001, x-FuSa spec §1.4.1 / §5) ---
     * Percentage of non-static public functions (in cmd/cfusa/*.c and
     * src/*.c — test files are excluded by do_scan_funcs()) that live in a
     * file carrying at least one //cfusa:req tag anywhere (this repo's
     * file-level tagging convention: "covered" = the containing file is
     * traced, not that the specific function is individually tagged).
     * Mirrors --req-coverage: N=0 disables the gate; exit 1 when below N. */
    if (func_coverage > 0) {
        printf("Function Coverage Report\n\n");
        do_scan_funcs(dir);
        int m2na = (g_func_count == 0);
        int func_pct = m2na ? 0 : g_func_covered_count * 100 / g_func_count;
        if (m2na) {
            printf("Function annotation density: N/A (no exported functions found)\n");
            return 0;
        }
        printf("Function annotation density: %d%% (%d/%d functions in annotated files)\n",
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
        if (func_pct < func_coverage) {
            fprintf(stderr,
                    "cfusa trace: func-coverage gate failed: %d%% < required %d%%\n",
                    func_pct, func_coverage);
            return 1;
        }
        return 0;
    }

    //cfusa:req REQ-FUNCCOV002
    /* --- func-coverage-strict gate (REQ-FUNCCOV002, issue #125) ---
     * Percentage of functions that EACH individually carry a //cfusa:req
     * tag directly above their own definition (only blank/comment lines
     * may sit between the tag and the function — see func_line_cb()'s
     * pending_impl_tag tracking). Unlike --func-coverage, a function does
     * NOT inherit coverage merely because some other function elsewhere
     * in the same file is tagged — this is the genuinely per-function
     * measurement the "func-coverage" name implies. Shipped as a
     * separate, opt-in flag so existing --func-coverage CI gates keep
     * their current (weaker but unchanged) contract; new gates should
     * prefer this one. */
    if (func_coverage_strict > 0) {
        printf("Function Coverage Report (strict, per-function)\n\n");
        do_scan_funcs(dir);
        int m2na = (g_func_count == 0);
        int strict_pct = m2na ? 0 : g_func_strict_covered_count * 100 / g_func_count;
        if (m2na) {
            printf("Function annotation density: N/A (no exported functions found)\n");
            return 0;
        }
        printf("Function annotation density: %d%% (%d/%d functions individually tagged)\n",
               strict_pct, g_func_strict_covered_count, g_func_count);
        int shown = 0;
        for (int i = 0; i < g_func_count; i++) {
            if (g_func_strict_covered[i]) continue;
            if (shown >= 20) {
                int rem = 0;
                for (int k = i; k < g_func_count; k++) if (!g_func_strict_covered[k]) rem++;
                printf("  ... and %d more\n", rem);
                break;
            }
            printf("  UNANNOTATED  %s\n", g_func_names[i]);
            shown++;
        }
        if (strict_pct < func_coverage_strict) {
            fprintf(stderr,
                    "cfusa trace: func-coverage-strict gate failed: %d%% < required %d%%\n",
                    strict_pct, func_coverage_strict);
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

        /* requirements[] — include parentId for LLR entries (REQ-HLR001) */
        fprintf(out, "  \"requirements\": [\n");
        for (int i = 0; i < g_req_count; i++) {
            char esc_id[MAX_ID*2], esc_title[MAX_TITLE*2],
                 esc_std[128], esc_lvl[64], esc_pid[MAX_ID*2];
            cfusa_str_escape_json(g_reqs[i].id,        esc_id,    sizeof(esc_id));
            cfusa_str_escape_json(g_reqs[i].title,     esc_title, sizeof(esc_title));
            cfusa_str_escape_json(g_reqs[i].standard,  esc_std,   sizeof(esc_std));
            cfusa_str_escape_json(g_reqs[i].level,     esc_lvl,   sizeof(esc_lvl));
            cfusa_str_escape_json(g_reqs[i].parent_id, esc_pid,   sizeof(esc_pid));
            fprintf(out, "    {\"id\": \"%s\", \"title\": \"%s\"",
                    esc_id, esc_title);
            if (esc_std[0])
                fprintf(out, ", \"standard\": \"%s\"", esc_std);
            if (esc_lvl[0])
                fprintf(out, ", \"level\": \"%s\"",    esc_lvl);
            if (esc_pid[0]) {
                //cfusa:req REQ-HLR004
                fprintf(out, ", \"parentId\": \"%s\"", esc_pid);
            }
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
            "  }",
            total, traced, tested, sec_tested_count);

        /* hlrllrSummary{} — only when HLR/LLR levels are in use */
        //cfusa:req REQ-HLR004
        if (g_hlr_count > 0 || g_llr_count > 0) {
            fprintf(out,
                ",\n"
                "  \"hlrllrSummary\": {\n"
                "    \"hlrCount\": %d,\n"
                "    \"llrCount\": %d,\n"
                "    \"orphanedCount\": %d,\n"
                "    \"uncoveredCount\": %d",
                g_hlr_count, g_llr_count,
                g_orphaned_count, g_uncovered_count);
            if (g_orphaned_count > 0) {
                fprintf(out, ",\n    \"orphaned\": [");
                for (int i = 0; i < g_orphaned_count; i++) {
                    char esc[MAX_ID*2];
                    cfusa_str_escape_json(g_orphaned[i], esc, sizeof(esc));
                    fprintf(out, "\"%s\"%s", esc,
                            (i < g_orphaned_count - 1) ? ", " : "");
                }
                fprintf(out, "]");
            }
            if (g_uncovered_count > 0) {
                fprintf(out, ",\n    \"uncovered\": [");
                for (int i = 0; i < g_uncovered_count; i++) {
                    char esc[MAX_ID*2];
                    cfusa_str_escape_json(g_uncovered[i], esc, sizeof(esc));
                    fprintf(out, "\"%s\"%s", esc,
                            (i < g_uncovered_count - 1) ? ", " : "");
                }
                fprintf(out, "]");
            }
            fprintf(out, "\n  }");
        }
        fprintf(out, "\n}\n");
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
        if (g_hlr_count > 0 || g_llr_count > 0)
            fprintf(out,
                    "\n| HLRs | %d |\n| LLRs | %d |\n"
                    "| Orphaned LLRs | %d |\n| Uncovered HLRs | %d |\n",
                    g_hlr_count, g_llr_count,
                    g_orphaned_count, g_uncovered_count);
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
            if (g_hlr_count > 0 || g_llr_count > 0)
                fprintf(out, "HLR/LLR: %d HLRs  %d LLRs  %d orphaned  %d uncovered\n",
                        g_hlr_count, g_llr_count, g_orphaned_count, g_uncovered_count);
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
