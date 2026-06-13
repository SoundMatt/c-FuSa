/*
 * cmd_comp.c — `cfusa comp`: McCabe V(G) cyclomatic complexity report.
 *
 * Walks .c source files, computes V(G) per function, and produces a
 * compliance report (text / json / md).  Exits 1 if any function exceeds
 * the threshold; exits 0 when clean.  Per DO-178C §6.3.4 thresholds:
 *   DAL-A = 4  DAL-B = 10  DAL-C = 15  DAL-D = 20  (default = DAL-B = 10)
 */
//cfusa:req REQ-COMP001
//cfusa:req REQ-COMP002
//cfusa:req REQ-COMP003
//cfusa:req REQ-COMP004
//cfusa:req REQ-COMP005

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include "cfusa/utils.h"
#include "cfusa/version.h"

#define COMP_REPORT_FILE "comp-report.json"

/* DO-178C §6.3.4 / ISO 26262 thresholds per assurance level */
#define THRESHOLD_DAL_A  4
#define THRESHOLD_DAL_B  10
#define THRESHOLD_DAL_C  15
#define THRESHOLD_DAL_D  20
#define THRESHOLD_ASIL_D 4
#define THRESHOLD_ASIL_C 10
#define THRESHOLD_ASIL_B 15
#define THRESHOLD_ASIL_A 20

typedef struct {
    char file[512];
    int  line;
    char name[128];
    int  complexity;
} fn_info_t;

typedef struct {
    fn_info_t *fns;
    int        count;
    int        cap;
    int        threshold;
} comp_ctx_t;

/* Count decision points on one (comment-stripped) line of C. */
static int comp_count_decisions(const char *line)
{
    int n = 0;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return 0;
    while (*p) {
        if      (strncmp(p, "if(",   3)==0 || strncmp(p, "if (",  4)==0)  { n++; p+=2; }
        else if (strncmp(p, "else if", 7)==0)                              { n++; p+=7; }
        else if (strncmp(p, "for(",  4)==0 || strncmp(p, "for (", 5)==0)  { n++; p+=3; }
        else if (strncmp(p, "while(",6)==0 || strncmp(p, "while (",7)==0) { n++; p+=5; }
        else if (strncmp(p, "case ", 5)==0)                                { n++; p+=4; }
        else if (*p == '?' && *(p+1) != '?')                               { n++; p++;  }
        else if (*p == '&' && *(p+1) == '&')                               { n++; p+=2; }
        else if (*p == '|' && *(p+1) == '|')                               { n++; p+=2; }
        else p++;
    }
    return n;
}

static void comp_push(comp_ctx_t *ctx, const char *file, int line,
                      const char *name, int complexity)
{
    if (ctx->count >= ctx->cap) {
        ctx->cap = ctx->cap ? ctx->cap * 2 : 64;
        ctx->fns = realloc(ctx->fns, (size_t)ctx->cap * sizeof(fn_info_t));
    }
    fn_info_t *f = &ctx->fns[ctx->count++];
    strncpy(f->file, file, sizeof(f->file)-1); f->file[sizeof(f->file)-1] = '\0';
    f->line = line;
    strncpy(f->name, name, sizeof(f->name)-1); f->name[sizeof(f->name)-1] = '\0';
    f->complexity = complexity;
}

static int comp_collect_file(const char *path, void *vctx)
{
    comp_ctx_t *ctx = vctx;
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[4096];
    int  lineno = 0, fn_start = 0, brace_depth = 0;
    int  in_fn  = 0, complexity = 0;
    char fn_name[128] = "";

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char trimmed[4096];
        strncpy(trimmed, line, sizeof(trimmed)-1); trimmed[sizeof(trimmed)-1] = '\0';
        cfusa_str_trim(trimmed);

        if (!in_fn && brace_depth == 0
            && strstr(trimmed, "(") && strstr(trimmed, ")")
            && trimmed[0] != '#' && trimmed[0] != '/'
            && trimmed[0] != '*' && trimmed[0] != ' ') {
            char *paren = strchr(trimmed, '(');
            if (paren) {
                char before[128] = "";
                size_t blen = (size_t)(paren - trimmed);
                if (blen < 128) {
                    strncpy(before, trimmed, blen); before[blen] = '\0';
                    char *sp = strrchr(before, ' ');
                    strncpy(fn_name, sp ? sp+1 : before, sizeof(fn_name)-1);
                    while (fn_name[0] == '*') memmove(fn_name, fn_name+1, strlen(fn_name));
                }
                in_fn = 1; fn_start = lineno; complexity = 1;
            }
        }

        if (in_fn) complexity += comp_count_decisions(line);

        for (const char *ch = line; *ch; ch++) {
            if (*ch == '{') brace_depth++;
            else if (*ch == '}') {
                brace_depth--;
                if (brace_depth == 0 && in_fn) {
                    comp_push(ctx, path, fn_start, fn_name, complexity);
                    in_fn = 0; complexity = 0; fn_start = 0; fn_name[0] = '\0';
                }
            }
        }
    }
    fclose(fp);
    return 0;
}

static int comp_cmp_desc(const void *a, const void *b)
{
    return ((const fn_info_t *)b)->complexity - ((const fn_info_t *)a)->complexity;
}

static void iso8601_now(char *buf, size_t n)
{
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", tm);
}

/* ── Output helpers ─────────────────────────────────────────────────────── */

static void print_text(FILE *out, const fn_info_t *fns, int n,
                       int threshold, int violations, int max_vg)
{
    fprintf(out, "Cyclomatic Complexity Report  (threshold: %d)\n", threshold);
    fprintf(out, "%-68s %5s  %s\n", "Function", "V(G)", "Status");
    fprintf(out, "%s\n", "--------------------------------------------------------------------"
                         "--------");
    for (int i = 0; i < n; i++) {
        char label[72];
        snprintf(label, sizeof(label), "%s:%s", fns[i].file, fns[i].name);
        if (strlen(label) > 68) {
            /* truncate from the left */
            const char *trunc = label + strlen(label) - 67;
            snprintf(label, sizeof(label), "~%s", trunc);
        }
        fprintf(out, "%-68s %5d  %s\n", label, fns[i].complexity,
                fns[i].complexity > threshold ? "VIOLATION" : "ok");
    }
    fprintf(out, "%s\n", "--------------------------------------------------------------------"
                         "--------");
    fprintf(out, "Functions: %d  Violations: %d  Max V(G): %d\n", n, violations, max_vg);
}

static void print_md(FILE *out, const fn_info_t *fns, int n,
                     int threshold, int violations, int max_vg)
{
    fprintf(out, "# Cyclomatic Complexity Report\n\n");
    fprintf(out, "Threshold: %d (DO-178C §6.3.4)\n\n", threshold);
    fprintf(out, "| Function | V(G) | Status |\n");
    fprintf(out, "|----------|------|--------|\n");
    for (int i = 0; i < n; i++)
        fprintf(out, "| `%s:%s` | %d | %s |\n",
                fns[i].file, fns[i].name, fns[i].complexity,
                fns[i].complexity > threshold ? "**VIOLATION**" : "ok");
    fprintf(out, "\n**Functions:** %d  **Violations:** %d  **Max V(G):** %d\n",
            n, violations, max_vg);
}

static void print_json(FILE *out, const fn_info_t *fns, int n,
                       int threshold, int violations, int max_vg,
                       const char *root)
{
    char ts[32]; iso8601_now(ts, sizeof(ts));
    fprintf(out, "{\n");
    fprintf(out, "  \"schemaVersion\": \"%s\",\n", CFUSA_SPEC_VERSION);
    fprintf(out, "  \"kind\": \"comp-report\",\n");
    fprintf(out, "  \"tool\": \"cfusa\",\n");
    fprintf(out, "  \"toolVersion\": \"%s\",\n", CFUSA_VERSION_STRING);
    fprintf(out, "  \"language\": \"c\",\n");
    fprintf(out, "  \"generatedAt\": \"%s\",\n", ts);
    fprintf(out, "  \"projectRoot\": \"%s\",\n", root);
    fprintf(out, "  \"threshold\": %d,\n", threshold);
    fprintf(out, "  \"functions\": [\n");
    for (int i = 0; i < n; i++) {
        fprintf(out, "    { \"file\": \"%s\", \"line\": %d, \"function\": \"%s\","
                     " \"complexity\": %d, \"exceedsThreshold\": %s }%s\n",
                fns[i].file, fns[i].line, fns[i].name, fns[i].complexity,
                fns[i].complexity > threshold ? "true" : "false",
                i < n-1 ? "," : "");
    }
    fprintf(out, "  ],\n");
    fprintf(out, "  \"summary\": {\n");
    fprintf(out, "    \"totalFunctions\": %d,\n", n);
    fprintf(out, "    \"violations\": %d,\n", violations);
    fprintf(out, "    \"maxComplexity\": %d\n", max_vg);
    fprintf(out, "  }\n}\n");
}

/* ── Entry point ────────────────────────────────────────────────────────── */

int cmd_comp(int argc, char **argv)
{
    const char *dir       = ".";
    const char *fmt_s     = "text";
    const char *output    = NULL;
    int         threshold = THRESHOLD_DAL_B;
    int         verbose   = 0;
    optind = 1;

    static const struct option long_opts[] = {
        {"dir",       required_argument, NULL, 'd'},
        {"format",    required_argument, NULL, 'f'},
        {"output",    required_argument, NULL, 'o'},
        {"threshold", required_argument, NULL, 't'},
        {"dal-a",     no_argument,       NULL, 'A'},
        {"dal-b",     no_argument,       NULL, 'B'},
        {"dal-c",     no_argument,       NULL, 'C'},
        {"dal-d",     no_argument,       NULL, 'D'},
        {"asil-d",    no_argument,       NULL, 'A'},
        {"asil-c",    no_argument,       NULL, 'B'},
        {"asil-b",    no_argument,       NULL, 'C'},
        {"asil-a",    no_argument,       NULL, 'D'},
        {"verbose",   no_argument,       NULL, 'v'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "d:f:o:t:ABCDvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd': dir       = optarg; break;
        case 'f': fmt_s     = optarg; break;
        case 'o': output    = optarg; break;
        case 't': threshold = atoi(optarg); break;
        case 'A': threshold = THRESHOLD_DAL_A; break;
        case 'B': threshold = THRESHOLD_DAL_B; break;
        case 'C': threshold = THRESHOLD_DAL_C; break;
        case 'D': threshold = THRESHOLD_DAL_D; break;
        case 'v': verbose   = 1; break;
        case 'h':
            printf("Usage: cfusa comp [options]\n\n");
            printf("Cyclomatic complexity (McCabe V(G)) report per DO-178C §6.3.4.\n\n");
            printf("Options:\n");
            printf("  -d, --dir <path>        Source root (default: .)\n");
            printf("  -f, --format <fmt>      text|json|md (default: text)\n");
            printf("  -o, --output <file>     Write report to file\n");
            printf("  -t, --threshold <n>     Custom V(G) threshold\n");
            printf("      --dal-a             Threshold 4  (DO-178C DAL-A)\n");
            printf("      --dal-b             Threshold 10 (DO-178C DAL-B, default)\n");
            printf("      --dal-c             Threshold 15 (DO-178C DAL-C)\n");
            printf("      --dal-d             Threshold 20 (DO-178C DAL-D)\n");
            printf("      --asil-d/c/b/a      Aliases for dal-a/b/c/d respectively\n");
            printf("  -v, --verbose           Show all functions (default: violations only in text)\n");
            printf("  -h, --help              Show this help\n\n");
            printf("Exit codes: 0 = no violations, 1 = violations found, 2 = usage error\n");
            return 0;
        default:
            fprintf(stderr, "cfusa comp: unknown option\n");
            return 2;
        }
    }

    /* Collect all functions */
    comp_ctx_t ctx = {NULL, 0, 0, threshold};
    static const char * const exts[] = {".c"};
    cfusa_walk_sources(dir, exts, 1, comp_collect_file, &ctx);

    if (ctx.count > 0)
        qsort(ctx.fns, (size_t)ctx.count, sizeof(fn_info_t), comp_cmp_desc);

    int violations = 0, max_vg = 0;
    for (int i = 0; i < ctx.count; i++) {
        if (ctx.fns[i].complexity > threshold) violations++;
        if (ctx.fns[i].complexity > max_vg)    max_vg = ctx.fns[i].complexity;
    }

    /* For text/md with --verbose=false, filter to violations only */
    fn_info_t *show     = ctx.fns;
    int        show_n   = ctx.count;
    fn_info_t *filtered = NULL;

    if (!verbose && strcmp(fmt_s, "json") != 0) {
        filtered = malloc((size_t)violations * sizeof(fn_info_t));
        int k = 0;
        for (int i = 0; i < ctx.count; i++)
            if (ctx.fns[i].complexity > threshold)
                filtered[k++] = ctx.fns[i];
        show   = filtered;
        show_n = violations;
    }

    /* Write report */
    FILE *out = stdout;
    if (output) {
        out = fopen(output, "w");
        if (!out) { perror(output); free(ctx.fns); free(filtered); return 1; }
    }

    if (strcmp(fmt_s, "json") == 0)
        print_json(out, show, show_n, threshold, violations, max_vg, dir);
    else if (strcmp(fmt_s, "md") == 0)
        print_md(out, show, show_n, threshold, violations, max_vg);
    else if (strcmp(fmt_s, "text") == 0)
        print_text(out, show, show_n, threshold, violations, max_vg);
    else {
        if (output) fclose(out);
        free(filtered); free(ctx.fns);
        fprintf(stderr, "cfusa comp: unknown format '%s' (text, json, or md)\n", fmt_s);
        return 2;
    }

    if (output)
        fclose(out);

    free(filtered);
    free(ctx.fns);
    return violations > 0 ? 1 : 0;
}
