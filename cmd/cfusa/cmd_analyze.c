#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

typedef struct { cfusa_report_t *rpt; } a_ctx_t;

/* Written as a numeric constant rather than the char literal '\\' to
 * avoid a known limitation in this file's own recursion scanner
 * (CFUSA-L004's file-wide brace tracker doesn't count consecutive
 * backslashes before a closing quote/apostrophe, so a '\\' literal can
 * desynchronize its brace count and misattribute later code to whichever
 * function it was last tracking). Same value, spelled to avoid tripping
 * an unrelated tool limitation, not a behavior change. */
#define A006_BACKSLASH ((char)0x5C)

//cfusa:req REQ-ANA001
/* A001 — dangerous string functions (potential buffer overflow) */
static const char * const dangerous_str_fns[] = {
    "strcpy(","strcat(","sprintf(","gets(","scanf(",
    "vsprintf(","wcscpy(","wcscat(",
    NULL
};

static void a001_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    for(int i=0; dangerous_str_fns[i]; i++) {
        const char *fp = strstr(line, dangerous_str_fns[i]);
        if (!fp) continue;
        /* word-boundary: skip substrings (e.g. "gets(" inside "fgets(") */
        if (fp > line && (*(fp-1)=='_' || (*(fp-1)>='a'&&*(fp-1)<='z')
                          || (*(fp-1)>='A'&&*(fp-1)<='Z')
                          || (*(fp-1)>='0'&&*(fp-1)<='9'))) continue;
        if (!cfusa_match_outside_string(line, dangerous_str_fns[i])) continue;
        cfusa_report_add(ctx->rpt,
            "CFUSA-A001", CFUSA_CATEGORY_ANALYZE, SEV_WARNING,
            path, lineno,
            "use of '%.*s' — unbounded string operation; "
            "use strlcpy/strlcat/snprintf with explicit bounds",
            (int)(strlen(dangerous_str_fns[i])-1), dangerous_str_fns[i]);
        return;
    }
}

static int a001_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a001_line, v); return 0;
}

static int rule_a001(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const dexts[]={".c"};
    a_ctx_t ctx={rpt};
    cfusa_walk_sources(dir, dexts, 1, a001_file, &ctx);
    return 0;
}

//cfusa:req REQ-ANA002
/* A002 — unchecked malloc return value */
static void a002_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Detect: statement starting with malloc/calloc/realloc with no if-check context */
    if((strstr(line,"= malloc(") || strstr(line,"= calloc(") || strstr(line,"= realloc("))
       && !strstr(line,"if ") && !strstr(line,"assert(")) {
        /* Check next-line context is hard at this level; flag as INFO */
        cfusa_report_add(ctx->rpt,
            "CFUSA-A002", CFUSA_CATEGORY_ANALYZE, SEV_WARNING,
            path, lineno,
            "allocation result may be unchecked — verify NULL return is handled "
            "(CERT-C MEM32-C)");
    }
}

static int a002_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a002_line, v); return 0;
}

static int rule_a002(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c"};
    a_ctx_t ctx={rpt};
    cfusa_walk_sources(dir, exts, 1, a002_file, &ctx);
    return 0;
}

/* A003 — signed/unsigned comparison against sizeof(...) (CERT-C INT02-C).
 *
 * Precision fix (issue #126): the original check was purely syntactic —
 * any "<op> sizeof" substring fired, with no notion of the left operand's
 * actual type. sizeof(...) itself returns size_t (unsigned), so comparing
 * it against another already-unsigned value (e.g. `size_t len = ...; if
 * (len < sizeof(buf))`) is exactly the code CERT INT02-C wants, not a
 * violation of it — but a same-file sample measured this as the dominant
 * false-positive shape (near-100% FP rate).
 *
 * Fix: a first pass over the file (a003_collect_line) records every
 * locally-visible size_t/unsigned*-typed name it can see via a simple
 * "<type keyword> <identifier>" scan (declarations and function
 * parameters alike — this also incidentally covers struct members, since
 * a struct's own field declarations match the same pattern). The second
 * pass then only flags a comparison whose left operand is a *simple*
 * identifier (walked back from the operator) that ISN'T in that set.
 *
 * This is a heuristic, not real type resolution — consistent with this
 * tool's line-based-scan precision ceiling elsewhere in the codebase. It
 * won't catch a real violation whose signed operand is a complex
 * expression (`arr[i] < sizeof(buf)`) or declared in a header this file
 * doesn't itself contain — trading recall for precision, which is the
 * right direction for a rule issue #126 measured at near-100% noise. */
#define A003_MAX_NAMES 256
#define A003_NAME_LEN   64

typedef struct {
    cfusa_report_t *rpt;
    char names[A003_MAX_NAMES][A003_NAME_LEN];
    int count;
} a003_ctx_t;

static const char * const a003_unsigned_types[] = {
    "unsigned long long", "unsigned long", "unsigned short", "unsigned int", "unsigned char",
    "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uintptr_t", "uintmax_t",
    "unsigned",
    NULL
};

static int a003_is_known_unsigned(a003_ctx_t *ctx, const char *id, size_t len)
{
    if (len == 0 || len >= A003_NAME_LEN) return 0;
    for (int i = 0; i < ctx->count; i++)
        if (strncmp(ctx->names[i], id, len) == 0 && ctx->names[i][len] == '\0')
            return 1;
    return 0;
}

//cfusa:req REQ-ANA003
/* Pass 1: scan the whole file for "<size_t/unsigned-family keyword>
 * <identifier>" occurrences and remember each identifier as known-
 * unsigned. Intentionally not scoped to declarations only — matching
 * inside a struct body, a function signature, or a local declaration all
 * use the same textual shape, and this is a best-effort heuristic, not a
 * real parser. */
static void a003_collect_line(const char *path, int lineno, const char *line, void *vctx)
{
    (void)path; (void)lineno;
    a003_ctx_t *ctx = vctx;
    const char *t = line;
    while (*t == ' ' || *t == '\t') t++;
    if (*t == '/' || *t == '*') return; /* skip whole-line comments */

    for (const char *p = line; *p; p++) {
        for (int i = 0; a003_unsigned_types[i]; i++) {
            size_t tlen = strlen(a003_unsigned_types[i]);
            if (strncmp(p, a003_unsigned_types[i], tlen) != 0) continue;
            /* identifier-boundary before and after the keyword — not a
             * substring of a longer identifier either side */
            if (p != line && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) continue;
            char after = p[tlen];
            if (isalnum((unsigned char)after) || after == '_') continue;

            const char *q = p + tlen;
            while (*q == ' ' || *q == '\t' || *q == '*') q++;
            const char *id_start = q;
            while (isalnum((unsigned char)*q) || *q == '_') q++;
            size_t idlen = (size_t)(q - id_start);
            if (idlen > 0 && idlen < A003_NAME_LEN && ctx->count < A003_MAX_NAMES) {
                memcpy(ctx->names[ctx->count], id_start, idlen);
                ctx->names[ctx->count][idlen] = '\0';
                ctx->count++;
            }
            p = q - 1; /* resume scanning after the captured identifier */
            break;
        }
    }
}

/* Extracts the identifier ending immediately before `at` (skipping any
 * whitespace directly before it) — e.g. for "  len < sizeof(buf)" with
 * `at` pointing at '<', returns "len". Returns length 0 when the token
 * immediately before `at` isn't a simple identifier (a closing paren/
 * bracket from a complex expression, or start of line). */
static size_t a003_operand_before(const char *line_start, const char *at, const char **id_out)
{
    const char *p = at;
    while (p > line_start && (p[-1] == ' ' || p[-1] == '\t')) p--;
    const char *end = p;
    while (p > line_start && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) p--;
    *id_out = p;
    return (size_t)(end - p);
}

/* Pass 2: the actual A003 check, now consulting pass 1's known-unsigned
 * name set before flagging. */
static void a003_line(const char *path,int lineno,const char *line,void *vctx)
{
    a003_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;

    static const char * const ops[] = {"<=", ">=", "==", "!=", "<", ">", NULL};
    for (int oi = 0; ops[oi]; oi++) {
        char pat[16];
        snprintf(pat, sizeof(pat), "%s sizeof", ops[oi]);
        const char *m = strstr(line, pat);
        if (!m) continue;
        if (strstr(line,"(size_t)") || strstr(line,"(int)sizeof")) return;

        const char *id;
        size_t idlen = a003_operand_before(line, m, &id);
        /* No simple identifier immediately before the operator (a
         * complex expression, or another sizeof(...)) — don't guess. */
        if (idlen == 0) return;
        if (a003_is_known_unsigned(ctx, id, idlen)) return;

        cfusa_report_add(ctx->rpt,
            "CFUSA-A003", CFUSA_CATEGORY_ANALYZE, SEV_WARNING,
            path, lineno,
            "signed/unsigned comparison with sizeof — sizeof returns size_t (unsigned); "
            "compare with (size_t) or use explicit cast (CERT-C INT02-C)");
        return;
    }
}

static int a003_collect_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a003_collect_line, v); return 0;
}

static int a003_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a003_line, v); return 0;
}

//cfusa:req REQ-ANA010
static int rule_a003(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c"};
    a003_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.rpt = rpt;
    /* Two full passes over every source file: pass 1 accumulates one
     * known-unsigned name set across the whole project (not scoped per
     * file — a name seen anywhere counts, biasing toward suppressing
     * more false positives at a small, acceptable risk of missing a
     * genuinely differently-typed same-named variable elsewhere), then
     * pass 2 runs the actual check consulting that set. */
    cfusa_walk_sources(dir, exts, 1, a003_collect_file, &ctx);
    cfusa_walk_sources(dir, exts, 1, a003_file, &ctx);
    return 0;
}

//cfusa:req REQ-ANA004
/* A004 — integer overflow risk (INT_MAX, UINT_MAX without check) */
static void a004_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    if((strstr(line,"INT_MAX") || strstr(line,"UINT_MAX") || strstr(line,"INT_MIN"))
       && !strstr(line,"if ") && !strstr(line,"assert(") && !strstr(line,"#define"))
        cfusa_report_add(ctx->rpt,
            "CFUSA-A004", CFUSA_CATEGORY_ANALYZE, SEV_INFO,
            path, lineno,
            "integer boundary constant referenced — verify overflow guard is in place "
            "(CERT-C INT30-C, INT32-C)");
}

static int a004_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a004_line, v); return 0;
}

static int rule_a004(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c",".h"};
    a_ctx_t ctx={rpt};
    cfusa_walk_sources(dir, exts, 2, a004_file, &ctx);
    return 0;
}

//cfusa:req REQ-ANA005
/* A005 — use of assert in production (not for safety invariants in release) */
static void a005_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    if(strncmp(p,"assert(",7)==0)
        cfusa_report_add(ctx->rpt,
            "CFUSA-A005", CFUSA_CATEGORY_ANALYZE, SEV_INFO,
            path, lineno,
            "assert() — in safety-critical code use explicit error handling; "
            "assert may be compiled out in release builds (CERT-C MSC11-C)");
}

static int a005_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a005_line, v); return 0;
}

static int rule_a005(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c"};
    a_ctx_t ctx={rpt};
    cfusa_walk_sources(dir, exts, 1, a005_file, &ctx);
    return 0;
}

/* Copies the identifier (alnum/underscore run) touching position `at`:
 * dir<0 scans backward from `at` (the operand of a postfix ++/--/+=/-=,
 * e.g. the "ptr" in "ptr++"); dir>0 scans forward from `at` (the operand
 * of a prefix ++/--, e.g. the "ptr" in "++ptr"). Returns the identifier's
 * length, or 0 if none touches `at` (e.g. "5++" — no identifier, not a
 * candidate). */
static size_t a006_ident_touching(const char *line, const char *at, int dir,
                                   char *out, size_t out_sz)
{
    if (dir < 0) {
        const char *e = at;
        const char *s = e;
        while (s > line && (isalnum((unsigned char)s[-1]) || s[-1] == '_')) s--;
        size_t n = (size_t)(e - s);
        if (n == 0 || n >= out_sz) return 0;
        memcpy(out, s, n); out[n] = '\0';
        return n;
    }
    const char *s = at;
    const char *b = s;
    while (isalnum((unsigned char)*s) || *s == '_') s++;
    size_t n = (size_t)(s - b);
    if (n == 0 || n >= out_sz) return 0;
    memcpy(out, b, n); out[n] = '\0';
    return n;
}

/* Does `*<ident>` (asterisk immediately followed by `ident`, i.e. a
 * dereference of it or a "<type> *ident" declaration of it, with a word
 * boundary after) appear outside string/char literals anywhere on `line`?
 * Used to confirm the identifier next to an arithmetic operator is
 * plausibly a pointer, rather than an unrelated variable that merely
 * shares the line with an unrelated '*'. */
static int a006_has_star_ident(const char *line, const char *ident)
{
    size_t ilen = strlen(ident);
    int in_str = 0, in_chr = 0, in_cmt = 0;
    for (const char *p = line; *p; p++) {
        if (in_cmt) { if (p[0]=='*' && p[1]=='/') { in_cmt = 0; p++; } continue; }
        if (in_str) { if (*p == '"' && p[-1] != A006_BACKSLASH) in_str = 0; continue; }
        if (in_chr) { if (*p == '\'' && p[-1] != A006_BACKSLASH) in_chr = 0; continue; }
        if (p[0] == '/' && p[1] == '*') { in_cmt = 1; p++; continue; }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == '\'') { in_chr = 1; continue; }
        if (*p == '*' && strncmp(p + 1, ident, ilen) == 0) {
            unsigned char after = (unsigned char)p[1 + ilen];
            if (!(isalnum(after) || after == '_')) return 1;
        }
    }
    return 0;
}

//cfusa:req REQ-ANA006
/*
 * A006 — pointer arithmetic (MISRA-C Rule 18.4).
 *
 * Previously flagged any line containing (loosely) a "++"/"--"/" += "/
 * " -= " token together with any "*" character anywhere on the line, with
 * no string-literal awareness and no requirement that the two relate to
 * the same variable — so e.g. an argv literal like
 * `char *argv[] = {"cfusa", "--lcov", ...};` matched purely by
 * coincidence: the "--" inside the "--lcov" string literal, and the
 * unrelated "*" in the pointer declaration.
 *
 * Tightened to require both: (1) the operator occurrence is outside a
 * string/char literal or a block comment, and (2) the
 * identifier immediately touching that operator also appears elsewhere on
 * the line as "*<same identifier>" (a dereference, or a pointer
 * declaration of that name) — i.e. the arithmetic and the pointer-ness
 * plausibly apply to the SAME variable, not just two unrelated tokens
 * that happen to share a line. Still a line-based heuristic (no real
 * symbol table, and block-comment tracking doesn't persist across lines
 * like the rest of this file's rules), not a false-positive-proof
 * parser.
 */
static void a006_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    if (strstr(line,"//")) return; /* preserves the prior line-comment exclusion */

    int in_str = 0, in_chr = 0, in_cmt = 0;
    for (const char *q = line; *q; q++) {
        if (in_cmt) { if (q[0]=='*' && q[1]=='/') { in_cmt = 0; q++; } continue; }
        if (in_str) { if (*q == '"' && q[-1] != A006_BACKSLASH) in_str = 0; continue; }
        if (in_chr) { if (*q == '\'' && q[-1] != A006_BACKSLASH) in_chr = 0; continue; }
        if (q[0] == '/' && q[1] == '*') { in_cmt = 1; q++; continue; }
        if (*q == '"') { in_str = 1; continue; }
        if (*q == '\'') { in_chr = 1; continue; }

        char ident[128]; size_t ilen = 0;
        if ((q[0]=='+' && q[1]=='+') || (q[0]=='-' && q[1]=='-')) {
            /* postfix (ptr++) takes priority; fall back to prefix (++ptr) */
            ilen = a006_ident_touching(line, q, -1, ident, sizeof ident);
            if (ilen == 0)
                ilen = a006_ident_touching(line, q + 2, +1, ident, sizeof ident);
        } else if (q[0]==' ' && (q[1]=='+' || q[1]=='-') && q[2]=='=' && q[3]==' ') {
            ilen = a006_ident_touching(line, q, -1, ident, sizeof ident);
        } else {
            continue;
        }
        if (ilen == 0) continue;

        if (a006_has_star_ident(line, ident)) {
            cfusa_report_add(ctx->rpt,
                "CFUSA-A006", CFUSA_CATEGORY_ANALYZE, SEV_INFO,
                path, lineno,
                "pointer arithmetic on '%s' detected — verify bounds "
                "(MISRA-C:2012 R18.4)", ident);
            return; /* one finding per line is enough */
        }
    }
}

static int a006_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a006_line, v); return 0;
}

static int rule_a006(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c"};
    a_ctx_t ctx={rpt};
    cfusa_walk_sources(dir, exts, 1, a006_file, &ctx);
    return 0;
}

//cfusa:req REQ-ANA007
/* A007 — missing return value check for system calls */
static const char * const syscall_fns[] = {
    "fopen(","fclose(","fread(","fwrite(",
    "read(","write(","open(","close(",
    "connect(","bind(","listen(",
    NULL
};

static void a007_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    for(int i=0; syscall_fns[i]; i++) {
        const char *fp = strstr(line, syscall_fns[i]);
        if (!fp) continue;
        /* word-boundary: skip substrings (e.g. "close(" inside "fclose(") */
        if (fp > line && (*(fp-1)=='_' || (*(fp-1)>='a'&&*(fp-1)<='z')
                          || (*(fp-1)>='A'&&*(fp-1)<='Z')
                          || (*(fp-1)>='0'&&*(fp-1)<='9'))) continue;
        if (!cfusa_match_outside_string(line, syscall_fns[i])) continue;
        /* Flag bare calls (no assignment or conditional) */
        if (!strstr(line,"=") && !strstr(line,"if ") && !strstr(line,"while "))
            cfusa_report_add(ctx->rpt,
                "CFUSA-A007", CFUSA_CATEGORY_ANALYZE, SEV_WARNING,
                path, lineno,
                "return value of '%.*s' may be unchecked — "
                "system call failures must be handled (CERT-C ERR33-C)",
                (int)(strlen(syscall_fns[i])-1), syscall_fns[i]);
    }
}

static int a007_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a007_line, v); return 0;
}

static int rule_a007(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c"};
    a_ctx_t ctx={rpt};
    cfusa_walk_sources(dir, exts, 1, a007_file, &ctx);
    return 0;
}

/* ---- rule table ---- */

static const cfusa_rule_t analyze_rules[] = {
    {"CFUSA-A001","analyze","Unsafe string functions",
     "Unbounded string operations risk overflow","cert-c","STR31-C",rule_a001},
    {"CFUSA-A002","analyze","Unchecked allocation",
     "malloc/calloc/realloc return must be checked","cert-c","MEM32-C",rule_a002},
    {"CFUSA-A003","analyze","Signed/unsigned comparison",
     "Comparison of signed and sizeof (unsigned)","cert-c","INT02-C",rule_a003},
    {"CFUSA-A004","analyze","Integer boundary",
     "INT_MAX/MIN/UINT_MAX usage without guard","cert-c","INT30-C",rule_a004},
    {"CFUSA-A005","analyze","Assert in production",
     "assert() may be compiled out in release builds","cert-c","MSC11-C",rule_a005},
    {"CFUSA-A006","analyze","Pointer arithmetic",
     "Pointer arithmetic requires bounds verification","misra-c","R18.4",rule_a006},
    {"CFUSA-A007","analyze","Unchecked system call",
     "System call return values must be checked","cert-c","ERR33-C",rule_a007},
};
#define N_ANALYZE_RULES ((int)(sizeof(analyze_rules)/sizeof(analyze_rules[0])))

void cfusa_analyze_register_rules(void)
{
    for (int i = 0; i < N_ANALYZE_RULES; i++)
        cfusa_engine_register(&analyze_rules[i]);
}

int cmd_analyze(int argc, char **argv)
{
    const char *dir   = ".";
    const char *fmt_s = "text";
    const char *output = NULL;
    int strict = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"strict", no_argument,       NULL, 's'},
        {"list",   no_argument,       NULL, 'l'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c, list_rules = 0;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:f:o:slh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 's': strict = 1;     break;
        case 'l': list_rules = 1; break;
        case 'h':
            printf("Usage: cfusa analyze [--dir <path>] [--format text|json|sarif|html|md]\n"
                   "                     [--output <file>] [--strict] [--list]\n\n"
                   "Static analysis: buffer overflows, unchecked returns, integer issues.\n\n"
                   "Rules: CFUSA-A001 through CFUSA-A007\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_engine_reset();
    cfusa_analyze_register_rules();

    if (list_rules) { cfusa_engine_list_rules(); return 0; }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    if (strict) cfg.strict = 1;

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    strncpy(rpt.project,  cfg.project, sizeof(rpt.project)  - 1);
    strncpy(rpt.version,  cfg.version, sizeof(rpt.version)  - 1);
    strncpy(rpt.standard, "CERT-C / MISRA-C:2012", sizeof(rpt.standard) - 1);
    /* issue #153: without project_root, cfusa_report_add() leaves `file`
     * absolute instead of relativizing it like cmd_check.c does — so the
     * same real finding gets a different fingerprint (and therefore
     * silently fails to match a recorded disposition) depending on
     * whether `cfusa check` or `cfusa analyze` produced it. */
    {
        char *abs = realpath(dir, NULL);
        if (abs) {
            strncpy(rpt.project_root, abs, sizeof(rpt.project_root) - 1);
            free(abs);
        } else {
            strncpy(rpt.project_root, dir, sizeof(rpt.project_root) - 1);
        }
    }

    cfusa_engine_run_category(CFUSA_CATEGORY_ANALYZE, dir, &cfg, &rpt);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    if (output)
        cfusa_report_write(&rpt, output, fmt);
    else
        cfusa_report_print(&rpt, stdout, fmt);

    int rc = (rpt.error_count > 0) || (cfg.strict && rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    return rc;
}
