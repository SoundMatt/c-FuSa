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
#include "cfusa/severity.h"
#include "cfusa/utils.h"
#include "cfusa/disposition.h"
#include "cfusa/lex.h"

/* ---- rule helpers ---- */

typedef struct {
    cfusa_report_t  *rpt;
    const cfusa_config_t *cfg;
    const char      *rule_id;
    const char      *category;
} scan_ctx_t;

//cfusa:req REQ-LINT001
/* L001 — function length > max_function_lines (MISRA-C Rule 15.5 analogue) */
typedef struct { cfusa_report_t *rpt; const cfusa_config_t *cfg; } l001_ctx_t;

static int l001_file(const char *path, void *vctx)
{
    l001_ctx_t *ctx = vctx;
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[4096];
    int lineno = 0, fn_start = 0, brace_depth = 0, in_fn = 0;
    char fn_name[128] = "";

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char trimmed[4096];
        strncpy(trimmed, line, sizeof(trimmed) - 1);
        /* issue #177: strncpy() only NUL-terminates when `line` is shorter
         * than the destination — without this, a single physical source
         * line >=4095 bytes with no embedded newline leaves trimmed[4095]
         * uninitialized before cfusa_str_trim()'s internal strlen() runs
         * (matches the fix l004_file() already applies for the same
         * hazard, cmd_lint.c below). */
        trimmed[sizeof(trimmed) - 1] = '\0';
        cfusa_str_trim(trimmed);

        /* Detect function signature before scanning braces on this line so
         * same-line opening braces (K&R style) are handled correctly. */
        if (!in_fn && brace_depth == 0
            && strstr(trimmed, "(") && strstr(trimmed, ")")
            && trimmed[0] != '#' && trimmed[0] != '/'
            && trimmed[0] != '*' && trimmed[0] != ' ') {
            char *paren = strchr(trimmed, '(');
            if (paren) {
                char before[128] = "";
                size_t blen = (size_t)(paren - trimmed);
                if (blen > 0 && blen < 128) {
                    strncpy(before, trimmed, blen);
                    char *sp = strrchr(before, ' ');
                    strncpy(fn_name, sp ? sp + 1 : before, sizeof(fn_name) - 1);
                    while (fn_name[0] == '*') memmove(fn_name, fn_name+1, strlen(fn_name));
                }
                in_fn = 1;
            }
        }

        for (char *p = line; *p; p++) {
            if (*p == '{') {
                if (brace_depth == 0 && in_fn) fn_start = lineno;
                brace_depth++;
            } else if (*p == '}') {
                brace_depth--;
                if (brace_depth == 0 && in_fn) {
                    int length = lineno - fn_start;
                    if (length > ctx->cfg->max_function_lines) {
                        cfusa_report_add(ctx->rpt,
                            "CFUSA-L001", CFUSA_CATEGORY_LINT, SEV_WARNING,
                            path, fn_start,
                            "function '%s' is %d lines (max %d); "
                            "MISRA-C recommends short functions",
                            fn_name, length, ctx->cfg->max_function_lines);
                    }
                    in_fn = 0; fn_name[0] = '\0';
                }
            }
        }
    }
    fclose(f);
    return 0;
}

static int rule_l001(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    static const char * const exts[] = {".c"};
    l001_ctx_t ctx = {rpt, cfg};
    cfusa_walk_sources(dir, exts, 1, l001_file, &ctx);
    return 0;
}

//cfusa:req REQ-LINT003
/* L002 — use of goto (MISRA-C 2012 Rule 15.1)
 *
 * issue #204: registered as a line rule instead of walking the source
 * tree itself -- the engine now performs one walk+lex pass per file and
 * hands every registered line rule the same already comment/string-
 * stripped `code_line`, so this callback no longer needs its own
 * string-literal tracking (issue #162's boundary check is unaffected). */
static void l002_line(const char *path, int lineno, const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    for (const char *p = code_line; *p; p++) {
        if (strncmp(p, "goto", 4) != 0) continue;
        int left_ok = (p == code_line) ||
            !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
        int right_ok = (p[4] == ' ' || p[4] == '\t');
        if (!left_ok || !right_ok) continue;
        cfusa_report_add(rpt,
            "CFUSA-L002", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "use of 'goto' violates MISRA-C 2012 Rule 15.1");
        return;
    }
}

//cfusa:req REQ-LINT005 REQ-LINT017
/* L003 — dynamic memory (malloc/calloc/realloc/free) MISRA-C 2012 Rule 21.3.
 *
 * Precision fix: the original version matched these names with a plain
 * strstr(), so "free(" also matched the "free(" *substring* inside any
 * custom cleanup function ending in "_free(" (e.g. cfusa_report_free())
 * — a large false-positive class (61% of findings project-wide when
 * this was measured). Now requires a non-identifier boundary
 * immediately before the match, the same technique L011 uses for its
 * octal-constant boundary check, and skips string-literal content so
 * quoted example code doesn't trigger it either.
 *
 * Severity is ASIL-scaled (mirrors cmd_misra.c's declared-ASIL-based
 * accredited-tool note): ISO 26262-6 lists
 * avoiding dynamic memory allocation as "highly recommended" at
 * ASIL-C/D but only "recommended" at QM/A/B, so a declared ASIL-C/D
 * project gets a hard SEV_ERROR here instead of the uniform SEV_WARNING
 * every project got before. */
static const char * const dyn_mem_fns[] = {
    "malloc(", "calloc(", "realloc(", "free(",
    "malloc (","calloc (","realloc (","free (",
    NULL
};

/* issue #204: registered as a line rule -- the engine's single walk+lex
 * pass (cfusa_lex_strip_line(), issue #203) already hands every line
 * rule a comment/string-stripped `code_line`, so this callback no
 * longer needs its own lexer state at all. Severity is still ASIL-
 * scaled per-call from `cfg` (the line-rule dispatcher passes `cfg`
 * through unchanged), matching the original per-invocation behavior. */
static void l003_line(const char *path, int lineno, const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)vctx;
    cfusa_severity_t sev = (cfusa_declared_asil_rank(cfg) >= 3)
        ? SEV_ERROR : SEV_WARNING;

    for (const char *q = code_line; *q; q++) {
        for (int i = 0; dyn_mem_fns[i]; i++) {
            size_t flen = strlen(dyn_mem_fns[i]);
            if (strncmp(q, dyn_mem_fns[i], flen) != 0) continue;
            int boundary_ok = (q == code_line) ||
                !(isalnum((unsigned char)q[-1]) || q[-1] == '_');
            if (!boundary_ok) continue;
            cfusa_report_add(rpt,
                "CFUSA-L003", CFUSA_CATEGORY_LINT, sev,
                path, lineno,
                "dynamic memory allocation ('%.*s') — MISRA-C 2012 Rule 21.3: "
                "heap usage prohibited in safety-critical code",
                (int)(flen - 1), dyn_mem_fns[i]);
            return;
        }
    }
}

//cfusa:req REQ-LINT007
/* L004 — recursive function (MISRA-C 2012 Rule 17.2) — self-call heuristic.
 *
 * Two fixes vs the original naive scanner:
 *
 * Fix 1 — definition-line false positive: the function's own name appears in
 * its signature (e.g. "void foo(void) {" contains "foo(").  We set
 * fn_just_detected on the line where the name is first recorded and skip the
 * self-call check for that line only.
 *
 * Fix 2 — brace mis-tracking: braces inside block comments, line comments, or
 * string/character literals are no longer counted.  in_block_comment persists
 * across lines in the context struct.
 */
typedef struct {
    cfusa_report_t *rpt;
    char fn_name[128];
    int  in_fn;
    cfusa_lex_state_t lex; /* in_block_comment persists across fgets() iterations */
} l004_ctx_t;

/* Word-boundary-aware self-call detector for CFUSA-L004. Unlike the
 * generic cfusa_match_outside_string() substring match (which is a
 * deliberate, documented non-word-boundary checker used elsewhere for
 * fixed dangerous-function-name lookups), a self-call check additionally
 * requires an identifier boundary immediately before the candidate match
 * — otherwise a callee whose name merely *ends with* the caller's name
 * (e.g. static int evaluate(...) calling helper_evaluate(...), or
 * rcp_e2e_wd_evaluate(...)) is misreported as recursion.
 *
 * issue #187 / #203: the caller (l004_file() below) now passes a view of
 * the line already stripped of comment and string content by the shared
 * cfusa_lex_strip_line() (include/cfusa/lex.h) -- so a doc-comment merely
 * mentioning the function's own name followed by '(' (e.g. "this
 * setUp() writes below") can no longer be misread as a real self-call.
 * The in_str tracking below is kept as a defensive no-op (string content
 * is already blanked in that stripped view) rather than removed, in case
 * this is ever called with a raw line in the future. */
static int l004_self_call(const char *line, const char *fn_name)
{
    size_t flen = strlen(fn_name);
    if (flen == 0) return 0;
    int in_str = 0;
    const char *p = line;
    while (*p) {
        if (*p == '"' && (p == line || p[-1] != '\\'))
            in_str = !in_str;
        if (!in_str && strncmp(p, fn_name, flen) == 0 && p[flen] == '(') {
            int boundary_ok = (p == line) ||
                !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
            if (boundary_ok) return 1;
        }
        p++;
    }
    return 0;
}

static int l004_file(const char *path, void *vctx)
{
    l004_ctx_t *ctx = vctx;
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[4096];
    int lineno = 0, brace = 0;
    ctx->fn_name[0] = '\0';
    ctx->in_fn = 0;
    cfusa_lex_reset(&ctx->lex);

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char trimmed[4096];
        strncpy(trimmed, line, sizeof(trimmed) - 1);
        trimmed[sizeof(trimmed) - 1] = '\0';
        /* cfusa_str_trim returns pointer past leading whitespace and
         * null-terminates trailing whitespace in the buffer. */
        const char *tp = cfusa_str_trim(trimmed);

        /* Detect function definitions at file scope only.
         * Skip: forward decls (ending ';'), preprocessor, comment lines
         * ('/' or '*' start), lines with '=' (assignments/initialisers),
         * array-subscript lines, and anything inside a block comment. */
        int fn_just_detected = 0;
        {
            size_t tlen = strlen(tp);
            int is_decl = (tlen > 0 && tp[tlen - 1] == ';');
            if (!ctx->in_fn && brace == 0 && !is_decl
                && !ctx->lex.in_block_comment
                && strstr(tp, "(") && strstr(tp, ")")
                && tp[0] != '#' && tp[0] != '/' && tp[0] != '*'
                && !strstr(tp, "=") && !strstr(tp, "[]")) {
                const char *paren = strchr(tp, '(');
                if (paren) {
                    char before[128] = "";
                    size_t bl = (size_t)(paren - tp);
                    if (bl < 128) {
                        strncpy(before, tp, bl);
                        before[bl] = '\0';
                        const char *sp = strrchr(before, ' ');
                        strncpy(ctx->fn_name, sp ? sp + 1 : before, 127);
                        ctx->fn_name[127] = '\0';
                        while (ctx->fn_name[0] == '*')
                            memmove(ctx->fn_name, ctx->fn_name + 1,
                                    strlen(ctx->fn_name));
                        ctx->in_fn = 1;
                        fn_just_detected = 1;
                    }
                }
            }
        }

        /* issue #203: comment/string-literal stripping now goes through
         * the shared cfusa_lex_strip_line() instead of a hand-rolled
         * copy of the same state machine. Brace depth is counted over
         * the stripped `code` buffer so embedded braces inside a comment
         * or string/character literal don't corrupt it; the self-call
         * check below scans the same stripped buffer so a comment merely
         * mentioning the function's own name followed by '(' is never
         * misread as a real recursive call (issue #187). */
        char code[4096];
        cfusa_lex_strip_line(&ctx->lex, line, code, sizeof(code));
        for (const char *p = code; *p; p++) {
            if (*p == '{') {
                brace++;
            } else if (*p == '}') {
                brace--;
                if (brace == 0) {
                    ctx->in_fn = 0;
                    ctx->fn_name[0] = '\0';
                }
            }
        }

        /* Self-call check.  Skip the line where the function was first
         * detected: the signature always contains "fn_name(" naturally. */
        if (!fn_just_detected && ctx->in_fn && ctx->fn_name[0] && brace > 0) {
            if (l004_self_call(code, ctx->fn_name)) {
                cfusa_report_add(ctx->rpt,
                    "CFUSA-L004", CFUSA_CATEGORY_LINT, SEV_ERROR,
                    path, lineno,
                    "function '%s' appears recursive — MISRA-C 2012 Rule 17.2: "
                    "recursion shall not be used",
                    ctx->fn_name);
            }
        }
    }
    fclose(f);
    return 0;
}

static int rule_l004(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c"};
    l004_ctx_t ctx = {rpt, "", 0, {0}};
    cfusa_walk_sources(dir, exts, 1, l004_file, &ctx);
    return 0;
}

//cfusa:req REQ-LINT008
/* L005 — use of #undef (MISRA-C 2012 Rule 20.5) */
static void l005_line(const char *path, int lineno, const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    const char *p = code_line;
    while (*p==' '||*p=='\t') p++;
    if (strncmp(p,"#undef",6)==0 && (p[6]==' '||p[6]=='\t'||p[6]=='\n'))
        cfusa_report_add(rpt,
            "CFUSA-L005", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "#undef usage — MISRA-C 2012 Rule 20.5: '#undef' shall not be used");
}

//cfusa:req REQ-LINT009
/* L006 — setjmp/longjmp (MISRA-C 2012 Rule 17.4).
 *
 * issue #161: identifier-boundary check — without it, a project-local
 * function whose name merely ends with "setjmp("/"longjmp(" (e.g.
 * cfusa_setjmp()) false-positives as a real non-local jump. issue #204:
 * registered as a line rule -- the engine's single walk+lex pass already
 * hands every line rule a comment/string-stripped `code_line`. */
static const char * const jmp_fns[] = {"setjmp(", "longjmp(", NULL};

static void l006_line(const char *path,int lineno,const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    for (const char *q = code_line; *q; q++) {
        for (int i = 0; jmp_fns[i]; i++) {
            size_t flen = strlen(jmp_fns[i]);
            if (strncmp(q, jmp_fns[i], flen) != 0) continue;
            int boundary_ok = (q == code_line) ||
                !(isalnum((unsigned char)q[-1]) || q[-1] == '_');
            if (!boundary_ok) continue;
            cfusa_report_add(rpt,
                "CFUSA-L006", CFUSA_CATEGORY_LINT, SEV_ERROR,
                path, lineno,
                "use of setjmp/longjmp — MISRA-C 2012 Rule 17.4: "
                "non-local jumps shall not be used");
            return;
        }
    }
}

//cfusa:req REQ-LINT011
/* L007 — global mutable variable (MISRA-C 2012 Rule 8.9 analogue) */
static void l007_line(const char *path,int lineno,const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    const char *p=code_line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='#') return;
    /* Heuristic: file-scope non-const variable declaration */
    if (strstr(code_line,"static ") && !strstr(code_line,"const ")
        && !strstr(code_line,"(") && strstr(code_line,";"))
        cfusa_report_add(rpt,
            "CFUSA-L007", CFUSA_CATEGORY_LINT, SEV_INFO,
            path, lineno,
            "mutable static variable — consider 'const' or restrict scope "
            "(MISRA-C 2012 Rule 8.9)");
}

//cfusa:req REQ-LINT012
/* L008 — void* usage (MISRA-C 2012 Rule 11.5) */
static void l008_line(const char *path,int lineno,const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    if (strstr(code_line,"void *") || strstr(code_line,"void*"))
        cfusa_report_add(rpt,
            "CFUSA-L008", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "use of void* pointer — MISRA-C 2012 Rule 11.5: "
            "conversion from void* should be avoided");
}

//cfusa:req REQ-LINT013
/* L009 — use of #pragma (MISRA-C 2012 Rule 20.10) */
static void l009_line(const char *path,int lineno,const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    const char *p=code_line;
    while(*p==' '||*p=='\t') p++;
    if (strncmp(p,"#pragma",7)==0)
        cfusa_report_add(rpt,
            "CFUSA-L009", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "#pragma directive — MISRA-C 2012 Rule 20.10: "
            "compiler extensions reduce portability");
}

//cfusa:req REQ-LINT014
/* L010 — use of errno (MISRA-C 2012 Rule 22.8) */
static void l010_line(const char *path,int lineno,const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    if (strstr(code_line,"errno") && !strstr(code_line,"<errno.h>"))
        cfusa_report_add(rpt,
            "CFUSA-L010", CFUSA_CATEGORY_LINT, SEV_INFO,
            path, lineno,
            "use of errno — MISRA-C 2012 Rule 22.8: "
            "errno value must be set to zero before calling a function; "
            "verify correct usage pattern");
}

//cfusa:req REQ-LINT015
/* L011 — octal constant (MISRA-C 2012 Rule 7.1) — c-FuSa issue #108.
 *
 * A '0' immediately followed by another digit, with no identifier/'.'
 * character directly before it, is an octal integer constant in C (e.g.
 * 0755). The boundary-before check alone is enough to reject the leading
 * '0' of a hex literal too: in "0x0A" the second '0' is preceded by 'x'
 * (alnum), so it never matches; a bare "0" or a float like "0.5" also
 * never matches since the character right after '0' isn't a digit. */
static void l011_line(const char *path, int lineno, const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    for (const char *q = code_line; *q; q++) {
        if (*q == '0' && q[1] >= '0' && q[1] <= '9') {
            int boundary_ok = (q == code_line) ||
                !(isalnum((unsigned char)q[-1]) || q[-1] == '.' || q[-1] == '_');
            if (boundary_ok) {
                cfusa_report_add(rpt,
                    "CFUSA-L011", CFUSA_CATEGORY_LINT, SEV_WARNING,
                    path, lineno,
                    "octal constant — MISRA-C 2012 Rule 7.1: octal "
                    "constants (other than zero) shall not be used");
                return; /* one finding per line is enough */
            }
        }
    }
}

//cfusa:req REQ-LINT016
/* L012 — macro defined with the same name as a C keyword
 * (MISRA-C 2012 Rule 20.4) — c-FuSa issue #108. */
static const char * const c_keywords[] = {
    "auto","break","case","char","const","continue","default","do",
    "double","else","enum","extern","float","for","goto","if",
    "inline","int","long","register","restrict","return","short",
    "signed","sizeof","static","struct","switch","typedef","union",
    "unsigned","void","volatile","while",
    "_Bool","_Complex","_Imaginary",
    NULL
};

static void l012_line(const char *path, int lineno, const char *code_line,
                       const cfusa_config_t *cfg, cfusa_report_t *rpt, void *vctx)
{
    (void)cfg; (void)vctx;
    const char *p = code_line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "#define", 7) != 0) return;
    p += 7;
    while (*p == ' ' || *p == '\t') p++;

    const char *start = p;
    while (isalnum((unsigned char)*p) || *p == '_') p++;
    size_t len = (size_t)(p - start);
    if (len == 0) return;

    for (int i = 0; c_keywords[i]; i++) {
        size_t klen = strlen(c_keywords[i]);
        if (klen == len && strncmp(start, c_keywords[i], klen) == 0) {
            cfusa_report_add(rpt,
                "CFUSA-L012", CFUSA_CATEGORY_LINT, SEV_ERROR,
                path, lineno,
                "macro '%s' has the same name as a C keyword — MISRA-C "
                "2012 Rule 20.4: a macro shall not be defined with a "
                "reserved keyword identifier",
                c_keywords[i]);
            return;
        }
    }
}

/* ---- rule table ---- */

/* L001 and L004 need state spanning more than one line (brace depth,
 * function scope) so they stay whole-file cfusa_rule_t rules; every
 * other rule below is a pure per-line pattern-matcher and is registered
 * as a cfusa_line_rule_t instead (issue #204) so the engine's single
 * walk+lex pass drives all of them together. */
static const cfusa_rule_t lint_rules[] = {
    {"CFUSA-L001","lint","Function length",
     "Functions should not exceed max_function_lines","misra-c","R15.5",rule_l001},
    {"CFUSA-L004","lint","No recursion",
     "Recursive functions are prohibited","misra-c","R17.2",rule_l004},
};
#define N_LINT_RULES ((int)(sizeof(lint_rules)/sizeof(lint_rules[0])))

static const char * const lint_exts_c[]   = {".c"};
static const char * const lint_exts_c_h[] = {".c", ".h"};

/* None of these need per-rule state beyond `rpt` (passed explicitly to
 * every cfusa_line_rule_cb, see cfusa/engine.h) and `cfg` (also passed
 * explicitly), so `ctx` is NULL for all of them. */
static const cfusa_line_rule_t lint_line_rules[] = {
    {"CFUSA-L002","lint","No goto",
     "Goto statements are prohibited","misra-c","R15.1",
     lint_exts_c_h, 2, l002_line, NULL},
    {"CFUSA-L003","lint","No dynamic memory",
     "malloc/calloc/realloc/free prohibited","misra-c","R21.3",
     lint_exts_c, 1, l003_line, NULL},
    {"CFUSA-L005","lint","No #undef",
     "#undef shall not be used","misra-c","R20.5",
     lint_exts_c_h, 2, l005_line, NULL},
    {"CFUSA-L006","lint","No setjmp/longjmp",
     "Non-local jumps shall not be used","misra-c","R17.4",
     lint_exts_c_h, 2, l006_line, NULL},
    {"CFUSA-L007","lint","Mutable static variable",
     "Mutable statics reduce testability","misra-c","R8.9",
     lint_exts_c, 1, l007_line, NULL},
    {"CFUSA-L008","lint","Avoid void*",
     "Conversions from void* should be avoided","misra-c","R11.5",
     lint_exts_c_h, 2, l008_line, NULL},
    {"CFUSA-L009","lint","No #pragma",
     "#pragma reduces portability","misra-c","R20.10",
     lint_exts_c_h, 2, l009_line, NULL},
    {"CFUSA-L010","lint","errno usage",
     "errno must be zeroed before use","misra-c","R22.8",
     lint_exts_c, 1, l010_line, NULL},
    {"CFUSA-L011","lint","No octal constants",
     "Octal constants (other than zero) shall not be used","misra-c","R7.1",
     lint_exts_c_h, 2, l011_line, NULL},
    {"CFUSA-L012","lint","No keyword-named macros",
     "A macro shall not be defined with the same name as a keyword","misra-c","R20.4",
     lint_exts_c_h, 2, l012_line, NULL},
};
#define N_LINT_LINE_RULES ((int)(sizeof(lint_line_rules)/sizeof(lint_line_rules[0])))

void cfusa_lint_register_rules(void)
{
    for (int i = 0; i < N_LINT_RULES; i++)
        cfusa_engine_register(&lint_rules[i]);
    for (int i = 0; i < N_LINT_LINE_RULES; i++)
        cfusa_engine_register_line_rule(&lint_line_rules[i]);
}

/* ---- cmd_lint entry point ---- */

int cmd_lint(int argc, char **argv)
{
    const char *dir    = ".";
    const char *fmt_s  = "text";
    const char *output = NULL;
    int strict = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"strict", no_argument,       NULL, 's'},
        {"list",   no_argument,       NULL, 'l'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c, list_rules = 0;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:f:o:slh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 's': strict = 1;      break;
        case 'l': list_rules = 1;  break;
        case 'h':
            printf("Usage: cfusa lint [--dir <path>] [--format text|json|sarif|html|md]\n"
                   "                  [--output <file>] [--strict] [--list]\n\n"
                   "Checks C source for MISRA-C and CERT-C coding standard violations.\n\n"
                   "Rules: CFUSA-L001 through CFUSA-L012\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_engine_reset();
    cfusa_lint_register_rules();

    if (list_rules) {
        cfusa_engine_list_rules();
        return 0;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    if (strict) cfg.strict = 1;

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    rpt.strict = cfg.strict; /* issue #164: printed Result must match the exit-code gate below */
    strncpy(rpt.project,  cfg.project,  sizeof(rpt.project)  - 1);
    strncpy(rpt.version,  cfg.version,  sizeof(rpt.version)  - 1);
    strncpy(rpt.standard, "MISRA-C:2012 / CERT-C", sizeof(rpt.standard) - 1);
    /* issue #153: without project_root, cfusa_report_add() leaves `file`
     * absolute instead of relativizing it like cmd_check.c does — so the
     * same real finding gets a different fingerprint (and therefore
     * silently fails to match a recorded disposition) depending on
     * whether `cfusa check` or `cfusa lint` produced it. */
    {
        char *abs = realpath(dir, NULL);
        if (abs) {
            strncpy(rpt.project_root, abs, sizeof(rpt.project_root) - 1);
            free(abs);
        } else {
            strncpy(rpt.project_root, dir, sizeof(rpt.project_root) - 1);
        }
    }

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, dir, &cfg, &rpt);

    //cfusa:req REQ-DISP-ENFORCE003
    /* issue #122: see the matching comment in cmd_check.c. */
    cfusa_disposition_list_t disps;
    if (!cfusa_dispositions_load(dir, &disps))
        fprintf(stderr, "cfusa lint: WARNING: dispositions may be incomplete\n");
    cfusa_report_apply_dispositions(&rpt, &disps);
    cfusa_dispositions_free(&disps);

    //cfusa:req REQ-BASELINE001
    /* issue #208: see the matching comment in cmd_check.c. */
    cfusa_disposition_list_t baseline;
    if (!cfusa_baseline_load(dir, &baseline))
        fprintf(stderr, "cfusa lint: WARNING: baseline may be incomplete\n");
    cfusa_report_apply_dispositions(&rpt, &baseline);
    cfusa_dispositions_free(&baseline);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);

    if (output) {
        /* issue #141: see the matching comment in cmd_check.c. */
        if (cfusa_report_write(&rpt, output, fmt) != 0) {
            cfusa_report_free(&rpt);
            return 3;
        }
    } else {
        cfusa_report_print(&rpt, stdout, fmt);
    }

    int exit_code = 0;
    if (rpt.error_count > 0) exit_code = 1;
    if (cfg.strict && rpt.warning_count > 0) exit_code = 1;

    cfusa_report_free(&rpt);
    return exit_code;
}
