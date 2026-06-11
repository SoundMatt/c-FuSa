#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

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
/* L002 — use of goto (MISRA-C 2012 Rule 15.1) */
typedef struct { cfusa_report_t *rpt; } line_scan_ctx_t;

static void l002_line(const char *path, int lineno, const char *line, void *vctx)
{
    line_scan_ctx_t *ctx = vctx;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "goto", 4) == 0 && (p[4] == ' ' || p[4] == '\t'))
        cfusa_report_add(ctx->rpt,
            "CFUSA-L002", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "use of 'goto' violates MISRA-C 2012 Rule 15.1");
}

static int l002_file(const char *path, void *vctx)
{
    cfusa_scan_lines(path, l002_line, vctx);
    return 0;
}

static int rule_l002(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c", ".h"};
    line_scan_ctx_t ctx = {rpt};
    cfusa_walk_sources(dir, exts, 2, l002_file, &ctx);
    return 0;
}

//cfusa:req REQ-LINT005
/* L003 — dynamic memory (malloc/calloc/realloc/free) MISRA-C 2012 Rule 21.3 */
static const char * const dyn_mem_fns[] = {
    "malloc(", "calloc(", "realloc(", "free(",
    "malloc (","calloc (","realloc (","free (",
    NULL
};

static void l003_line(const char *path, int lineno, const char *line, void *vctx)
{
    line_scan_ctx_t *ctx = vctx;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return; /* comment */
    for (int i = 0; dyn_mem_fns[i]; i++) {
        if (strstr(line, dyn_mem_fns[i])) {
            cfusa_report_add(ctx->rpt,
                "CFUSA-L003", CFUSA_CATEGORY_LINT, SEV_WARNING,
                path, lineno,
                "dynamic memory allocation ('%.*s') — MISRA-C 2012 Rule 21.3: "
                "heap usage prohibited in safety-critical code",
                (int)(strlen(dyn_mem_fns[i]) - 1), dyn_mem_fns[i]);
            return;
        }
    }
}

static int l003_file(const char *path, void *vctx)
{
    cfusa_scan_lines(path, l003_line, vctx);
    return 0;
}

static int rule_l003(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c"};
    line_scan_ctx_t ctx = {rpt};
    cfusa_walk_sources(dir, exts, 1, l003_file, &ctx);
    return 0;
}

//cfusa:req REQ-LINT007
/* L004 — recursive function (MISRA-C 2012 Rule 17.2) — simple self-call heuristic */
typedef struct {
    cfusa_report_t *rpt;
    char fn_name[128];
    int  in_fn;
} l004_ctx_t;

static int l004_file(const char *path, void *vctx)
{
    l004_ctx_t *ctx = vctx;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[4096];
    int lineno = 0, brace = 0;
    ctx->fn_name[0] = '\0';
    ctx->in_fn = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char trimmed[4096];
        strncpy(trimmed, line, sizeof(trimmed)-1);
        cfusa_str_trim(trimmed);

        /* Only detect function definitions at file scope (brace == 0).
         * Skip declarations ending with ';' (forward decls / extern). */
        size_t tlen = strlen(trimmed);
        int is_decl = (tlen > 0 && trimmed[tlen-1] == ';');
        if (!ctx->in_fn && brace == 0 && !is_decl
            && strstr(trimmed,"(") && strstr(trimmed,")")
            && trimmed[0] != '#' && trimmed[0] != '/'
            && !strstr(trimmed,"=") && !strstr(trimmed,"[]")) {
            char *paren = strchr(trimmed,'(');
            if (paren) {
                char before[128]="";
                size_t bl=(size_t)(paren-trimmed);
                if(bl<128){
                    strncpy(before,trimmed,bl);
                    char *sp=strrchr(before,' ');
                    strncpy(ctx->fn_name, sp?sp+1:before, 127);
                    while(ctx->fn_name[0]=='*')
                        memmove(ctx->fn_name,ctx->fn_name+1,strlen(ctx->fn_name));
                }
                ctx->in_fn = 1;
            }
        }

        for (char *p=line; *p; p++) {
            if (*p=='{') brace++;
            else if(*p=='}'){
                brace--;
                if(brace==0){ ctx->in_fn=0; ctx->fn_name[0]='\0'; }
            }
        }

        if (ctx->in_fn && ctx->fn_name[0] && brace>0) {
            /* Check if the function calls itself */
            char call[130];
            snprintf(call,sizeof(call),"%s(",ctx->fn_name);
            if (cfusa_match_outside_string(line, call)) {
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
    l004_ctx_t ctx = {rpt, "", 0};
    cfusa_walk_sources(dir, exts, 1, l004_file, &ctx);
    return 0;
}

//cfusa:req REQ-LINT008
/* L005 — use of #undef (MISRA-C 2012 Rule 20.5) */
static void l005_line(const char *path, int lineno, const char *line, void *vctx)
{
    line_scan_ctx_t *ctx = vctx;
    const char *p = line;
    while (*p==' '||*p=='\t') p++;
    if (strncmp(p,"#undef",6)==0 && (p[6]==' '||p[6]=='\t'||p[6]=='\n'))
        cfusa_report_add(ctx->rpt,
            "CFUSA-L005", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "#undef usage — MISRA-C 2012 Rule 20.5: '#undef' shall not be used");
}

static int l005_file(const char *path, void *v)
{
    cfusa_scan_lines(path,l005_line,v); return 0;
}

static int rule_l005(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c",".h"};
    line_scan_ctx_t ctx={rpt};
    cfusa_walk_sources(dir,exts,2,l005_file,&ctx);
    return 0;
}

//cfusa:req REQ-LINT009
/* L006 — setjmp/longjmp (MISRA-C 2012 Rule 17.4) */
static void l006_line(const char *path,int lineno,const char *line,void *vctx)
{
    line_scan_ctx_t *ctx=vctx;
    if (cfusa_match_outside_string(line,"setjmp(")||cfusa_match_outside_string(line,"longjmp("))
        cfusa_report_add(ctx->rpt,
            "CFUSA-L006", CFUSA_CATEGORY_LINT, SEV_ERROR,
            path, lineno,
            "use of setjmp/longjmp — MISRA-C 2012 Rule 17.4: "
            "non-local jumps shall not be used");
}

static int l006_file(const char *path, void *v)
{
    cfusa_scan_lines(path,l006_line,v); return 0;
}

static int rule_l006(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c",".h"};
    line_scan_ctx_t ctx={rpt};
    cfusa_walk_sources(dir,exts,2,l006_file,&ctx);
    return 0;
}

//cfusa:req REQ-LINT011
/* L007 — global mutable variable (MISRA-C 2012 Rule 8.9 analogue) */
static void l007_line(const char *path,int lineno,const char *line,void *vctx)
{
    line_scan_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/' || *p=='#' || *p=='*') return;
    /* Heuristic: file-scope non-const variable declaration */
    if (strstr(line,"static ") && !strstr(line,"const ")
        && !strstr(line,"(") && strstr(line,";"))
        cfusa_report_add(ctx->rpt,
            "CFUSA-L007", CFUSA_CATEGORY_LINT, SEV_INFO,
            path, lineno,
            "mutable static variable — consider 'const' or restrict scope "
            "(MISRA-C 2012 Rule 8.9)");
}

static int l007_file(const char *path, void *v)
{
    cfusa_scan_lines(path,l007_line,v); return 0;
}

static int rule_l007(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c"};
    line_scan_ctx_t ctx={rpt};
    cfusa_walk_sources(dir,exts,1,l007_file,&ctx);
    return 0;
}

//cfusa:req REQ-LINT012
/* L008 — void* usage (MISRA-C 2012 Rule 11.5) */
static void l008_line(const char *path,int lineno,const char *line,void *vctx)
{
    line_scan_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    if (strstr(line,"void *") || strstr(line,"void*"))
        cfusa_report_add(ctx->rpt,
            "CFUSA-L008", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "use of void* pointer — MISRA-C 2012 Rule 11.5: "
            "conversion from void* should be avoided");
}

static int l008_file(const char *path, void *v)
{
    cfusa_scan_lines(path,l008_line,v); return 0;
}

static int rule_l008(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c",".h"};
    line_scan_ctx_t ctx={rpt};
    cfusa_walk_sources(dir,exts,2,l008_file,&ctx);
    return 0;
}

//cfusa:req REQ-LINT013
/* L009 — use of #pragma (MISRA-C 2012 Rule 20.10) */
static void l009_line(const char *path,int lineno,const char *line,void *vctx)
{
    line_scan_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if (strncmp(p,"#pragma",7)==0)
        cfusa_report_add(ctx->rpt,
            "CFUSA-L009", CFUSA_CATEGORY_LINT, SEV_WARNING,
            path, lineno,
            "#pragma directive — MISRA-C 2012 Rule 20.10: "
            "compiler extensions reduce portability");
}

static int l009_file(const char *path, void *v)
{
    cfusa_scan_lines(path,l009_line,v); return 0;
}

static int rule_l009(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c",".h"};
    line_scan_ctx_t ctx={rpt};
    cfusa_walk_sources(dir,exts,2,l009_file,&ctx);
    return 0;
}

//cfusa:req REQ-LINT014
/* L010 — use of errno (MISRA-C 2012 Rule 22.8) */
static void l010_line(const char *path,int lineno,const char *line,void *vctx)
{
    line_scan_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Check for errno usage that isn't in a comment */
    if (strstr(line,"errno") && !strstr(line,"<errno.h>"))
        cfusa_report_add(ctx->rpt,
            "CFUSA-L010", CFUSA_CATEGORY_LINT, SEV_INFO,
            path, lineno,
            "use of errno — MISRA-C 2012 Rule 22.8: "
            "errno value must be set to zero before calling a function; "
            "verify correct usage pattern");
}

static int l010_file(const char *path, void *v)
{
    cfusa_scan_lines(path,l010_line,v); return 0;
}

static int rule_l010(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c"};
    line_scan_ctx_t ctx={rpt};
    cfusa_walk_sources(dir,exts,1,l010_file,&ctx);
    return 0;
}

/* ---- rule table ---- */

static const cfusa_rule_t lint_rules[] = {
    {"CFUSA-L001","lint","Function length",
     "Functions should not exceed max_function_lines","MISRA-C:2012 R15.5",rule_l001},
    {"CFUSA-L002","lint","No goto",
     "Goto statements are prohibited","MISRA-C:2012 R15.1",rule_l002},
    {"CFUSA-L003","lint","No dynamic memory",
     "malloc/calloc/realloc/free prohibited","MISRA-C:2012 R21.3",rule_l003},
    {"CFUSA-L004","lint","No recursion",
     "Recursive functions are prohibited","MISRA-C:2012 R17.2",rule_l004},
    {"CFUSA-L005","lint","No #undef",
     "#undef shall not be used","MISRA-C:2012 R20.5",rule_l005},
    {"CFUSA-L006","lint","No setjmp/longjmp",
     "Non-local jumps shall not be used","MISRA-C:2012 R17.4",rule_l006},
    {"CFUSA-L007","lint","Mutable static variable",
     "Mutable statics reduce testability","MISRA-C:2012 R8.9",rule_l007},
    {"CFUSA-L008","lint","Avoid void*",
     "Conversions from void* should be avoided","MISRA-C:2012 R11.5",rule_l008},
    {"CFUSA-L009","lint","No #pragma",
     "#pragma reduces portability","MISRA-C:2012 R20.10",rule_l009},
    {"CFUSA-L010","lint","errno usage",
     "errno must be zeroed before use","MISRA-C:2012 R22.8",rule_l010},
};
#define N_LINT_RULES ((int)(sizeof(lint_rules)/sizeof(lint_rules[0])))

void cfusa_lint_register_rules(void)
{
    for (int i = 0; i < N_LINT_RULES; i++)
        cfusa_engine_register(&lint_rules[i]);
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
                   "Rules: CFUSA-L001 through CFUSA-L010\n");
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
    strncpy(rpt.project,  cfg.project,  sizeof(rpt.project)  - 1);
    strncpy(rpt.version,  cfg.version,  sizeof(rpt.version)  - 1);
    strncpy(rpt.standard, "MISRA-C:2012 / CERT-C", sizeof(rpt.standard) - 1);

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, dir, &cfg, &rpt);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);

    if (output)
        cfusa_report_write(&rpt, output, fmt);
    else
        cfusa_report_print(&rpt, stdout, fmt);

    int exit_code = 0;
    if (rpt.error_count > 0) exit_code = 1;
    if (cfg.strict && rpt.warning_count > 0) exit_code = 1;

    cfusa_report_free(&rpt);
    return exit_code;
}
