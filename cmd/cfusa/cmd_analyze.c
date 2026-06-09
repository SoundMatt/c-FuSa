#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

typedef struct { cfusa_report_t *rpt; } a_ctx_t;

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

//cfusa:req REQ-ANA003
/* A003 — signed/unsigned comparison */
static void a003_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    if ((strstr(line,"< sizeof") || strstr(line,"> sizeof")
      || strstr(line,"<= sizeof") || strstr(line,">= sizeof")
      || strstr(line,"== sizeof") || strstr(line,"!= sizeof"))
      && !strstr(line,"(size_t)") && !strstr(line,"(int)sizeof"))
        cfusa_report_add(ctx->rpt,
            "CFUSA-A003", CFUSA_CATEGORY_ANALYZE, SEV_WARNING,
            path, lineno,
            "signed/unsigned comparison with sizeof — sizeof returns size_t (unsigned); "
            "compare with (size_t) or use explicit cast (CERT-C INT02-C)");
}

static int a003_file(const char *path, void *v)
{
    cfusa_scan_lines(path, a003_line, v); return 0;
}

static int rule_a003(const char *dir, const cfusa_config_t *cfg,
                      cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[]={".c"};
    a_ctx_t ctx={rpt};
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

//cfusa:req REQ-ANA006
/* A006 — pointer arithmetic (MISRA-C Rule 18.4) */
static void a006_line(const char *path,int lineno,const char *line,void *vctx)
{
    a_ctx_t *ctx=vctx;
    const char *p=line;
    while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Very rough: pointer +/- arithmetic (ptr + n, ptr - n, ptr++, ptr--) */
    if((strstr(line," += ") || strstr(line," -= ")
      || strstr(line,"++") || strstr(line,"--"))
      && strstr(line,"*") && !strstr(line,"//"))
        cfusa_report_add(ctx->rpt,
            "CFUSA-A006", CFUSA_CATEGORY_ANALYZE, SEV_INFO,
            path, lineno,
            "pointer arithmetic detected — verify bounds (MISRA-C:2012 R18.4)");
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
     "Unbounded string operations risk overflow","CERT-C STR31-C",rule_a001},
    {"CFUSA-A002","analyze","Unchecked allocation",
     "malloc/calloc/realloc return must be checked","CERT-C MEM32-C",rule_a002},
    {"CFUSA-A003","analyze","Signed/unsigned comparison",
     "Comparison of signed and sizeof (unsigned)","CERT-C INT02-C",rule_a003},
    {"CFUSA-A004","analyze","Integer boundary",
     "INT_MAX/MIN/UINT_MAX usage without guard","CERT-C INT30-C",rule_a004},
    {"CFUSA-A005","analyze","Assert in production",
     "assert() may be compiled out in release builds","CERT-C MSC11-C",rule_a005},
    {"CFUSA-A006","analyze","Pointer arithmetic",
     "Pointer arithmetic requires bounds verification","MISRA-C:2012 R18.4",rule_a006},
    {"CFUSA-A007","analyze","Unchecked system call",
     "System call return values must be checked","CERT-C ERR33-C",rule_a007},
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
        default: return 1;
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
