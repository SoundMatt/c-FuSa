#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

typedef struct { cfusa_report_t *rpt; } cy_ctx_t;

//cfusa:req REQ-CYB001
/* CY001 — CWE-120: Buffer copy without checking size */
static void cy001_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    static const char * const fns[]={"strcpy(","strncpy(","strcat(","strncat(","memcpy(","memmove(",NULL};
    for(int i=0;fns[i];i++){
        const char *fp=strstr(line,fns[i]);
        if(!fp) continue;
        if(fp>line && (*(fp-1)=='_'||(*(fp-1)>='a'&&*(fp-1)<='z')
                       ||(*(fp-1)>='A'&&*(fp-1)<='Z')
                       ||(*(fp-1)>='0'&&*(fp-1)<='9'))) continue;
        if(!cfusa_match_outside_string(line,fns[i])) continue;
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY001","cyber",SEV_WARNING,path,lineno,
            "CWE-120: buffer copy '%.*s' — ensure destination buffer is large enough; "
            "prefer explicit size-bounded variants",
            (int)(strlen(fns[i])-1),fns[i]);
        break;
    }
}

static int cy001_file(const char *path,void *v){cfusa_scan_lines(path,cy001_line,v);return 0;}
static int rule_cy001(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy001_file,&c); return 0;
}

//cfusa:req REQ-CYB002
/* CY002 — CWE-134: Uncontrolled format string */
static void cy002_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* printf/fprintf/syslog: check the FORMAT argument (not the FILE* arg) */
    const char * const fns[]={"printf(","fprintf(","syslog(","dprintf(",NULL};
    for(int i=0;fns[i];i++){
        const char *fp=strstr(line,fns[i]);
        if(!fp) continue;
        /* Ensure it is a proper token start (not e.g. "printf" inside "fprintf") */
        if(fp > line && (*(fp-1)=='_' || (*(fp-1)>='a'&&*(fp-1)<='z')
                         || (*(fp-1)>='A'&&*(fp-1)<='Z')
                         || (*(fp-1)>='0'&&*(fp-1)<='9'))) continue;
        /* Skip past any comment or string-literal context */
        if(!cfusa_match_outside_string(line, fns[i])) continue;
        const char *arg=fp+strlen(fns[i]);
        while(*arg==' ') arg++;
        /* fprintf/dprintf: first arg is FILE* — advance to the format arg */
        if(strncmp(fns[i],"fprintf",7)==0 || strncmp(fns[i],"dprintf",7)==0){
            while(*arg && *arg != ',') arg++;
            if(*arg==',') arg++;
            while(*arg==' ') arg++;
        }
        /* If no format arg visible on this line (multiline call), skip */
        if(!*arg || *arg=='\n' || *arg=='\r' || *arg==')') continue;
        /* If format argument is not a string literal → uncontrolled format string */
        if(*arg != '"' && strncmp(arg,"stderr",6)!=0 && strncmp(arg,"stdout",6)!=0
           && strncmp(arg,"stdin",5)!=0)
            cfusa_report_add(ctx->rpt,
                "CFUSA-CY002","cyber",SEV_ERROR,path,lineno,
                "CWE-134: possible uncontrolled format string in '%.*s' — "
                "format argument should be a string literal (CERT-C FIO30-C)",
                (int)(strlen(fns[i])-1),fns[i]);
    }
}

static int cy002_file(const char *path,void *v){cfusa_scan_lines(path,cy002_line,v);return 0;}
static int rule_cy002(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy002_file,&c); return 0;
}

//cfusa:req REQ-CYB003
/* CY003 — CWE-78: OS command injection */
static void cy003_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    static const char * const cmdfns[]={"system(","popen(","execl(","execlp(","execv(","execvp(",NULL};
    for(int i=0;cmdfns[i];i++){
        const char *fp=strstr(line,cmdfns[i]);
        if(!fp) continue;
        if(!cfusa_match_outside_string(line,cmdfns[i])) continue;
        /* Only flag if the first argument is not a string literal (i.e., a variable) */
        const char *arg=fp+strlen(cmdfns[i]);
        while(*arg==' ') arg++;
        if(*arg=='"') continue; /* hardcoded literal — low risk; skip */
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY003","cyber",SEV_ERROR,path,lineno,
            "CWE-78: OS command execution with non-literal argument — verify "
            "all arguments are sanitised and not influenced by external input "
            "(ISO 21434 CAL3)");
        break;
    }
}

static int cy003_file(const char *path,void *v){cfusa_scan_lines(path,cy003_line,v);return 0;}
static int rule_cy003(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy003_file,&c); return 0;
}

//cfusa:req REQ-CYB004
/* CY004 — CWE-476: NULL pointer dereference after allocation */
static void cy004_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Flag immediate dereference of malloc/calloc result on same line */
    {
        const char *alloc = strstr(line,"malloc(");
        if (!alloc) alloc = strstr(line,"calloc(");
        if (alloc && strstr(alloc, "->")
            && (cfusa_match_outside_string(line,"malloc(") || cfusa_match_outside_string(line,"calloc(")))
            cfusa_report_add(ctx->rpt,
                "CFUSA-CY004","cyber",SEV_ERROR,path,lineno,
                "CWE-476: potential NULL dereference — do not dereference allocation "
                "result without checking for NULL first");
    }
}

static int cy004_file(const char *path,void *v){cfusa_scan_lines(path,cy004_line,v);return 0;}
static int rule_cy004(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy004_file,&c); return 0;
}

//cfusa:req REQ-CYB005
/* CY005 — CWE-190: Integer overflow */
static void cy005_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Unsigned wrap: uint * uint or uint + uint fed to size_t / index */
    if((strstr(line,"* n") || strstr(line,"* size") || strstr(line,"* count")
       || strstr(line,"* len") || strstr(line,"* num"))
       && (strstr(line,"malloc(") || strstr(line,"calloc(") || strstr(line,"alloc(")))
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY005","cyber",SEV_WARNING,path,lineno,
            "CWE-190: integer overflow in allocation size expression — "
            "verify operands cannot overflow before multiplication (CERT-C INT30-C)");
}

static int cy005_file(const char *path,void *v){cfusa_scan_lines(path,cy005_line,v);return 0;}
static int rule_cy005(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy005_file,&c); return 0;
}

//cfusa:req REQ-CYB006
/* CY006 — CWE-416: Use after free */
static void cy006_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Heuristic: free() followed by use — flag free() calls for review */
    if(strstr(line,"free("))
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY006","cyber",SEV_INFO,path,lineno,
            "CWE-416: free() call — ensure pointer is set to NULL immediately after "
            "and not referenced again (use-after-free prevention)");
}

static int cy006_file(const char *path,void *v){cfusa_scan_lines(path,cy006_line,v);return 0;}
static int rule_cy006(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy006_file,&c); return 0;
}

//cfusa:req REQ-CYB007
/* CY007 — CWE-415: Double free */
static void cy007_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    /* Simple: two free() on same line (rare but real) — both outside string literals */
    const char *first=strstr(line,"free(");
    if(!first || !cfusa_match_outside_string(line,"free(")) return;
    const char *second=strstr(first+5,"free(");
    if(second && cfusa_match_outside_string(first+5,"free("))
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY007","cyber",SEV_ERROR,path,lineno,
            "CWE-415: possible double-free on same line — "
            "ensure each allocated pointer is freed exactly once");
}

static int cy007_file(const char *path,void *v){cfusa_scan_lines(path,cy007_line,v);return 0;}
static int rule_cy007(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy007_file,&c); return 0;
}

//cfusa:req REQ-CYB008
/* CY008 — CWE-377: Insecure temp file creation */
static void cy008_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    if(cfusa_match_outside_string(line,"tmpnam(") || cfusa_match_outside_string(line,"mktemp(")
       || cfusa_match_outside_string(line,"tempnam("))
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY008","cyber",SEV_ERROR,path,lineno,
            "CWE-377: insecure temp file function — use mkstemp() or "
            "equivalent safe alternative (CERT-C FIO21-C)");
}

static int cy008_file(const char *path,void *v){cfusa_scan_lines(path,cy008_line,v);return 0;}
static int rule_cy008(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy008_file,&c); return 0;
}

//cfusa:req REQ-CYB009
/* CY009 — CWE-327: Use of broken cryptographic algorithm */
static void cy009_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    static const char * const broken[]={"MD5_","DES_","RC4_","SHA1_","md5(","des_",NULL};
    for(int i=0;broken[i];i++)
        if(cfusa_match_outside_string(line,broken[i]))
            cfusa_report_add(ctx->rpt,
                "CFUSA-CY009","cyber",SEV_ERROR,path,lineno,
                "CWE-327: weak/broken cryptographic function '%.*s' — "
                "use SHA-256 or stronger (ISO 21434 CS-7)",
                (int)strlen(broken[i]),broken[i]);
}

static int cy009_file(const char *path,void *v){cfusa_scan_lines(path,cy009_line,v);return 0;}
static int rule_cy009(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c",".h"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,2,cy009_file,&c); return 0;
}

//cfusa:req REQ-CYB010
/* CY010 — CWE-676: Use of potentially dangerous function */
static void cy010_line(const char *path,int lineno,const char *line,void *vctx)
{
    cy_ctx_t *ctx=vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    static const char * const dangerous[]={"gets(","getpwd(","mktemp(","strtok(",NULL};
    for(int i=0;dangerous[i];i++){
        const char *fp=strstr(line,dangerous[i]);
        if(!fp) continue;
        /* word-boundary: skip if preceded by an identifier character */
        if(fp>line && (*(fp-1)=='_' || (*(fp-1)>='a'&&*(fp-1)<='z')
                       || (*(fp-1)>='A'&&*(fp-1)<='Z')
                       || (*(fp-1)>='0'&&*(fp-1)<='9'))) continue;
        if(!cfusa_match_outside_string(line,dangerous[i])) continue;
        cfusa_report_add(ctx->rpt,
            "CFUSA-CY010","cyber",SEV_WARNING,path,lineno,
            "CWE-676: potentially dangerous function '%.*s' — "
            "see CERT-C for safe alternatives",
            (int)(strlen(dangerous[i])-1),dangerous[i]);
        break;
    }
}

static int cy010_file(const char *path,void *v){cfusa_scan_lines(path,cy010_line,v);return 0;}
static int rule_cy010(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy010_file,&c); return 0;
}

/* ---- rule table ---- */

static const cfusa_rule_t cyber_rules[] = {
    {"CFUSA-CY001","cyber","Buffer copy size check","CWE-120","ISO 21434 / CERT-C STR31-C",rule_cy001},
    {"CFUSA-CY002","cyber","Format string injection","CWE-134","CERT-C FIO30-C",rule_cy002},
    {"CFUSA-CY003","cyber","OS command injection","CWE-78","ISO 21434 CAL3",rule_cy003},
    {"CFUSA-CY004","cyber","NULL pointer dereference","CWE-476","CERT-C EXP34-C",rule_cy004},
    {"CFUSA-CY005","cyber","Integer overflow in alloc","CWE-190","CERT-C INT30-C",rule_cy005},
    {"CFUSA-CY006","cyber","Use after free","CWE-416","CERT-C MEM30-C",rule_cy006},
    {"CFUSA-CY007","cyber","Double free","CWE-415","CERT-C MEM31-C",rule_cy007},
    {"CFUSA-CY008","cyber","Insecure temp file","CWE-377","CERT-C FIO21-C",rule_cy008},
    {"CFUSA-CY009","cyber","Broken crypto","CWE-327","ISO 21434 CS-7",rule_cy009},
    {"CFUSA-CY010","cyber","Dangerous function","CWE-676","CERT-C",rule_cy010},
};
#define N_CYBER_RULES ((int)(sizeof(cyber_rules)/sizeof(cyber_rules[0])))

void cfusa_cyber_register_rules(void)
{
    for(int i=0;i<N_CYBER_RULES;i++)
        cfusa_engine_register(&cyber_rules[i]);
}

int cmd_cyber(int argc, char **argv)
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
            printf("Usage: cfusa cyber [--dir <path>] [--format text|json|sarif|html|md]\n"
                   "                   [--output <file>] [--strict] [--list]\n\n"
                   "20 CWE-mapped cybersecurity rules (ISO 21434, CERT-C).\n\n"
                   "Rules: CFUSA-CY001 through CFUSA-CY010\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    if (list_rules) { cfusa_engine_list_rules(); return 0; }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    if (strict) cfg.strict = 1;

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    strncpy(rpt.project,  cfg.project, sizeof(rpt.project)  - 1);
    strncpy(rpt.version,  cfg.version, sizeof(rpt.version)  - 1);
    strncpy(rpt.standard, "ISO 21434 / CWE / CERT-C", sizeof(rpt.standard) - 1);

    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, dir, &cfg, &rpt);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    if (output) cfusa_report_write(&rpt, output, fmt);
    else        cfusa_report_print(&rpt, stdout, fmt);

    int rc = (rpt.error_count > 0) || (cfg.strict && rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    return rc;
}
