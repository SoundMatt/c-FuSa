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

//cfusa:req REQ-CYB019
/* CY011 — CWE-918: SSRF — URL/proxy from variable passed to curl */
static void cy011_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (!cfusa_match_outside_string(line, "curl_easy_setopt(")) return;
    if (!strstr(line, "CURLOPT_URL") && !strstr(line, "CURLOPT_PROXY")) return;
    /* Find third argument — if not a string literal, URL comes from a variable */
    const char *fp = strstr(line, "curl_easy_setopt(");
    const char *arg = fp + strlen("curl_easy_setopt(");
    int commas = 0;
    while (*arg && commas < 2) { if (*arg == ',') commas++; arg++; }
    while (*arg == ' ') arg++;
    if (*arg && *arg != '"')
        cfusa_report_add(ctx->rpt, "CFUSA-CY011", "cyber", SEV_WARNING, path, lineno,
            "CWE-918: curl URL/proxy from variable — validate or whitelist "
            "before use to prevent SSRF (ISO 21434 CS-10)");
}
static int cy011_file(const char *path,void *v){cfusa_scan_lines(path,cy011_line,v);return 0;}
static int rule_cy011(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy011_file,&c); return 0;
}

//cfusa:req REQ-CYB020
/* CY012 — CWE-489: Debug socket option left enabled */
static void cy012_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (cfusa_match_outside_string(line, "SO_DEBUG")
        && cfusa_match_outside_string(line, "setsockopt("))
        cfusa_report_add(ctx->rpt, "CFUSA-CY012", "cyber", SEV_WARNING, path, lineno,
            "CWE-489: SO_DEBUG socket option exposes internal TCP state — "
            "remove before production build");
}
static int cy012_file(const char *path,void *v){cfusa_scan_lines(path,cy012_line,v);return 0;}
static int rule_cy012(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy012_file,&c); return 0;
}

//cfusa:req REQ-CYB021
/* CY013 — CWE-23: Zip-slip — archive entry path used without sanitisation */
static void cy013_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (cfusa_match_outside_string(line, "archive_entry_pathname(")
        || cfusa_match_outside_string(line, "zip_entry_name(")
        || cfusa_match_outside_string(line, "unzGetCurrentFileInfo("))
        cfusa_report_add(ctx->rpt, "CFUSA-CY013", "cyber", SEV_WARNING, path, lineno,
            "CWE-23: archive entry path name — sanitise with realpath() and "
            "verify prefix before using in file operations (zip-slip risk)");
}
static int cy013_file(const char *path,void *v){cfusa_scan_lines(path,cy013_line,v);return 0;}
static int rule_cy013(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy013_file,&c); return 0;
}

//cfusa:req REQ-CYB022
/* CY014 — CWE-326: Weak/deprecated TLS method */
static void cy014_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    static const char * const weak_tls[] = {
        "SSLv3_method(", "SSLv3_client_method(", "SSLv3_server_method(",
        "TLSv1_method(", "TLSv1_client_method(", "TLSv1_server_method(",
        "TLSv1_1_method(", "TLSv1_1_client_method(", "TLSv1_1_server_method(",
        "SSLv23_method(", NULL
    };
    for (int i = 0; weak_tls[i]; i++) {
        if (cfusa_match_outside_string(line, weak_tls[i]))
            cfusa_report_add(ctx->rpt, "CFUSA-CY014", "cyber", SEV_ERROR, path, lineno,
                "CWE-326: deprecated TLS/SSL method — use TLS_method() with "
                "SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) (CERT-C MSC61-C)");
    }
}
static int cy014_file(const char *path,void *v){cfusa_scan_lines(path,cy014_line,v);return 0;}
static int rule_cy014(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c",".h"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,2,cy014_file,&c); return 0;
}

//cfusa:req REQ-CYB023
/* CY015 — CWE-89: SQL injection via sprintf */
static void cy015_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (!cfusa_match_outside_string(line, "sprintf(")
        && !cfusa_match_outside_string(line, "snprintf(")) return;
    if (!strstr(line, "%s")) return;
    static const char * const sql[] = {"SELECT","INSERT","UPDATE","DELETE","DROP",NULL};
    for (int i = 0; sql[i]; i++)
        if (strstr(line, sql[i]))
            cfusa_report_add(ctx->rpt, "CFUSA-CY015", "cyber", SEV_ERROR, path, lineno,
                "CWE-89: SQL query built with sprintf + %%s — use parameterised "
                "queries or prepared statements (CERT-C FIO30-C)");
}
static int cy015_file(const char *path,void *v){cfusa_scan_lines(path,cy015_line,v);return 0;}
static int rule_cy015(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy015_file,&c); return 0;
}

//cfusa:req REQ-CYB024
/* CY016 — CWE-732: Directory created with world-writable/readable mode */
static void cy016_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (!cfusa_match_outside_string(line, "mkdir(")) return;
    static const char * const bad_modes[] = {
        "0777","0776","0775","0773","0772","0771","0770",
        "0767","0766","0765","0764","0763","0762","0761","0760",NULL
    };
    for (int i = 0; bad_modes[i]; i++)
        if (strstr(line, bad_modes[i]))
            cfusa_report_add(ctx->rpt, "CFUSA-CY016", "cyber", SEV_WARNING, path, lineno,
                "CWE-732: directory mode more permissive than 0750 — "
                "world-readable or world-writable directories expose data (CERT-C FIO06-C)");
}
static int cy016_file(const char *path,void *v){cfusa_scan_lines(path,cy016_line,v);return 0;}
static int rule_cy016(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy016_file,&c); return 0;
}

//cfusa:req REQ-CYB025
/* CY017 — CWE-732: File created with world-readable/writable mode */
static void cy017_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    int has_open = cfusa_match_outside_string(line, "open(")
                || cfusa_match_outside_string(line, "creat(");
    if (!has_open) return;
    /* Flag modes more permissive than 0640 */
    static const char * const bad_modes[] = {
        "0666","0664","0662","0660","0646","0644","0642","0640",
        "0606","0604","0602","0600",NULL
    };
    /* Only flag modes with world-readable (o+r=04) or world-write (o+w=02) */
    static const char * const really_bad[] = {
        "0666","0664","0662","0646","0644","0642",
        "0606","0604","0602",NULL
    };
    (void)bad_modes;
    for (int i = 0; really_bad[i]; i++)
        if (strstr(line, really_bad[i]))
            cfusa_report_add(ctx->rpt, "CFUSA-CY017", "cyber", SEV_WARNING, path, lineno,
                "CWE-732: file mode more permissive than 0640 — world-readable "
                "or world-writable files may expose sensitive data (CERT-C FIO06-C)");
}
static int cy017_file(const char *path,void *v){cfusa_scan_lines(path,cy017_line,v);return 0;}
static int rule_cy017(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy017_file,&c); return 0;
}

//cfusa:req REQ-CYB026
/* CY018 — CWE-22: Path traversal — file path from argv/getenv */
static void cy018_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    int has_open = cfusa_match_outside_string(line, "fopen(")
                || cfusa_match_outside_string(line, "open(");
    if (!has_open) return;
    if (strstr(line, "argv[") || strstr(line, "getenv("))
        cfusa_report_add(ctx->rpt, "CFUSA-CY018", "cyber", SEV_ERROR, path, lineno,
            "CWE-22: file path from argv/getenv used directly in open — "
            "validate with realpath() and check prefix before use (path traversal)");
}
static int cy018_file(const char *path,void *v){cfusa_scan_lines(path,cy018_line,v);return 0;}
static int rule_cy018(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy018_file,&c); return 0;
}

//cfusa:req REQ-CYB027
/* CY019 — CWE-362: TOCTOU — access()/stat() check before open */
static void cy019_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (cfusa_match_outside_string(line, "access("))
        cfusa_report_add(ctx->rpt, "CFUSA-CY019", "cyber", SEV_WARNING, path, lineno,
            "CWE-362: access() check before open() creates TOCTOU race — "
            "use open() with O_CREAT|O_EXCL or fstat() on an open fd instead");
}
static int cy019_file(const char *path,void *v){cfusa_scan_lines(path,cy019_line,v);return 0;}
static int rule_cy019(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy019_file,&c); return 0;
}

//cfusa:req REQ-CYB028
/* CY020 — CWE-377: Hardcoded predictable /tmp path */
static void cy020_line(const char *path, int lineno, const char *line, void *vctx)
{
    cy_ctx_t *ctx = vctx;
    const char *p = line; while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (!cfusa_match_outside_string(line, "fopen(")) return;
    /* Flag fopen("/tmp/fixed_name", ...) — predictable temp path */
    const char *fp = strstr(line, "fopen(");
    if (!fp) return;
    const char *arg = fp + strlen("fopen(");
    while (*arg == ' ') arg++;
    if (*arg == '"' && strncmp(arg+1, "/tmp/", 5) == 0)
        cfusa_report_add(ctx->rpt, "CFUSA-CY020", "cyber", SEV_WARNING, path, lineno,
            "CWE-377: hardcoded /tmp path creates predictable temp file — "
            "use mkstemp() for safe temporary file creation (CERT-C FIO21-C)");
}
static int cy020_file(const char *path,void *v){cfusa_scan_lines(path,cy020_line,v);return 0;}
static int rule_cy020(const char *dir,const cfusa_config_t *cfg,cfusa_report_t *rpt)
{
    (void)cfg; static const char * const e[]={".c"}; cy_ctx_t c={rpt};
    cfusa_walk_sources(dir,e,1,cy020_file,&c); return 0;
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
    {"CFUSA-CY011","cyber","SSRF via curl URL variable","CWE-918","ISO 21434 CS-10",rule_cy011},
    {"CFUSA-CY012","cyber","Debug socket option exposed","CWE-489","CERT-C",rule_cy012},
    {"CFUSA-CY013","cyber","Archive path traversal (zip-slip)","CWE-23","CERT-C FIO02-C",rule_cy013},
    {"CFUSA-CY014","cyber","Weak/deprecated TLS method","CWE-326","CERT-C MSC61-C",rule_cy014},
    {"CFUSA-CY015","cyber","SQL injection via sprintf","CWE-89","CERT-C FIO30-C",rule_cy015},
    {"CFUSA-CY016","cyber","Permissive directory mode","CWE-732","CERT-C FIO06-C",rule_cy016},
    {"CFUSA-CY017","cyber","Permissive file mode","CWE-732","CERT-C FIO06-C",rule_cy017},
    {"CFUSA-CY018","cyber","Path traversal from argv/env","CWE-22","CERT-C FIO02-C",rule_cy018},
    {"CFUSA-CY019","cyber","TOCTOU race (access before open)","CWE-362","CERT-C FIO45-C",rule_cy019},
    {"CFUSA-CY020","cyber","Predictable /tmp path","CWE-377","CERT-C FIO21-C",rule_cy020},
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
                   "Rules: CFUSA-CY001 through CFUSA-CY020\n");
            return 0;
        default: return 2;
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

    printf("\nCyber findings: %d error  %d warning  %d info\n",
           rpt.error_count, rpt.warning_count, rpt.info_count);

    int rc = (rpt.error_count > 0) || (cfg.strict && rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    return rc;
}
