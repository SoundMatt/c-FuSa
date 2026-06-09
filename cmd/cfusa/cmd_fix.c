#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Auto-applies safe, mechanical fixes for a subset of findings.
 * Only fixes where the replacement is unambiguous are supported.
 */

typedef struct {
    const char *rule_id;
    const char *from;
    const char *to;
    const char *description;
} autofix_t;

static const autofix_t AUTOFIXES[] = {
    {"CFUSA-L005","#undef ","/* #undef ","Remove #undef (MISRA-C R20.5) — comment it out"},
    {"CFUSA-CY008","tmpnam(","/* FIXME: use mkstemp */ tmpnam(","Flag insecure tmpnam"},
    {NULL,NULL,NULL,NULL}
};

typedef struct {
    const autofix_t *fix;
    int dry_run;
    int count;
} fix_ctx_t;

static int fix_file(const char *path, void *vctx)
{
    fix_ctx_t *ctx = vctx;
    size_t len;
    char *content = cfusa_read_file(path, &len);
    if (!content) return 0;

    int changed = 0;
    /* Simple single-pass replacement */
    const char *from = ctx->fix->from;
    const char *to   = ctx->fix->to;
    size_t flen = strlen(from), tlen = strlen(to);
    size_t new_sz = len * 4 + 1;
    char *out = malloc(new_sz);
    if (!out) { free(content); return 0; }

    char *dst = out;
    const char *src = content;
    while (*src) {
        if (strncmp(src, from, flen)==0) {
            memcpy(dst, to, tlen);
            dst += tlen;
            src += flen;
            changed++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    if (changed && !ctx->dry_run) {
        FILE *f = fopen(path,"w");
        if (f) { fputs(out,f); fclose(f); }
    }
    if (changed)
        printf("%s  %s: %d replacement(s)%s\n",
               ctx->fix->rule_id, path, changed,
               ctx->dry_run?" [dry-run]":"");
    ctx->count += changed;
    free(content);
    free(out);
    return 0;
}

int cmd_fix(int argc, char **argv)
{
    const char *dir    = ".";
    const char *rule   = NULL;
    int dry_run = 0;

    static const struct option long_opts[] = {
        {"dir",     required_argument, NULL, 'd'},
        {"rule",    required_argument, NULL, 'r'},
        {"dry-run", no_argument,       NULL, 'n'},
        {"list",    no_argument,       NULL, 'l'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c, list=0;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:r:nlh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir     = optarg; break;
        case 'r': rule    = optarg; break;
        case 'n': dry_run = 1;     break;
        case 'l': list    = 1;     break;
        case 'h':
            printf("Usage: cfusa fix [--dir <path>] [--rule <RULE-ID>] [--dry-run] [--list]\n\n"
                   "Applies mechanical auto-fixes for supported rules.\n"
                   "Use --dry-run to preview changes without writing.\n");
            return 0;
        default: return 1;
        }
    }

    if (list) {
        printf("Auto-fixable rules:\n\n");
        for (int i=0; AUTOFIXES[i].rule_id; i++)
            printf("  %-18s  %s\n", AUTOFIXES[i].rule_id, AUTOFIXES[i].description);
        return 0;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    int total = 0;
    static const char * const exts[]={".c",".h"};
    for (int i=0; AUTOFIXES[i].rule_id; i++) {
        if (rule && strcmp(AUTOFIXES[i].rule_id, rule)!=0) continue;
        fix_ctx_t ctx = {&AUTOFIXES[i], dry_run, 0};
        cfusa_walk_sources(dir, exts, 2, fix_file, &ctx);
        total += ctx.count;
    }

    printf("\nTotal replacements: %d%s\n", total, dry_run?" (dry-run, no files modified)":"");
    return 0;
}
