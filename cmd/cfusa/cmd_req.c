#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Shows all occurrences of a specific requirement ID in the source */

typedef struct {
    const char *req_id;
    const char *prefix;
    int         count;
} req_ctx_t;

static void req_line(const char *path, int lineno, const char *line, void *vctx)
{
    req_ctx_t *ctx = vctx;
    const char *p = strstr(line, ctx->prefix);
    if (!p) return;
    p += strlen(ctx->prefix);
    while (*p==' '||*p=='\t') p++;

    /* Check if our requirement ID appears after the prefix */
    char buf[512];
    strncpy(buf, p, sizeof(buf)-1);
    char *end = strpbrk(buf,"*/\n");
    if (end) *end='\0';

    char *tok = strtok(buf, ", \t");
    while (tok) {
        char *t = cfusa_str_trim(tok);
        if (!strcmp(t, ctx->req_id)) {
            printf("%s:%d  %s\n", path, lineno, cfusa_str_trim((char*)line));
            ctx->count++;
        }
        tok = strtok(NULL, ", \t");
    }
}

static int req_file(const char *path, void *v)
{
    cfusa_scan_lines(path, req_line, v); return 0;
}

int cmd_req(int argc, char **argv)
{
    const char *dir    = ".";
    const char *prefix = "REQ:";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"prefix", required_argument, NULL, 'p'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:p:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'p': prefix = optarg; break;
        case 'h':
            printf("Usage: cfusa req <REQ-ID> [--dir <path>] [--prefix REQ:]\n\n"
                   "Shows all source locations annotated with the given requirement ID.\n");
            return 0;
        default: return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr,"cfusa req: requirement ID required\n");
        return 1;
    }
    const char *req_id = argv[optind];

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    req_ctx_t ctx = {req_id, prefix, 0};
    static const char * const exts[]={".c",".h"};
    cfusa_walk_sources(dir, exts, 2, req_file, &ctx);

    if (ctx.count == 0)
        printf("No occurrences of '%s' found (prefix: %s).\n", req_id, prefix);
    else
        printf("\nTotal: %d occurrence(s)\n", ctx.count);

    return ctx.count == 0 ? 1 : 0;
}
