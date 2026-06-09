#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Software Configuration Index — lists all source files with SHA-256 checksums */

typedef struct {
    FILE       *out;
    const char *fmt;   /* "text" or "md" or "json" */
    int         count;
    int         first;
} sci_ctx_t;

static int sci_file(const char *path, void *vctx)
{
    sci_ctx_t *ctx = vctx;
    char hex[65];
    cfusa_sha256_file(path, hex);

    if (!strcmp(ctx->fmt,"json")) {
        fprintf(ctx->out, "%s\n    {\"file\": \"%s\", \"sha256\": \"%s\"}",
                ctx->first ? "" : ",", path, hex);
        ctx->first = 0;
    } else if (!strcmp(ctx->fmt,"md")) {
        fprintf(ctx->out, "| %s | `%s` |\n", path, hex);
    } else {
        fprintf(ctx->out, "%-60s  %s\n", path, hex);
    }
    ctx->count++;
    return 0;
}

int cmd_sci(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = NULL;
    const char *fmt_s  = "text";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:f:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'h':
            printf("Usage: cfusa sci [--dir <path>] [--format text|md|json]\n"
                   "                  [--output <file>]\n\n"
                   "Generates a Software Configuration Index with SHA-256 checksums\n"
                   "for all C source files (DO-178C §11.16 / ISO 26262 Part 8).\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    FILE *out = stdout;
    if (output) { out = fopen(output,"w"); if (!out){perror(output);return 1;} }

    char ts[32]; cfusa_timestamp_now(ts);

    if (!strcmp(fmt_s,"json")) {
        fprintf(out, "{\n  \"project\": \"%s\", \"version\": \"%s\","
                " \"timestamp\": \"%s\",\n  \"files\": [",
                cfg.project, cfg.version, ts);
    } else if (!strcmp(fmt_s,"md")) {
        fprintf(out, "# Software Configuration Index\n\n"
                "**Project:** %s v%s  |  **Generated:** %s\n\n"
                "| File | SHA-256 |\n|---|---|\n",
                cfg.project, cfg.version, ts);
    } else {
        fprintf(out, "Software Configuration Index\n"
                "Project: %s v%s   Generated: %s\n\n"
                "%-60s  %s\n"
                "%-60s  %s\n",
                cfg.project, cfg.version, ts,
                "FILE","SHA-256",
                "------------------------------------------------------------",
                "----------------------------------------------------------------");
    }

    sci_ctx_t ctx = {out, fmt_s, 0, 1};
    static const char * const exts[] = {".c",".h"};
    cfusa_walk_sources(dir, exts, 2, sci_file, &ctx);

    if (!strcmp(fmt_s,"json"))
        fprintf(out, "\n  ],\n  \"total_files\": %d\n}\n", ctx.count);
    else if (!strcmp(fmt_s,"text"))
        fprintf(out, "\nTotal files: %d\n", ctx.count);
    else
        fprintf(out, "\n_Total files: %d_\n", ctx.count);

    if (output&&out!=stdout) fclose(out);
    return 0;
}
