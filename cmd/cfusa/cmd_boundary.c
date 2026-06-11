#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Component dependency graph from #include directives */

#define MAX_INCLUDES 4096

typedef struct {
    char from[256];
    char to[128];
} include_edge_t;

static include_edge_t g_edges[MAX_INCLUDES];
static int            g_edge_count = 0;

static void boundary_line(const char *path, int lineno,
                            const char *line, void *vctx)
{
    (void)lineno; (void)vctx;
    if (g_edge_count >= MAX_INCLUDES) return;
    const char *p = line;
    while (*p==' '||*p=='\t') p++;
    if (strncmp(p,"#include",8)!=0) return;
    p+=8;
    while (*p==' '||*p=='\t') p++;
    /* Only local includes "..." not <...> */
    if (*p!='"') return;
    p++;
    char inc[128]="";
    int i=0;
    while (*p && *p!='"' && i<127) inc[i++]=*p++;
    inc[i]='\0';
    if (!inc[0]) return;
    strncpy(g_edges[g_edge_count].from, cfusa_basename(path), 255);
    strncpy(g_edges[g_edge_count].to,   inc, 127);
    g_edge_count++;
}

static int boundary_file(const char *path, void *v)
{
    cfusa_scan_lines(path, boundary_line, v); return 0;
}

static void write_mermaid(FILE *out)
{
    fprintf(out,"```mermaid\ngraph LR\n");
    for (int i = 0; i < g_edge_count; i++) {
        char from[256], to[128];
        strncpy(from, g_edges[i].from, 255); from[255] = '\0';
        strncpy(to,   g_edges[i].to,   127); to[127]   = '\0';
        for (char *p = from; *p; p++) if (*p=='.'||*p=='-') *p='_';
        for (char *p = to;   *p; p++) if (*p=='.'||*p=='-') *p='_';
        fprintf(out,"    %s --> %s\n", from, to);
    }
    fprintf(out,"```\n");
}

static void write_dot(FILE *out)
{
    fprintf(out,"digraph cfusa_deps {\n  rankdir=LR;\n");
    for (int i = 0; i < g_edge_count; i++)
        fprintf(out,"  \"%s\" -> \"%s\";\n", g_edges[i].from, g_edges[i].to);
    fprintf(out,"}\n");
}

int cmd_boundary(int argc, char **argv)
{
    const char *dir       = ".";
    const char *output    = NULL;
    const char *output_dir= NULL;
    const char *fmt_s     = NULL;  /* NULL = dual mermaid+dot (go-FuSa default) */

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"output",     required_argument, NULL, 'o'},
        {"output-dir", required_argument, NULL, 'D'},
        {"format",     required_argument, NULL, 'f'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:D:f:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir        = optarg; break;
        case 'o': output     = optarg; break;
        case 'D': output_dir = optarg; break;
        case 'f': fmt_s      = optarg; break;
        case 'h':
            printf("Usage: cfusa boundary [--dir <path>] [--format mermaid|dot|text]\n"
                   "                      [--output <file>] [--output-dir <dir>]\n\n"
                   "Generates a component dependency graph from #include directives.\n"
                   "Default: writes both boundary.mermaid and boundary.dot.\n");
            return 0;
        default: return 2;
        }
    }

    g_edge_count = 0;
    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, boundary_file, NULL);

    const char *base = output_dir ? output_dir : dir;

    if (!fmt_s && !output) {
        /* Default: write both boundary.mermaid and boundary.dot */
        char mpath[512], dpath[512];
        cfusa_path_join(mpath, sizeof(mpath), base, "boundary.mermaid");
        cfusa_path_join(dpath, sizeof(dpath), base, "boundary.dot");

        FILE *mf = fopen(mpath, "w");
        if (!mf) { perror(mpath); return 3; }
        write_mermaid(mf);
        fclose(mf);

        FILE *df = fopen(dpath, "w");
        if (!df) { perror(dpath); return 3; }
        write_dot(df);
        fclose(df);

        printf("boundary.mermaid written to %s  (%d edges)\n", mpath, g_edge_count);
        printf("boundary.dot     written to %s\n", dpath);
        return 0;
    }

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 3; } }

    if (fmt_s && !strcmp(fmt_s, "dot")) {
        write_dot(out);
    } else if (fmt_s && !strcmp(fmt_s, "text")) {
        fprintf(out, "Component dependency graph (%d edges)\n\n", g_edge_count);
        for (int i = 0; i < g_edge_count; i++)
            fprintf(out, "  %s  ->  %s\n", g_edges[i].from, g_edges[i].to);
    } else {
        write_mermaid(out);
    }

    if (output && out != stdout) fclose(out);
    return 0;
}
