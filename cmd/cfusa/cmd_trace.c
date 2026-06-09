#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/report.h"
#include "cfusa/utils.h"

/*
 * Scans source files for requirement annotation comments of the form:
 *   // REQ: SRS-001, SRS-002
 *   // REQ: SRS-003
 * and builds a traceability matrix.
 */

#define MAX_REQS    2048
#define MAX_REQ_ID  64

typedef struct {
    char req_id[MAX_REQ_ID];
    char file[256];
    int  line;
} trace_entry_t;

static trace_entry_t g_entries[MAX_REQS];
static int           g_entry_count = 0;

typedef struct {
    const char *prefix; /* e.g. "REQ:" */
} trace_scan_ctx_t;

static void trace_line(const char *path, int lineno, const char *line, void *vctx)
{
    trace_scan_ctx_t *ctx = vctx;
    const char *p = strstr(line, ctx->prefix);
    if (!p) return;
    p += strlen(ctx->prefix);
    while (*p == ' ' || *p == '\t') p++;

    /* Parse comma-separated IDs on this line */
    char buf[512];
    strncpy(buf, p, sizeof(buf) - 1);
    /* Strip trailing comment */
    char *end = strpbrk(buf, "*/\n");
    if (end) *end = '\0';

    char *tok = strtok(buf, ", \t");
    while (tok && g_entry_count < MAX_REQS) {
        char *t = cfusa_str_trim(tok);
        if (*t) {
            strncpy(g_entries[g_entry_count].req_id, t, MAX_REQ_ID - 1);
            strncpy(g_entries[g_entry_count].file,   path, 255);
            g_entries[g_entry_count].line = lineno;
            g_entry_count++;
        }
        tok = strtok(NULL, ", \t");
    }
}

static int trace_file(const char *path, void *vctx)
{
    cfusa_scan_lines(path, trace_line, vctx);
    return 0;
}

static int req_cmp(const void *a, const void *b)
{
    return strcmp(((const trace_entry_t *)a)->req_id,
                  ((const trace_entry_t *)b)->req_id);
}

int cmd_trace(int argc, char **argv)
{
    const char *dir    = ".";
    const char *prefix = "REQ:";
    const char *output = NULL;
    const char *fmt_s  = "text";
    int show_gaps      = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"prefix", required_argument, NULL, 'p'},
        {"output", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'f'},
        {"gaps",   no_argument,       NULL, 'g'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:p:o:f:gh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg; break;
        case 'p': prefix   = optarg; break;
        case 'o': output   = optarg; break;
        case 'f': fmt_s    = optarg; break;
        case 'g': show_gaps = 1;    break;
        case 'h':
            printf("Usage: cfusa trace [--dir <path>] [--prefix REQ:]\n"
                   "                   [--format text|json|md] [--output <file>]\n"
                   "                   [--gaps]\n\n"
                   "Scans C sources for '// REQ: ID, ID' annotations and generates\n"
                   "a requirements traceability matrix.\n"
                   "Use --gaps to list requirement IDs with no source coverage.\n");
            return 0;
        default: return 1;
        }
    }

    g_entry_count = 0;
    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    static const char * const exts[] = {".c", ".h"};
    trace_scan_ctx_t ctx = {prefix};
    cfusa_walk_sources(dir, exts, 2, trace_file, &ctx);

    qsort(g_entries, (size_t)g_entry_count, sizeof(trace_entry_t), req_cmp);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 1; } }

    if (fmt == FMT_JSON) {
        fprintf(out, "{\n  \"prefix\": \"%s\",\n  \"entries\": [\n", prefix);
        for (int i = 0; i < g_entry_count; i++) {
            fprintf(out, "    {\"req_id\": \"%s\", \"file\": \"%s\", \"line\": %d}%s\n",
                    g_entries[i].req_id, g_entries[i].file, g_entries[i].line,
                    (i < g_entry_count-1) ? "," : "");
        }
        fprintf(out, "  ]\n}\n");
    } else if (fmt == FMT_MD) {
        fprintf(out, "# Requirements Traceability Matrix\n\n");
        fprintf(out, "| Requirement | File | Line |\n|---|---|---|\n");
        for (int i = 0; i < g_entry_count; i++)
            fprintf(out, "| %s | %s | %d |\n",
                    g_entries[i].req_id, g_entries[i].file, g_entries[i].line);
    } else {
        fprintf(out, "Requirements Traceability Matrix  (prefix: %s)\n\n", prefix);
        fprintf(out, "%-24s  %-40s  %s\n", "REQUIREMENT", "FILE", "LINE");
        fprintf(out, "%-24s  %-40s  %s\n",
                "------------------------","----------------------------------------","----");
        for (int i = 0; i < g_entry_count; i++)
            fprintf(out, "%-24s  %-40s  %d\n",
                    g_entries[i].req_id,
                    cfusa_basename(g_entries[i].file),
                    g_entries[i].line);
        fprintf(out, "\nTotal traced references: %d\n", g_entry_count);

        if (show_gaps && g_entry_count == 0)
            fprintf(out, "\nNo requirement annotations found. "
                    "Annotate with '// %s ID' in source.\n", prefix);
    }

    if (output && out != stdout) fclose(out);
    return 0;
}
