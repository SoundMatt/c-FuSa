/*
 * cfusa coupling — data and control coupling analysis (DO-178C §6.4.4.3).
 *
 * Data coupling:    extern variable declarations referencing another TU's globals.
 * Control coupling: function pointer parameters (flow controlled by caller).
 *
 * Writes coupling-report.json as evidence of coupling characterisation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

//cfusa:req REQ-COUP001 REQ-COUP002 REQ-COUP003

#define MAX_FINDINGS 512

typedef struct {
    char kind[16];   /* "data" or "control" */
    char file[256];
    int  line;
    char message[256];
} coupling_finding_t;

static coupling_finding_t g_findings[MAX_FINDINGS];
static int                g_count = 0;

static void add_finding(const char *kind, const char *file, int line,
                         const char *msg)
{
    if (g_count >= MAX_FINDINGS) return;
    coupling_finding_t *f = &g_findings[g_count++];
    strncpy(f->kind,    kind, sizeof(f->kind)    - 1);
    strncpy(f->file,    file, sizeof(f->file)    - 1);
    strncpy(f->message, msg,  sizeof(f->message) - 1);
    f->line = line;
}

static void scan_line(const char *path, int lineno, const char *line, void *v)
{
    (void)v;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;

    /* Data coupling: extern variable declaration (not a function prototype) */
    if (strncmp(p, "extern ", 7) == 0) {
        const char *rest = p + 7;
        /* Skip "extern void foo(..." — function prototypes, not data */
        const char *paren = strchr(rest, '(');
        const char *semi  = strchr(rest, ';');
        if (semi && (!paren || semi < paren)) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "data coupling: extern variable declaration accesses external state");
            add_finding("data", path, lineno, msg);
        }
    }

    /* Control coupling: function pointer parameter — pattern (*fn) or (*cb) */
    if (strchr(p, '(') && strstr(p, "(*") && strncmp(p, "typedef", 7) != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "control coupling: function pointer parameter passes flow control to caller");
        add_finding("control", path, lineno, msg);
    }
}

static int scan_file(const char *path, void *v)
{
    cfusa_scan_lines(path, scan_line, v);
    return 0;
}

static void write_json(FILE *out, const char *project, const char *ts,
                        int data_n, int ctrl_n)
{
    fprintf(out,
        "{\n"
        "  \"format\": \"c-FuSa Coupling Report v1\",\n"
        "  \"generatedAt\": \"%s\",\n"
        "  \"project\": \"%s\",\n"
        "  \"dataCoupling\": [\n", ts, project);

    int first = 1;
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_findings[i].kind, "data") != 0) continue;
        if (!first) fprintf(out, ",\n");
        char ef[512], em[512];
        cfusa_str_escape_json(g_findings[i].file,    ef, sizeof(ef));
        cfusa_str_escape_json(g_findings[i].message, em, sizeof(em));
        fprintf(out,
            "    {\"file\": \"%s\", \"line\": %d, \"message\": \"%s\"}",
            ef, g_findings[i].line, em);
        first = 0;
    }
    fprintf(out, "\n  ],\n  \"controlCoupling\": [\n");

    first = 1;
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_findings[i].kind, "control") != 0) continue;
        if (!first) fprintf(out, ",\n");
        char ef[512], em[512];
        cfusa_str_escape_json(g_findings[i].file,    ef, sizeof(ef));
        cfusa_str_escape_json(g_findings[i].message, em, sizeof(em));
        fprintf(out,
            "    {\"file\": \"%s\", \"line\": %d, \"message\": \"%s\"}",
            ef, g_findings[i].line, em);
        first = 0;
    }
    fprintf(out, "\n  ]\n}\n");
    (void)data_n; (void)ctrl_n;
}

int cmd_coupling(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = NULL;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa coupling [--dir <path>] [--output <file>]\n\n"
                   "Analyse data and control coupling in C source (DO-178C §6.4.4.3).\n"
                   "Writes coupling-report.json as evidence of coupling characterisation.\n\n"
                   "  Data coupling:    extern variable declarations\n"
                   "  Control coupling: function pointer parameters\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    g_count = 0;

    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, scan_file, NULL);

    int data_n = 0, ctrl_n = 0;
    for (int i = 0; i < g_count; i++) {
        if (!strcmp(g_findings[i].kind, "data"))    data_n++;
        else                                         ctrl_n++;
    }

    char ts[32]; cfusa_timestamp_now(ts);

    char out_path[512];
    if (output) {
        strncpy(out_path, output, sizeof(out_path) - 1);
    } else {
        cfusa_path_join(out_path, sizeof(out_path), dir, "coupling-report.json");
    }

    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }
    write_json(f, cfg.project, ts, data_n, ctrl_n);
    fclose(f);

    printf("Coupling report written to %s (%d data, %d control)\n",
           out_path, data_n, ctrl_n);
    return 0;
}
