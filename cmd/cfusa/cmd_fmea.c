#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Generates a design FMEA skeleton from exported function signatures */

#define MAX_FUNS 1024

typedef struct {
    char name[128];
    char file[256];
    int  line;
    char sig[256];
} fn_entry_t;

static fn_entry_t g_fns[MAX_FUNS];
static int        g_fn_count = 0;

static void fmea_line(const char *path, int lineno, const char *line, void *vctx)
{
    (void)vctx;
    if (g_fn_count >= MAX_FUNS) return;
    const char *p = line;
    /* Skip blank, preprocessor, and comment lines */
    while (*p==' '||*p=='\t') p++;
    if (!*p || *p=='/' || *p=='#' || *p=='*' || *p=='}') return;
    /* Look for function signatures: type name( — no leading keyword like if/for/while */
    static const char * const skip_kw[] = {
        "if ","for ","while ","switch ","return ","else ","case ","typedef ",
        "struct ","enum ","union ","static ","extern ","inline ",NULL
    };
    for (int i=0; skip_kw[i]; i++)
        if (strncmp(p, skip_kw[i], strlen(skip_kw[i]))==0) return;

    if (!strstr(line,"(") || !strstr(line,")")) return;
    /* Skip lines ending with ; — these are declarations, not definitions */
    const char *end = line + strlen(line);
    while (end>line && (end[-1]==' '||end[-1]=='\t'||end[-1]=='\n'||end[-1]=='\r')) end--;
    if (end>line && end[-1]==';') return;

    /* Extract function name */
    char *paren = strchr((char*)p, '(');
    if (!paren) return;
    char before[128]="";
    size_t bl=(size_t)(paren-p);
    if(bl==0||bl>=128) return;
    strncpy(before,p,bl); before[bl]='\0';
    char *sp=strrchr(before,' ');
    char *fn_name=sp?sp+1:before;
    while(*fn_name=='*') fn_name++;
    if(!*fn_name||strlen(fn_name)<2) return;

    strncpy(g_fns[g_fn_count].name, fn_name,     127);
    strncpy(g_fns[g_fn_count].file, path,         255);
    strncpy(g_fns[g_fn_count].sig,  p,            255);
    g_fns[g_fn_count].line = lineno;
    g_fn_count++;
}

static int fmea_file(const char *path, void *v)
{
    cfusa_scan_lines(path, fmea_line, v); return 0;
}

int cmd_fmea(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = "FMEA.md";
    int with_cyber     = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"cyber",  no_argument,       NULL, 'c'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:ch", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir        = optarg; break;
        case 'o': output     = optarg; break;
        case 'c': with_cyber = 1;      break;
        case 'h':
            printf("Usage: cfusa fmea [--dir <path>] [--output FMEA.md] [--cyber]\n\n"
                   "Generates a design FMEA skeleton from function signatures.\n"
                   "--cyber enriches entries with cybersecurity failure modes.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    g_fn_count = 0;

    static const char * const exts[]={".c"};
    cfusa_walk_sources(dir, exts, 1, fmea_file, NULL);

    char out_path[512];
    if (output[0]=='/') strncpy(out_path, output, sizeof(out_path)-1);
    else cfusa_path_join(out_path, sizeof(out_path), dir, output);

    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }

    char ts[32]; cfusa_timestamp_now(ts);

    fprintf(f,
        "# Design FMEA — %s v%s\n"
        "Generated: %s  |  Standard: IEC 60812 / ISO 26262 Part 5\n\n"
        "**Instructions:** For each function, identify failure modes and effects.\n"
        "Severity (S) / Occurrence (O) / Detection (D) rated 1–10; RPN = S×O×D.\n\n",
        cfg.project, cfg.version, ts);

    fprintf(f,
        "| ID | Function | File | Failure Mode | Effect | "
        "Cause | S | O | D | RPN | Action |");
    if (with_cyber)
        fprintf(f, " Cyber Failure Mode |");
    fprintf(f, "\n|---|---|---|---|---|---|---|---|---|---|---|");
    if (with_cyber)
        fprintf(f, "---|");
    fprintf(f, "\n");

    for (int i = 0; i < g_fn_count; i++) {
        fprintf(f, "| FM-%03d | `%s` | %s:%d | [describe] | [effect] | [cause] "
                   "| [1-10] | [1-10] | [1-10] | | [action] |",
                i+1, g_fns[i].name,
                cfusa_basename(g_fns[i].file), g_fns[i].line);
        if (with_cyber)
            fprintf(f, " [cyber failure mode] |");
        fprintf(f, "\n");
    }

    fprintf(f,
        "\n---\n"
        "_Total functions analysed: %d_  \n"
        "_Review: [name / date]_\n", g_fn_count);

    fclose(f);
    printf("FMEA skeleton written to %s  (%d functions)\n", out_path, g_fn_count);
    return 0;
}
