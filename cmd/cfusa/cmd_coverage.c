#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Parses lcov .info files for line, function, and branch coverage */

typedef struct {
    long   lines_found;
    long   lines_hit;
    long   funcs_found;
    long   funcs_hit;
    long   branches_found;
    long   branches_hit;
    char   current_file[512];
    int    in_record;
} lcov_state_t;

static void parse_lcov(const char *path, lcov_state_t *s)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return; }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "SF:", 3) == 0) {
            strncpy(s->current_file, line + 3, sizeof(s->current_file) - 1);
            s->in_record = 1;
        } else if (strcmp(line, "end_of_record") == 0) {
            s->in_record = 0;
        } else if (strncmp(line, "LF:", 3) == 0) {
            s->lines_found += atol(line + 3);
        } else if (strncmp(line, "LH:", 3) == 0) {
            s->lines_hit += atol(line + 3);
        } else if (strncmp(line, "FNF:", 4) == 0) {
            s->funcs_found += atol(line + 4);
        } else if (strncmp(line, "FNH:", 4) == 0) {
            s->funcs_hit += atol(line + 4);
        } else if (strncmp(line, "BRF:", 4) == 0) {
            s->branches_found += atol(line + 4);
        } else if (strncmp(line, "BRH:", 4) == 0) {
            s->branches_hit += atol(line + 4);
        }
    }
    fclose(f);
}

static double pct(long hit, long found)
{
    if (found == 0) return 100.0;
    return (double)hit / (double)found * 100.0;
}

int cmd_coverage(int argc, char **argv)
{
    const char *dir      = ".";
    const char *lcov_in  = NULL;  /* lcov .info file */
    const char *fmt_s    = "text";
    const char *output   = NULL;
    double threshold     = 80.0;
    int    mcdc          = 0;

    static const struct option long_opts[] = {
        {"dir",       required_argument, NULL, 'd'},
        {"lcov",      required_argument, NULL, 'L'},
        {"format",    required_argument, NULL, 'f'},
        {"output",    required_argument, NULL, 'o'},
        {"threshold", required_argument, NULL, 't'},
        {"mcdc",      no_argument,       NULL, 'm'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:L:f:o:t:mh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir       = optarg;         break;
        case 'L': lcov_in   = optarg;         break;
        case 'f': fmt_s     = optarg;         break;
        case 'o': output    = optarg;         break;
        case 't': threshold = atof(optarg);   break;
        case 'm': mcdc      = 1;              break;
        case 'h':
            printf("Usage: cfusa coverage [--dir <path>] [--lcov <file.info>]\n"
                   "                      [--format text|json] [--output <file>]\n"
                   "                      [--threshold <pct>] [--mcdc]\n\n"
                   "Parses gcov/lcov output and reports statement, function, and\n"
                   "branch coverage. --mcdc flags decision coverage <100%%.\n"
                   "Generate lcov data with: lcov --capture --directory . -o coverage.info\n");
            return 0;
        default: return 1;
        }
    }

    /* Locate lcov file if not specified */
    char auto_path[512];
    if (!lcov_in) {
        cfusa_path_join(auto_path, sizeof(auto_path), dir, "coverage.info");
        if (!cfusa_file_exists(auto_path)) {
            cfusa_path_join(auto_path, sizeof(auto_path), dir, "lcov.info");
        }
        if (cfusa_file_exists(auto_path))
            lcov_in = auto_path;
    }

    if (!lcov_in || !cfusa_file_exists(lcov_in)) {
        fprintf(stderr, "cfusa coverage: no lcov .info file found.\n"
                "  Generate with: lcov --capture --directory %s -o coverage.info\n"
                "  Or specify:    cfusa coverage --lcov <file.info>\n", dir);
        return 1;
    }

    lcov_state_t state = {0};
    parse_lcov(lcov_in, &state);

    double line_pct   = pct(state.lines_hit,    state.lines_found);
    double func_pct   = pct(state.funcs_hit,    state.funcs_found);
    double branch_pct = pct(state.branches_hit, state.branches_found);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    FILE *out_f = stdout;
    if (output) { out_f = fopen(output, "w"); if (!out_f) { perror(output); return 1; } }

    if (fmt == FMT_JSON) {
        fprintf(out_f,
            "{\n"
            "  \"lcov_file\": \"%s\",\n"
            "  \"line_coverage\":     {\"hit\": %ld, \"found\": %ld, \"pct\": %.2f},\n"
            "  \"function_coverage\": {\"hit\": %ld, \"found\": %ld, \"pct\": %.2f},\n"
            "  \"branch_coverage\":   {\"hit\": %ld, \"found\": %ld, \"pct\": %.2f},\n"
            "  \"threshold\": %.1f,\n"
            "  \"passed\": %s\n"
            "}\n",
            lcov_in,
            state.lines_hit,    state.lines_found,    line_pct,
            state.funcs_hit,    state.funcs_found,    func_pct,
            state.branches_hit, state.branches_found, branch_pct,
            threshold,
            (line_pct >= threshold && func_pct >= threshold) ? "true" : "false");
    } else {
        fprintf(out_f, "Coverage report  source: %s\n\n", lcov_in);
        fprintf(out_f, "  Line      coverage: %6.2f%%  (%ld / %ld)\n",
                line_pct,   state.lines_hit,    state.lines_found);
        fprintf(out_f, "  Function  coverage: %6.2f%%  (%ld / %ld)\n",
                func_pct,   state.funcs_hit,    state.funcs_found);
        fprintf(out_f, "  Branch    coverage: %6.2f%%  (%ld / %ld)\n",
                branch_pct, state.branches_hit, state.branches_found);
        if (mcdc) {
            fprintf(out_f, "\n  MC/DC analysis: branch coverage %.2f%%", branch_pct);
            if (branch_pct < 100.0)
                fprintf(out_f, "  [FAIL — DO-178C requires 100%% for DAL A/B]");
            fprintf(out_f, "\n");
        }
        fprintf(out_f, "\n  Threshold: %.1f%%  Status: %s\n",
                threshold,
                (line_pct >= threshold && func_pct >= threshold) ? "PASS" : "FAIL");
    }

    if (output && out_f != stdout) fclose(out_f);

    return (line_pct < threshold || func_pct < threshold) ? 1 : 0;
}
