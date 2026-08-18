#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/disposition.h"

//cfusa:req REQ-CLI003 REQ-NOSUMMARY001
int cmd_check(int argc, char **argv)
{
    const char *dir    = ".";
    const char *fmt_s  = "text";
    const char *output = NULL;
    int strict = 0, no_summary = 0;

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"format",     required_argument, NULL, 'f'},
        {"output",     required_argument, NULL, 'o'},
        {"strict",     no_argument,       NULL, 's'},
        {"no-color",   no_argument,       NULL, 'C'},
        {"no-summary", no_argument,       NULL, 'S'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:f:o:sCSh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir        = optarg; break;
        case 'f': fmt_s      = optarg; break;
        case 'o': output     = optarg; break;
        case 's': strict     = 1;     break;
        case 'C': break; /* no-color: text output has no ANSI codes; accepted for spec compliance */
        case 'S': no_summary = 1;     break;
        case 'h':
            printf("Usage: cfusa check [--dir <path>] [--format text|json|sarif|html|md]\n"
                   "                   [--output <file>] [--strict] [--no-color] [--no-summary]\n\n"
                   "Runs all lint + analyze + cyber rules.\n"
                   "Exits 1 on any ERROR; with --strict, exits 1 on any WARNING too.\n"
                   "--no-summary suppresses the per-category and top-rules summary block.\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_analyze_register_rules();
    cfusa_cyber_register_rules();
    cfusa_safety_register_rules();

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    if (strict) cfg.strict = 1;

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    rpt.strict = cfg.strict; /* issue #164: printed Result must match the exit-code gate below */
    strncpy(rpt.project,  cfg.project, sizeof(rpt.project)  - 1);
    strncpy(rpt.version,  cfg.version, sizeof(rpt.version)  - 1);
    {
        char *abs = realpath(dir, NULL);
        if (abs) {
            strncpy(rpt.project_root, abs, sizeof(rpt.project_root) - 1);
            free(abs);
        } else {
            strncpy(rpt.project_root, dir, sizeof(rpt.project_root) - 1);
        }
    }

    /* Build standard string from config */
    char std_buf[128] = "";
    for (int i = 0; i < cfg.standards_count; i++) {
        if (i) strncat(std_buf, ", ", sizeof(std_buf) - strlen(std_buf) - 1);
        strncat(std_buf, cfg.standards[i], sizeof(std_buf) - strlen(std_buf) - 1);
    }
    strncpy(rpt.standard, std_buf, sizeof(rpt.standard) - 1);

    rpt.no_summary = no_summary;
    cfusa_engine_run_all(dir, &cfg, &rpt);

    //cfusa:req REQ-DISP-ENFORCE003
    /* issue #122: cross-reference findings against .fusa-dispositions.json
     * by fingerprint — an accept/mitigate-action disposition suppresses
     * its matching finding from error_count/warning_count (and so from
     * the exit-code gate below) without ever removing it from the
     * printed report. A missing dispositions file is not an error. */
    cfusa_disposition_list_t disps;
    if (!cfusa_dispositions_load(dir, &disps))
        fprintf(stderr, "cfusa check: WARNING: dispositions may be incomplete\n");
    cfusa_report_apply_dispositions(&rpt, &disps);
    cfusa_dispositions_free(&disps);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    if (output) {
        /* issue #141: a failed report write (bad --output path, permission
         * denied, disk full) used to be silently swallowed — the exit code
         * still came from finding counts alone, so CI gating on exit code
         * saw a green build with no compliance-report artifact ever
         * produced. Matches the exit-3 convention already used elsewhere
         * in this codebase (cmd_trace.c/cmd_coverage.c/cmd_fmea.c/
         * cmd_hara.c) for the identical fopen-for-write failure. */
        if (cfusa_report_write(&rpt, output, fmt) != 0) {
            cfusa_report_free(&rpt);
            return 3;
        }
    } else {
        cfusa_report_print(&rpt, stdout, fmt);
    }

    int rc = (rpt.error_count > 0) || (cfg.strict && rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    return rc;
}
