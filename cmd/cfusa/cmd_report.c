#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

int cmd_report(int argc, char **argv)
{
    const char *dir    = ".";
    const char *fmt_s  = "text";
    const char *output = NULL;
    int strict = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"strict", no_argument,       NULL, 's'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:f:o:sh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 's': strict = 1;     break;
        case 'h':
            printf("Usage: cfusa report [--dir <path>] [--format text|json|sarif|html|md]\n"
                   "                    [--output <file>]\n\n"
                   "Runs all checks and produces a compliance report.\n"
                   "Use --format html for a browsable report.\n"
                   "Note: --strict is a usage error on report (use 'check' for gating).\n");
            return 0;
        default: return 1;
        }
    }

    /* §9.1: --strict on report is a usage error */
    if (strict) {
        fprintf(stderr, "cfusa report: --strict is invalid; use 'cfusa check --strict' for gating\n");
        return 2;
    }

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_analyze_register_rules();
    cfusa_cyber_register_rules();

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    strncpy(rpt.project, cfg.project, sizeof(rpt.project) - 1);
    strncpy(rpt.version, cfg.version, sizeof(rpt.version) - 1);
    {
        char *abs = realpath(dir, NULL);
        if (abs) {
            strncpy(rpt.project_root, abs, sizeof(rpt.project_root) - 1);
            free(abs);
        } else {
            strncpy(rpt.project_root, dir, sizeof(rpt.project_root) - 1);
        }
    }

    char std_buf[128] = "";
    for (int i=0; i<cfg.standards_count; i++) {
        if (i) strncat(std_buf,", ",sizeof(std_buf)-strlen(std_buf)-1);
        strncat(std_buf,cfg.standards[i],sizeof(std_buf)-strlen(std_buf)-1);
    }
    strncpy(rpt.standard, std_buf, sizeof(rpt.standard)-1);

    cfusa_engine_run_all(dir, &cfg, &rpt);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    if (output)
        cfusa_report_write(&rpt, output, fmt);
    else
        cfusa_report_print(&rpt, stdout, fmt);

    cfusa_report_free(&rpt);
    return 0;
}
