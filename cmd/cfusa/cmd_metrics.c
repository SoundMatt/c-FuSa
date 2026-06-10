#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * Safety metrics tracking over time.
 * Records snapshots of cfusa findings counts in .fusa-metrics.jsonl
 * (newline-delimited JSON, one record per snapshot).
 *
 * Subcommands: record, show
 */

#define METRICS_FILE        ".fusa-metrics.jsonl"
#define METRICS_FILE_LEGACY ".cfusa-metrics.jsonl"

static void do_record(const char *dir, int errors, int warnings, int infos,
                      const char *label)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, METRICS_FILE);

    char ts[32]; cfusa_timestamp_now(ts);

    char esc_label[128];
    cfusa_str_escape_json(label, esc_label, sizeof(esc_label));

    FILE *f = fopen(path, "a");
    if (!f) { perror(path); return; }

    fprintf(f,
        "{\"schemaVersion\":\"" CFUSA_SCHEMA_VERSION "\","
        "\"kind\":\"metrics-snapshot\","
        "\"tool\":\"c-FuSa\",\"toolVersion\":\"" CFUSA_VERSION_STRING "\","
        "\"language\":\"c\","
        "\"timestamp\":\"%s\",\"label\":\"%s\","
        "\"errors\":%d,\"warnings\":%d,\"info\":%d,"
        "\"total\":%d}\n",
        ts, esc_label, errors, warnings, infos,
        errors + warnings + infos);
    fclose(f);

    printf("Recorded snapshot: errors=%d warnings=%d info=%d  [%s]\n",
           errors, warnings, infos, ts);
}

static void do_show(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, METRICS_FILE);

    FILE *f = fopen(path, "r");
    if (!f) {
        /* legacy fallback */
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, METRICS_FILE_LEGACY);
        f = fopen(legacy, "r");
    }
    if (!f) {
        printf("No metrics recorded yet. Run 'cfusa metrics record --errors N ...' to start.\n");
        return;
    }

    printf("Safety Metrics History\n");
    printf("======================\n\n");
    printf("%-26s %-20s %8s %9s %6s %7s\n",
           "Timestamp", "Label", "Errors", "Warnings", "Info", "Total");
    printf("%-26s %-20s %8s %9s %6s %7s\n",
           "--------------------------", "--------------------",
           "--------", "---------", "------", "-------");

    int prev_errors = -1, prev_total = -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char ts[32]="", label[64]="";
        int errors=0, warnings=0, info_=0, total=0;
        char *p;
        if ((p = strstr(line, "\"timestamp\":")))  sscanf(p, "\"timestamp\":\"%31[^\"]", ts);
        if ((p = strstr(line, "\"label\":")))       sscanf(p, "\"label\":\"%63[^\"]", label);
        if ((p = strstr(line, "\"errors\":")))      sscanf(p, "\"errors\":%d", &errors);
        if ((p = strstr(line, "\"warnings\":")))    sscanf(p, "\"warnings\":%d", &warnings);
        if ((p = strstr(line, "\"info\":")))        sscanf(p, "\"info\":%d", &info_);
        if ((p = strstr(line, "\"total\":")))       sscanf(p, "\"total\":%d", &total);

        const char *trend = "  ";
        if (prev_total >= 0) {
            if (total < prev_total)      trend = " (-)";
            else if (total > prev_total) trend = " (+)";
        }

        char delta_e[8] = "";
        if (prev_errors >= 0 && errors != prev_errors)
            snprintf(delta_e, sizeof(delta_e), "%+d", errors - prev_errors);

        printf("%-26s %-20s %8d %9d %6d %7d%s%s\n",
               ts, label, errors, warnings, info_, total, trend, delta_e);

        prev_errors = errors;
        prev_total  = total;
    }
    fclose(f);
}

int cmd_metrics(int argc, char **argv)
{
    const char *subcmd   = "show";
    const char *dir      = ".";
    const char *label    = "manual";
    int         errors   = 0;
    int         warnings = 0;
    int         infos    = 0;

    static const struct option long_opts[] = {
        {"dir",      required_argument, NULL, 'd'},
        {"errors",   required_argument, NULL, 'e'},
        {"warnings", required_argument, NULL, 'w'},
        {"info",     required_argument, NULL, 'i'},
        {"label",    required_argument, NULL, 'l'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    if (argc >= 2 && argv[1][0] != '-') {
        subcmd = argv[1];
        argv++; argc--;
    }

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:e:w:i:l:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg;       break;
        case 'e': errors   = atoi(optarg); break;
        case 'w': warnings = atoi(optarg); break;
        case 'i': infos    = atoi(optarg); break;
        case 'l': label    = optarg;       break;
        case 'h':
            printf("Usage: cfusa metrics <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  record  --errors N --warnings N --info N [--label <tag>]\n"
                   "  show    Display metrics history\n\n"
                   "Metrics are appended to .fusa-metrics.jsonl\n\n"
                   "Example — record after cfusa check:\n"
                   "  cfusa check --dir src/ --format json --output report.json\n"
                   "  E=$(jq .summary.errors report.json)\n"
                   "  W=$(jq .summary.warnings report.json)\n"
                   "  cfusa metrics record --errors $E --warnings $W --label ci-build-123\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "record")) {
        do_record(dir, errors, warnings, infos, label);
    } else {
        do_show(dir);
    }

    return 0;
}
