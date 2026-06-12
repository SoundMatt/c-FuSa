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
 * Subcommands:
 *   record  — auto-collect from project artifacts, or supply counts manually
 *   show    — display history (--format text|json, --output <file>)
 */

#define METRICS_FILE        ".fusa-metrics.jsonl"
#define METRICS_FILE_LEGACY ".cfusa-metrics.jsonl"

/* ---- auto-collection helpers ---- */

/* Parse an integer field from a JSON fragment: "key": <int> */
static int json_int(const char *json, const char *key, int fallback)
{
    const char *p = strstr(json, key);
    if (!p) return fallback;
    p = strchr(p, ':');
    if (!p) return fallback;
    return atoi(p + 1);
}

/* Parse a double field: "key": <float> */
static double json_double(const char *json, const char *key, double fallback)
{
    const char *p = strstr(json, key);
    if (!p) return fallback;
    p = strchr(p, ':');
    if (!p) return fallback;
    return atof(p + 1);
}

/* Count findings by severity in check-report.json.
 * Supports both flat-array [{...}] and nested {"findings":[...]} formats. */
static void collect_check(const char *dir, int *errors, int *warnings, int *infos)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, "check-report.json");
    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) return;

    const char *p = json;
    while ((p = strstr(p, "\"severity\":"))) {
        p += 11;
        while (*p == ' ' || *p == '"') p++;
        if (strncmp(p, "ERROR",   5) == 0) (*errors)++;
        else if (strncmp(p, "WARNING", 7) == 0) (*warnings)++;
        else if (strncmp(p, "INFO",    4) == 0) (*infos)++;
    }
    free(json);
}

/* Parse coverage pct from coverage-report.json "lineCoverage":{"pct":N} */
static double collect_coverage(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, "coverage-report.json");
    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) return -1.0;

    double pct = -1.0;
    const char *lc = strstr(json, "\"lineCoverage\"");
    if (lc) {
        const char *pc = strstr(lc, "\"pct\"");
        if (pc) pct = json_double(pc, "\"pct\"", -1.0);
    }
    if (pct < 0.0)
        pct = json_double(json, "\"stmtPct\"", -1.0);

    free(json);
    return pct;
}

/* Parse totalRequirements / tracedRequirements / testedRequirements
 * from trace-matrix.json (coverage object) */
static void collect_trace(const char *dir,
                           int *total, int *traced, int *tested)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, "trace-matrix.json");
    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) return;

    const char *cov = strstr(json, "\"coverage\"");
    if (cov) {
        *total  = json_int(cov, "\"totalRequirements\"",  *total);
        *traced = json_int(cov, "\"tracedRequirements\"", *traced);
        *tested = json_int(cov, "\"testedRequirements\"", *tested);
    }
    free(json);
}

/* ---- record ---- */

static void do_record(const char *dir,
                      int  manual_errors, int  manual_warnings, int  manual_infos,
                      int  manual_mode,   const char *label)
{
    int errors = 0, warnings = 0, infos = 0;

    if (manual_mode) {
        errors   = manual_errors;
        warnings = manual_warnings;
        infos    = manual_infos;
    } else {
        collect_check(dir, &errors, &warnings, &infos);
    }

    int    total_reqs  = 0, traced_reqs  = 0, tested_reqs  = 0;
    double coverage_pct = -1.0;
    collect_trace(dir, &total_reqs, &traced_reqs, &tested_reqs);
    coverage_pct = collect_coverage(dir);

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
        "\"errorCount\":%d,\"warningCount\":%d,\"infoCount\":%d,"
        "\"totalRequirements\":%d,\"tracedRequirements\":%d,"
        "\"testedRequirements\":%d",
        ts, esc_label, errors, warnings, infos,
        total_reqs, traced_reqs, tested_reqs);

    if (coverage_pct >= 0.0)
        fprintf(f, ",\"coveragePct\":%.2f", coverage_pct);

    fprintf(f, "}\n");
    fclose(f);

    printf("Recorded: errors=%d warnings=%d info=%d reqs=%d traced=%d",
           errors, warnings, infos, total_reqs, traced_reqs);
    if (coverage_pct >= 0.0)
        printf(" coverage=%.1f%%", coverage_pct);
    printf("  [%s]\n", ts);
}

/* ---- show ---- */

typedef struct {
    char ts[32];
    char label[64];
    int  errors, warnings, info;
    int  total_reqs, traced_reqs, tested_reqs;
    double coverage_pct;
    int  has_coverage;
} snap_t;

#define MAX_SNAPS 4096

static int load_snapshots(const char *dir, snap_t *snaps, int cap)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, METRICS_FILE);
    FILE *f = fopen(path, "r");
    if (!f) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, METRICS_FILE_LEGACY);
        f = fopen(legacy, "r");
    }
    if (!f) return 0;

    int n = 0;
    char line[1024];
    while (n < cap && fgets(line, sizeof(line), f)) {
        snap_t *s = &snaps[n];
        memset(s, 0, sizeof(*s));
        char *p;
        if ((p = strstr(line, "\"timestamp\":")))
            sscanf(p, "\"timestamp\":\"%31[^\"]", s->ts);
        if ((p = strstr(line, "\"label\":")))
            sscanf(p, "\"label\":\"%63[^\"]", s->label);
        if ((p = strstr(line, "\"errorCount\":")))
            s->errors = json_int(p, "\"errorCount\"", 0);
        else if ((p = strstr(line, "\"errors\":")))
            s->errors = json_int(p, "\"errors\"", 0);
        if ((p = strstr(line, "\"warningCount\":")))
            s->warnings = json_int(p, "\"warningCount\"", 0);
        else if ((p = strstr(line, "\"warnings\":")))
            s->warnings = json_int(p, "\"warnings\"", 0);
        if ((p = strstr(line, "\"infoCount\":")))
            s->info = json_int(p, "\"infoCount\"", 0);
        else if ((p = strstr(line, "\"info\":")))
            s->info = json_int(p, "\"info\"", 0);
        if ((p = strstr(line, "\"totalRequirements\":")))
            s->total_reqs  = json_int(p, "\"totalRequirements\"",  0);
        if ((p = strstr(line, "\"tracedRequirements\":")))
            s->traced_reqs = json_int(p, "\"tracedRequirements\"", 0);
        if ((p = strstr(line, "\"testedRequirements\":")))
            s->tested_reqs = json_int(p, "\"testedRequirements\"", 0);
        if ((p = strstr(line, "\"coveragePct\":"))) {
            s->coverage_pct = json_double(p, "\"coveragePct\"", -1.0);
            s->has_coverage = (s->coverage_pct >= 0.0);
        }
        n++;
    }
    fclose(f);
    return n;
}

static void do_show(const char *dir, const char *fmt, FILE *out)
{
    snap_t *snaps = malloc(MAX_SNAPS * sizeof(snap_t));
    if (!snaps) { fprintf(stderr, "cfusa metrics show: out of memory\n"); return; }

    int n = load_snapshots(dir, snaps, MAX_SNAPS);

    if (!strcmp(fmt, "json")) {
        fprintf(out, "[\n");
        for (int i = 0; i < n; i++) {
            snap_t *s = &snaps[i];
            fprintf(out,
                "%s  {\"timestamp\":\"%s\",\"label\":\"%s\","
                "\"errorCount\":%d,\"warningCount\":%d,\"infoCount\":%d,"
                "\"totalRequirements\":%d,\"tracedRequirements\":%d,"
                "\"testedRequirements\":%d",
                i ? ",\n" : "",
                s->ts, s->label,
                s->errors, s->warnings, s->info,
                s->total_reqs, s->traced_reqs, s->tested_reqs);
            if (s->has_coverage)
                fprintf(out, ",\"coveragePct\":%.2f", s->coverage_pct);
            fprintf(out, "}");
        }
        fprintf(out, "\n]\n");
    } else {
        if (n == 0) {
            fprintf(out, "No metrics recorded. Run 'cfusa metrics record' to start.\n");
            free(snaps);
            return;
        }
        fprintf(out, "Safety Metrics History\n");
        fprintf(out, "======================\n\n");
        fprintf(out, "%-22s %-16s %6s %8s %6s %6s %6s %8s\n",
               "Timestamp", "Label", "ERR", "WARN", "INFO",
               "Reqs", "Traced", "Coverage");
        fprintf(out, "%-22s %-16s %6s %8s %6s %6s %6s %8s\n",
               "----------------------", "----------------",
               "------", "--------", "------",
               "------", "------", "--------");

        for (int i = 0; i < n; i++) {
            snap_t *s = &snaps[i];
            fprintf(out, "%-22s %-16s %6d %8d %6d %6d %6d",
                   s->ts, s->label,
                   s->errors, s->warnings, s->info,
                   s->total_reqs, s->traced_reqs);
            if (s->has_coverage)
                fprintf(out, " %7.1f%%", s->coverage_pct);
            else
                fprintf(out, "        -");
            fprintf(out, "\n");
        }
    }
    free(snaps);
}

/* ---- main entry point ---- */

int cmd_metrics(int argc, char **argv)
{
    const char *subcmd   = "show";
    const char *dir      = ".";
    const char *label    = "auto";
    const char *fmt      = "text";
    const char *output   = NULL;
    int         errors   = 0;
    int         warnings = 0;
    int         infos    = 0;
    int         manual_mode = 0;

    static const struct option long_opts[] = {
        {"dir",      required_argument, NULL, 'd'},
        {"errors",   required_argument, NULL, 'e'},
        {"warnings", required_argument, NULL, 'w'},
        {"info",     required_argument, NULL, 'i'},
        {"label",    required_argument, NULL, 'l'},
        {"format",   required_argument, NULL, 'f'},
        {"output",   required_argument, NULL, 'o'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    if (argc >= 2 && argv[1][0] != '-') {
        subcmd = argv[1];
        argv++; argc--;
    }

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:e:w:i:l:f:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg;       break;
        case 'e': errors   = atoi(optarg); manual_mode = 1; break;
        case 'w': warnings = atoi(optarg); manual_mode = 1; break;
        case 'i': infos    = atoi(optarg); manual_mode = 1; break;
        case 'l': label    = optarg;       break;
        case 'f': fmt      = optarg;       break;
        case 'o': output   = optarg;       break;
        case 'h':
            printf("Usage: cfusa metrics <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  record  Auto-collect from project artifacts, or supply manually:\n"
                   "            --errors N --warnings N --info N [--label <tag>]\n"
                   "          Auto-reads: check-report.json, trace-matrix.json,\n"
                   "                      coverage-report.json\n"
                   "  show    Display metrics history\n"
                   "            --format text|json  --output <file>\n\n"
                   "Metrics are appended to .fusa-metrics.jsonl\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "record")) {
        if (!manual_mode) label = "auto";
        do_record(dir, errors, warnings, infos, manual_mode, label);
    } else {
        FILE *out = stdout;
        if (output) {
            out = fopen(output, "w");
            if (!out) { perror(output); return 3; }
        }
        do_show(dir, fmt, out);
        if (output && out != stdout) fclose(out);
    }

    return 0;
}
