#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "cfusa/report.h"
#include "cfusa/utils.h"

#define INITIAL_CAPACITY 256

void cfusa_report_init(cfusa_report_t *rpt)
{
    memset(rpt, 0, sizeof(*rpt));
    rpt->findings = calloc(INITIAL_CAPACITY, sizeof(cfusa_finding_t));
    rpt->capacity = INITIAL_CAPACITY;
    cfusa_timestamp_now(rpt->timestamp);
}

void cfusa_report_free(cfusa_report_t *rpt)
{
    free(rpt->findings);
    rpt->findings = NULL;
    rpt->count = rpt->capacity = 0;
}

void cfusa_report_add(cfusa_report_t *rpt, const char *rule_id,
                       const char *category, cfusa_severity_t sev,
                       const char *file, int line,
                       const char *fmt, ...)
{
    if (rpt->count >= rpt->capacity) {
        int newcap = rpt->capacity * 2;
        rpt->findings = realloc(rpt->findings,
                                (size_t)newcap * sizeof(cfusa_finding_t));
        rpt->capacity = newcap;
    }
    cfusa_finding_t *f = &rpt->findings[rpt->count++];
    memset(f, 0, sizeof(*f));
    strncpy(f->rule_id,  rule_id,  sizeof(f->rule_id)  - 1);
    strncpy(f->category, category, sizeof(f->category) - 1);
    strncpy(f->file,     file,     sizeof(f->file)     - 1);
    f->line     = line;
    f->severity = sev;

    va_list ap;
    va_start(ap, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vsnprintf(f->message, sizeof(f->message), fmt, ap);
#pragma clang diagnostic pop
    va_end(ap);

    switch (sev) {
    case SEV_ERROR:   rpt->error_count++;   break;
    case SEV_WARNING: rpt->warning_count++; break;
    case SEV_INFO:    rpt->info_count++;    break;
    }
}

const char *cfusa_severity_str(cfusa_severity_t sev)
{
    switch (sev) {
    case SEV_ERROR:   return "ERROR";
    case SEV_WARNING: return "WARNING";
    case SEV_INFO:    return "INFO";
    }
    return "UNKNOWN";
}

cfusa_format_t cfusa_format_parse(const char *s)
{
    if (!s)               return FMT_TEXT;
    if (!strcmp(s, "json"))  return FMT_JSON;
    if (!strcmp(s, "sarif")) return FMT_SARIF;
    if (!strcmp(s, "html"))  return FMT_HTML;
    if (!strcmp(s, "md") || !strcmp(s, "markdown")) return FMT_MD;
    if (!strcmp(s, "csv")) return FMT_CSV;
    return FMT_TEXT;
}

double cfusa_report_score(const cfusa_report_t *rpt)
{
    if (rpt->count == 0) return 100.0;
    double penalty = (rpt->error_count * 10.0) + (rpt->warning_count * 2.0)
                   + (rpt->info_count  * 0.5);
    double score = 100.0 - penalty;
    return score < 0.0 ? 0.0 : score;
}

/* ---- TEXT output ---- */
static void print_text(const cfusa_report_t *rpt, FILE *out)
{
    fprintf(out, "cfusa report  project=%s  version=%s  ts=%s\n",
            rpt->project, rpt->version, rpt->timestamp);
    fprintf(out, "standard: %s\n", rpt->standard[0] ? rpt->standard : "(none)");
    fprintf(out, "score: %.1f/100  errors=%d  warnings=%d  info=%d\n\n",
            cfusa_report_score(rpt),
            rpt->error_count, rpt->warning_count, rpt->info_count);

    for (int i = 0; i < rpt->count; i++) {
        const cfusa_finding_t *f = &rpt->findings[i];
        fprintf(out, "[%s] %s  %s:%d\n  %s\n",
                cfusa_severity_str(f->severity), f->rule_id,
                f->file[0] ? f->file : ".", f->line, f->message);
    }
    if (rpt->count == 0)
        fprintf(out, "No findings.\n");
}

/* ---- JSON output ---- */
static void print_json(const cfusa_report_t *rpt, FILE *out)
{
    char esc_proj[256], esc_ts[64], esc_std[256];
    cfusa_str_escape_json(rpt->project,   esc_proj, sizeof(esc_proj));
    cfusa_str_escape_json(rpt->timestamp, esc_ts,   sizeof(esc_ts));
    cfusa_str_escape_json(rpt->standard,  esc_std,  sizeof(esc_std));

    fprintf(out,
        "{\n"
        "  \"project\": \"%s\",\n"
        "  \"version\": \"%s\",\n"
        "  \"timestamp\": \"%s\",\n"
        "  \"standard\": \"%s\",\n"
        "  \"score\": %.1f,\n"
        "  \"summary\": {\"errors\": %d, \"warnings\": %d, \"info\": %d},\n"
        "  \"findings\": [\n",
        esc_proj, rpt->version, esc_ts, esc_std,
        cfusa_report_score(rpt),
        rpt->error_count, rpt->warning_count, rpt->info_count);

    for (int i = 0; i < rpt->count; i++) {
        const cfusa_finding_t *f = &rpt->findings[i];
        char esc_file[512], esc_msg[768];
        cfusa_str_escape_json(f->file,    esc_file, sizeof(esc_file));
        cfusa_str_escape_json(f->message, esc_msg,  sizeof(esc_msg));
        fprintf(out,
            "    {\"rule_id\": \"%s\", \"category\": \"%s\","
            " \"severity\": \"%s\","
            " \"file\": \"%s\", \"line\": %d,"
            " \"message\": \"%s\"}%s\n",
            f->rule_id, f->category,
            cfusa_severity_str(f->severity),
            esc_file, f->line, esc_msg,
            (i < rpt->count - 1) ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
}

/* ---- SARIF 2.1.0 output ---- */
static void print_sarif(const cfusa_report_t *rpt, FILE *out)
{
    fprintf(out,
        "{\n"
        "  \"version\": \"2.1.0\",\n"
        "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n"
        "  \"runs\": [{\n"
        "    \"tool\": {\"driver\": {\"name\": \"cfusa\","
        " \"version\": \"%s\","
        " \"informationUri\": \"https://github.com/SoundMatt/c-FuSa\"}},\n"
        "    \"results\": [\n",
        rpt->version[0] ? rpt->version : "0.1.0");

    for (int i = 0; i < rpt->count; i++) {
        const cfusa_finding_t *f = &rpt->findings[i];
        const char *level =
            (f->severity == SEV_ERROR)   ? "error" :
            (f->severity == SEV_WARNING) ? "warning" : "note";
        char esc_file[512], esc_msg[768];
        cfusa_str_escape_json(f->file,    esc_file, sizeof(esc_file));
        cfusa_str_escape_json(f->message, esc_msg,  sizeof(esc_msg));
        fprintf(out,
            "      {\"ruleId\": \"%s\","
            " \"level\": \"%s\","
            " \"message\": {\"text\": \"%s\"},"
            " \"locations\": [{\"physicalLocation\":"
            " {\"artifactLocation\": {\"uri\": \"%s\"},"
            " \"region\": {\"startLine\": %d}}}]}%s\n",
            f->rule_id, level, esc_msg, esc_file, f->line,
            (i < rpt->count - 1) ? "," : "");
    }
    fprintf(out, "    ]\n  }]\n}\n");
}

/* ---- HTML output ---- */
static void print_html(const cfusa_report_t *rpt, FILE *out)
{
    fprintf(out,
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<title>cfusa report — %s</title>"
        "<style>body{font-family:sans-serif;max-width:900px;margin:2em auto}"
        "table{border-collapse:collapse;width:100%%}"
        "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}"
        "th{background:#f0f0f0}.ERROR{color:#c00}.WARNING{color:#960}"
        ".INFO{color:#066}.score{font-size:2em;font-weight:bold}</style>"
        "</head><body>\n"
        "<h1>cfusa — Safety Report</h1>"
        "<p><b>Project:</b> %s &nbsp; <b>Version:</b> %s &nbsp;"
        "<b>Generated:</b> %s</p>"
        "<p><b>Standard:</b> %s</p>"
        "<p class=\"score\">Score: %.1f / 100</p>"
        "<p>Errors: %d &nbsp; Warnings: %d &nbsp; Info: %d</p>\n",
        rpt->project, rpt->project, rpt->version,
        rpt->timestamp, rpt->standard[0] ? rpt->standard : "(none)",
        cfusa_report_score(rpt),
        rpt->error_count, rpt->warning_count, rpt->info_count);

    if (rpt->count == 0) {
        fprintf(out, "<p><b>No findings.</b></p>\n");
    } else {
        fprintf(out,
            "<table><tr><th>Severity</th><th>Rule</th><th>Category</th>"
            "<th>File</th><th>Line</th><th>Message</th></tr>\n");
        for (int i = 0; i < rpt->count; i++) {
            const cfusa_finding_t *f = &rpt->findings[i];
            fprintf(out,
                "<tr><td class=\"%s\">%s</td>"
                "<td>%s</td><td>%s</td><td>%s</td>"
                "<td>%d</td><td>%s</td></tr>\n",
                cfusa_severity_str(f->severity),
                cfusa_severity_str(f->severity),
                f->rule_id, f->category,
                f->file[0] ? f->file : ".",
                f->line, f->message);
        }
        fprintf(out, "</table>\n");
    }
    fprintf(out, "</body></html>\n");
}

/* ---- Markdown output ---- */
static void print_md(const cfusa_report_t *rpt, FILE *out)
{
    fprintf(out,
        "# cfusa Safety Report\n\n"
        "| Field | Value |\n|---|---|\n"
        "| Project | %s |\n"
        "| Version | %s |\n"
        "| Generated | %s |\n"
        "| Standard | %s |\n"
        "| Score | %.1f / 100 |\n"
        "| Errors | %d |\n"
        "| Warnings | %d |\n"
        "| Info | %d |\n\n",
        rpt->project, rpt->version, rpt->timestamp,
        rpt->standard[0] ? rpt->standard : "(none)",
        cfusa_report_score(rpt),
        rpt->error_count, rpt->warning_count, rpt->info_count);

    if (rpt->count == 0) {
        fprintf(out, "**No findings.**\n");
        return;
    }
    fprintf(out,
        "## Findings\n\n"
        "| Severity | Rule | Category | File | Line | Message |\n"
        "|---|---|---|---|---|---|\n");
    for (int i = 0; i < rpt->count; i++) {
        const cfusa_finding_t *f = &rpt->findings[i];
        fprintf(out, "| %s | %s | %s | %s | %d | %s |\n",
                cfusa_severity_str(f->severity),
                f->rule_id, f->category,
                f->file[0] ? f->file : ".",
                f->line, f->message);
    }
}

void cfusa_report_print(const cfusa_report_t *rpt, FILE *out, cfusa_format_t fmt)
{
    switch (fmt) {
    case FMT_JSON:  print_json(rpt, out);  break;
    case FMT_SARIF: print_sarif(rpt, out); break;
    case FMT_HTML:  print_html(rpt, out);  break;
    case FMT_MD:    print_md(rpt, out);    break;
    default:        print_text(rpt, out);  break;
    }
}

int cfusa_report_write(const cfusa_report_t *rpt, const char *path,
                        cfusa_format_t fmt)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        return -1;
    }
    cfusa_report_print(rpt, f, fmt);
    fclose(f);
    return 0;
}
