#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "cfusa/report.h"
#include "cfusa/engine.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

#define INITIAL_CAPACITY 256

//cfusa:req REQ-RPT001 REQ-RPT002 REQ-RPT003 REQ-RPT004 REQ-RPT005 REQ-RPT006 REQ-RPT007
void cfusa_report_init(cfusa_report_t *rpt)
{
    memset(rpt, 0, sizeof(*rpt));
    rpt->findings = calloc(INITIAL_CAPACITY, sizeof(cfusa_finding_t));
    if (!rpt->findings) {
        fprintf(stderr, "cfusa: out of memory initialising report\n");
        rpt->capacity = 0;
        return;
    }
    rpt->capacity = INITIAL_CAPACITY;
    cfusa_timestamp_now(rpt->timestamp);
}

void cfusa_report_free(cfusa_report_t *rpt)
{
    free(rpt->findings);
    rpt->findings = NULL;
    rpt->count = rpt->capacity = 0;
}

/* Spec §4.2: replace digit runs with '#', collapse whitespace, trim ends. */
static void cfusa_normalize_msg(const char *msg, char *out, size_t out_max)
{
    if (out_max == 0) return;
    size_t wi = 0;
    int in_space = 1; /* treat leading content as after-whitespace so it is trimmed */
    for (const char *p = msg; *p && wi < out_max - 1; p++) {
        if (isdigit((unsigned char)*p)) {
            if (in_space && wi > 0) { out[wi++] = ' '; if (wi >= out_max - 1) break; }
            if (wi == 0 || out[wi - 1] != '#') out[wi++] = '#';
            while (isdigit((unsigned char)*(p + 1))) p++;
            in_space = 0;
        } else if (isspace((unsigned char)*p)) {
            in_space = 1;
        } else {
            if (in_space && wi > 0) { out[wi++] = ' '; if (wi >= out_max - 1) break; }
            out[wi++] = *p;
            in_space = 0;
        }
    }
    out[wi] = '\0';
}

void cfusa_report_add(cfusa_report_t *rpt, const char *rule_id,
                       const char *category, cfusa_severity_t sev,
                       const char *file, int line,
                       const char *fmt, ...)
{
    if (rpt->count >= rpt->capacity) {
        int newcap = rpt->capacity > 0 ? rpt->capacity * 2 : INITIAL_CAPACITY;
        cfusa_finding_t *tmp = realloc(rpt->findings,
                                       (size_t)newcap * sizeof(cfusa_finding_t));
        if (!tmp) {
            fprintf(stderr, "cfusa: out of memory growing report\n");
            return;
        }
        rpt->findings = tmp;
        rpt->capacity = newcap;
    }
    cfusa_finding_t *f = &rpt->findings[rpt->count++];
    memset(f, 0, sizeof(*f));
    strncpy(f->rule_id,  rule_id,  sizeof(f->rule_id)  - 1);
    strncpy(f->category, category, sizeof(f->category) - 1);

    /* Relativize file path against project_root (§4 location.file MUST be
     * relative to --dir, using '/' separators). */
    {
        const char *rel = file;
        if (rpt->project_root[0]) {
            size_t prlen = strlen(rpt->project_root);
            if (strncmp(file, rpt->project_root, prlen) == 0 &&
                (file[prlen] == '/' || file[prlen] == '\0'))
                rel = file + prlen + (file[prlen] == '/');
        }
        while (rel[0] == '.' && rel[1] == '/') rel += 2;
        strncpy(f->file, rel[0] ? rel : ".", sizeof(f->file) - 1);
    }

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

    /* §4.2 fingerprint: sha256(ruleId \x1f location.file \x1f normalizedMessage) */
    {
        char norm_msg[CFUSA_FINDING_MSG_MAX];
        cfusa_normalize_msg(f->message, norm_msg, sizeof(norm_msg));
        char canonical[CFUSA_FINDING_MSG_MAX + CFUSA_FINDING_FILE_MAX + 64 + 4];
        int clen = snprintf(canonical, sizeof(canonical), "%s\x1f%s\x1f%s",
                            f->rule_id, f->file, norm_msg);
        if (clen < 0 || (size_t)clen >= sizeof(canonical))
            clen = (int)sizeof(canonical) - 1;
        char hex[65];
        cfusa_sha256_buf((const unsigned char *)canonical, (size_t)clen, hex);
        snprintf(f->fingerprint, sizeof(f->fingerprint), "sha256:%s", hex);
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
    char esc_proj[256], esc_ts[64], esc_std[256], esc_root[512];
    cfusa_str_escape_json(rpt->project,      esc_proj, sizeof(esc_proj));
    cfusa_str_escape_json(rpt->timestamp,    esc_ts,   sizeof(esc_ts));
    cfusa_str_escape_json(rpt->standard,     esc_std,  sizeof(esc_std));
    cfusa_str_escape_json(rpt->project_root, esc_root, sizeof(esc_root));

    int total = rpt->error_count + rpt->warning_count + rpt->info_count;

    fprintf(out,
        "{\n"
        "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
        "  \"kind\": \"%s\",\n"
        "  \"tool\": \"c-FuSa\",\n"
        "  \"toolVersion\": \"%s\",\n"
        "  \"language\": \"c\",\n"
        "  \"generatedAt\": \"%s\",\n"
        "  \"projectRoot\": \"%s\",\n"
        "  \"project\": \"%s\",\n"
        "  \"standard\": \"%s\",\n"
        "  \"score\": %.1f,\n"
        "  \"summary\": {\"total\": %d, \"errors\": %d, \"warnings\": %d, \"infos\": %d},\n"
        "  \"findings\": [\n",
        rpt->kind[0] ? rpt->kind : "check-report",
        rpt->version[0] ? rpt->version : CFUSA_VERSION_STRING,
        esc_ts, esc_root, esc_proj, esc_std,
        cfusa_report_score(rpt),
        total, rpt->error_count, rpt->warning_count, rpt->info_count);

    int nrules = cfusa_engine_rule_count();
    for (int i = 0; i < rpt->count; i++) {
        const cfusa_finding_t *f = &rpt->findings[i];
        char esc_file[512], esc_msg[768];
        cfusa_str_escape_json(f->file,    esc_file, sizeof(esc_file));
        cfusa_str_escape_json(f->message, esc_msg,  sizeof(esc_msg));

        /* Look up rule metadata for remediation/standard fields */
        const char *remediation = "";
        const char *standard    = "";
        for (int j = 0; j < nrules; j++) {
            const cfusa_rule_t *r = cfusa_engine_get_rule(j);
            if (strcmp(r->id, f->rule_id) == 0) {
                if (r->description) remediation = r->description;
                if (r->standard)    standard    = r->standard;
                break;
            }
        }
        char esc_rem[256], esc_rulestd[64];
        cfusa_str_escape_json(remediation, esc_rem,     sizeof(esc_rem));
        cfusa_str_escape_json(standard,    esc_rulestd, sizeof(esc_rulestd));

        /* §4 location: file and line are MUST; endLine/endColumn are MAY */
        if (f->end_line > 0 && f->end_column > 0) {
            fprintf(out,
                "    {\"ruleId\": \"%s\", \"category\": \"%s\","
                " \"severity\": \"%s\","
                " \"location\": {\"file\": \"%s\", \"line\": %d,"
                " \"endLine\": %d, \"endColumn\": %d},"
                " \"message\": \"%s\","
                " \"fingerprint\": \"%s\","
                " \"remediation\": \"%s\","
                " \"standard\": \"%s\"}%s\n",
                f->rule_id, f->category,
                cfusa_severity_str(f->severity),
                esc_file, f->line, f->end_line, f->end_column, esc_msg,
                f->fingerprint,
                esc_rem, esc_rulestd,
                (i < rpt->count - 1) ? "," : "");
        } else if (f->end_line > 0) {
            fprintf(out,
                "    {\"ruleId\": \"%s\", \"category\": \"%s\","
                " \"severity\": \"%s\","
                " \"location\": {\"file\": \"%s\", \"line\": %d,"
                " \"endLine\": %d},"
                " \"message\": \"%s\","
                " \"fingerprint\": \"%s\","
                " \"remediation\": \"%s\","
                " \"standard\": \"%s\"}%s\n",
                f->rule_id, f->category,
                cfusa_severity_str(f->severity),
                esc_file, f->line, f->end_line, esc_msg,
                f->fingerprint,
                esc_rem, esc_rulestd,
                (i < rpt->count - 1) ? "," : "");
        } else {
            fprintf(out,
                "    {\"ruleId\": \"%s\", \"category\": \"%s\","
                " \"severity\": \"%s\","
                " \"location\": {\"file\": \"%s\", \"line\": %d},"
                " \"message\": \"%s\","
                " \"fingerprint\": \"%s\","
                " \"remediation\": \"%s\","
                " \"standard\": \"%s\"}%s\n",
                f->rule_id, f->category,
                cfusa_severity_str(f->severity),
                esc_file, f->line, esc_msg,
                f->fingerprint,
                esc_rem, esc_rulestd,
                (i < rpt->count - 1) ? "," : "");
        }
    }
    /* §3.2: structured error channel; empty when no tool-level runtime errors occurred */
    fprintf(out, "  ],\n  \"errors\": []\n}\n");
}

/* djb2 hash for SARIF partialFingerprints */
static unsigned long sarif_hash(const char *s)
{
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*s++)) h = h * 33 ^ (unsigned long)c;
    return h;
}

/* ---- SARIF 2.1.0 output ---- */
static void print_sarif(const cfusa_report_t *rpt, FILE *out)
{
    int nrules = cfusa_engine_rule_count();

    fprintf(out,
        "{\n"
        "  \"version\": \"2.1.0\",\n"
        "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n"
        "  \"runs\": [{\n"
        "    \"tool\": {\"driver\": {\n"
        "      \"name\": \"cfusa\",\n"
        "      \"version\": \"%s\",\n"
        "      \"informationUri\": \"https://github.com/SoundMatt/c-FuSa\",\n"
        "      \"rules\": [\n",
        rpt->version[0] ? rpt->version : CFUSA_VERSION_STRING);

    for (int i = 0; i < nrules; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        char esc_name[128], esc_desc[256], esc_std[64];
        cfusa_str_escape_json(r->name,                         esc_name, sizeof(esc_name));
        cfusa_str_escape_json(r->description ? r->description : r->name, esc_desc, sizeof(esc_desc));
        cfusa_str_escape_json(r->standard    ? r->standard    : "",      esc_std,  sizeof(esc_std));
        fprintf(out,
            "        {\"id\": \"%s\","
            " \"name\": \"%s\","
            " \"fullDescription\": {\"text\": \"%s\"},"
            " \"help\": {\"text\": \"%s\"}}%s\n",
            r->id, esc_name, esc_desc, esc_std,
            (i < nrules - 1) ? "," : "");
    }

    fprintf(out,
        "      ]\n"
        "    }},\n"
        "    \"results\": [\n");

    for (int i = 0; i < rpt->count; i++) {
        const cfusa_finding_t *f = &rpt->findings[i];
        const char *level =
            (f->severity == SEV_ERROR)   ? "error" :
            (f->severity == SEV_WARNING) ? "warning" : "note";
        char esc_file[512], esc_msg[768];
        cfusa_str_escape_json(f->file,    esc_file, sizeof(esc_file));
        cfusa_str_escape_json(f->message, esc_msg,  sizeof(esc_msg));

        /* partialFingerprints: stable hash of rule+file+line for deduplication */
        char fp_input[320];
        snprintf(fp_input, sizeof(fp_input), "%s:%s:%d", f->rule_id, f->file, f->line);
        unsigned long fp = sarif_hash(fp_input);

        /* §4 MAY: include endLine/endColumn in SARIF region when available */
        if (f->end_line > 0 && f->end_column > 0) {
            fprintf(out,
                "      {\"ruleId\": \"%s\","
                " \"level\": \"%s\","
                " \"message\": {\"text\": \"%s\"},"
                " \"partialFingerprints\": {\"primaryLocationLineHash\": \"%08lx\"},"
                " \"locations\": [{\"physicalLocation\":"
                " {\"artifactLocation\": {\"uri\": \"%s\"},"
                " \"region\": {\"startLine\": %d, \"endLine\": %d,"
                " \"endColumn\": %d}}}]}%s\n",
                f->rule_id, level, esc_msg, fp, esc_file,
                f->line > 0 ? f->line : 1, f->end_line, f->end_column,
                (i < rpt->count - 1) ? "," : "");
        } else if (f->end_line > 0) {
            fprintf(out,
                "      {\"ruleId\": \"%s\","
                " \"level\": \"%s\","
                " \"message\": {\"text\": \"%s\"},"
                " \"partialFingerprints\": {\"primaryLocationLineHash\": \"%08lx\"},"
                " \"locations\": [{\"physicalLocation\":"
                " {\"artifactLocation\": {\"uri\": \"%s\"},"
                " \"region\": {\"startLine\": %d, \"endLine\": %d}}}]}%s\n",
                f->rule_id, level, esc_msg, fp, esc_file,
                f->line > 0 ? f->line : 1, f->end_line,
                (i < rpt->count - 1) ? "," : "");
        } else {
            fprintf(out,
                "      {\"ruleId\": \"%s\","
                " \"level\": \"%s\","
                " \"message\": {\"text\": \"%s\"},"
                " \"partialFingerprints\": {\"primaryLocationLineHash\": \"%08lx\"},"
                " \"locations\": [{\"physicalLocation\":"
                " {\"artifactLocation\": {\"uri\": \"%s\"},"
                " \"region\": {\"startLine\": %d}}}]}%s\n",
                f->rule_id, level, esc_msg, fp, esc_file, f->line > 0 ? f->line : 1,
                (i < rpt->count - 1) ? "," : "");
        }
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
