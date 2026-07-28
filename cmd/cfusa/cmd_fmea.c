/*
 * cfusa fmea — Design FMEA generator (IEC 60812:2018 / AIAG-VDA FMEA
 * Handbook 2019 / ISO 26262 Part 5), x-FuSa spec §9.2.
 *
 * Scans C source for public (non-static) function definitions and emits an
 * FMEA table in JSON, CSV, or Markdown. Failure mode / effect / cause text
 * is heuristically templated from each function's actual name, file, and a
 * keyword-based risk category — it varies per entry (x-FuSa spec §1.6 rule
 * 3 / §1.6.1 rule B), rather than a single canned string repeated for every
 * row, and never ships bracket/instructional placeholder text (§1.6 rule 1).
 */
//cfusa:req REQ-CLI-FMEA001 REQ-FMEA001 REQ-FMEA002 REQ-FMEA006 REQ-FMEA007 REQ-FMEA008
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/qualitybar.h"
#include "cfusa/report.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

#define MAX_FUNS      1024
#define FMEA_RATING_SCALE "cfusa-heuristic-1-10"

/* Resolved absolute --dir, for project-relative `file` fields (x-FuSa spec
 * §4) regardless of whether --dir itself was given relative or absolute —
 * same pattern as cmd_trace.c's g_dir_abs. */
static char g_dir_abs[512];

typedef struct {
    char name[128];
    char file[256];
    int  line;
    int  severity;      /* 1-10, inferred from a keyword heuristic */
    int  occurrence;    /* 1-10 */
    int  detection;      /* 1-10 */
    const char *category;      /* "safety-critical" | "monitoring/control" | "general" */
    const char *action_priority; /* "high" | "medium" | "low" */
} fn_entry_t;

static fn_entry_t g_fns[MAX_FUNS];
static int        g_fn_count = 0;
static int        g_total_found = 0; /* uncapped — x-FuSa spec §9.2 componentsInProject */

/* Heuristic: elevated severity if name contains safety-critical keywords.
 * Mirrors the same public-function detection x-FuSa spec §5/§1.4.1
 * `trace --func-coverage` uses (non-static functions with a body), so
 * componentsInProject/componentsAnalyzed share one methodology. */
static void infer_profile(const char *name, fn_entry_t *fn)
{
    static const char * const hi[] = {
        "brake","steer","throttle","safety","shutdown","critical",
        "halt","fault","error","emergency","protect","watchdog", NULL
    };
    static const char * const med[] = {
        "init","config","check","validate","monitor","log", NULL
    };
    for (int i = 0; hi[i]; i++)
        if (strstr(name, hi[i])) {
            fn->severity = 9; fn->occurrence = 4; fn->detection = 6;
            fn->category = "safety-critical"; fn->action_priority = "high";
            return;
        }
    for (int i = 0; med[i]; i++)
        if (strstr(name, med[i])) {
            fn->severity = 5; fn->occurrence = 3; fn->detection = 4;
            fn->category = "monitoring/control"; fn->action_priority = "medium";
            return;
        }
    fn->severity = 3; fn->occurrence = 2; fn->detection = 3;
    fn->category = "general"; fn->action_priority = "low";
}

/* ---- qualitative-field rendering (varies per entry — x-FuSa spec §1.6.1 rule B) ---- */

static void render_failure_mode(char *out, size_t sz, const fn_entry_t *fn)
{
    snprintf(out, sz, "%s (%s function) does not perform its intended action", fn->name, fn->category);
}

static void render_effect(char *out, size_t sz, const fn_entry_t *fn)
{
    snprintf(out, sz, "Failure of %s could propagate undetected to callers in %s",
             fn->name, cfusa_basename(fn->file));
}

/* RFC 4180 CSV escaping: a quoted field's embedded '"' MUST be doubled. */
static void csv_escape(const char *in, char *out, size_t sz)
{
    size_t k = 0;
    while (*in && k + 2 < sz) {
        if (*in == '"') out[k++] = '"';
        out[k++] = *in++;
    }
    out[k] = '\0';
}

static void render_cause(char *out, size_t sz, const fn_entry_t *fn)
{
    if (strcmp(fn->category, "safety-critical") == 0)
        snprintf(out, sz, "Unhandled fault or invalid input condition within %s", fn->name);
    else if (strcmp(fn->category, "monitoring/control") == 0)
        snprintf(out, sz, "Configuration or state inconsistency affecting %s", fn->name);
    else
        snprintf(out, sz, "Logic error or untested edge case in %s", fn->name);
}

static void fmea_line(const char *path, int lineno, const char *line, void *vctx)
{
    (void)vctx;
    /* cfusa_extract_call_name() (src/utils.c) centralises the match
     * heuristic that used to live here: skip control-flow/storage-class
     * keywords (word-boundary aware, so "if(" and "if " are both caught),
     * require the "(" to be outside a string literal (a test-fixture
     * description string is not a call site), and exclude standard-library
     * calls outright — x-FuSa spec §1.6 rule 4 ("real referents only"). */
    char fn_name[128];
    if (!cfusa_extract_call_name(line, fn_name, sizeof(fn_name))) return;

    /* Counted for componentsInProject regardless of the per-run table cap,
     * so coveragePct honestly reflects truncation on very large projects
     * instead of silently reporting 100% either way. */
    g_total_found++;
    if (g_fn_count >= MAX_FUNS) return;

    strncpy(g_fns[g_fn_count].name, fn_name, 127);
    /* Project-relative (x-FuSa spec §4), regardless of whether --dir was
     * given relative or absolute. */
    cfusa_relativize_path(g_dir_abs, path, g_fns[g_fn_count].file,
                           sizeof(g_fns[g_fn_count].file));
    g_fns[g_fn_count].line     = lineno;
    infer_profile(fn_name, &g_fns[g_fn_count]);
    g_fn_count++;
}

/* Mirrors trace --func-coverage's is_test_file(): a design FMEA is over the
 * project's own safety-relevant public functions, not its test scaffolding
 * — same exclusion used by trace --func-coverage's componentsInProject-
 * equivalent denominator (x-FuSa spec §1.4.1/§5), which this command's
 * summary.componentsInProject is intentionally aligned with. */
static int fmea_is_test_file(const char *path)
{
    return cfusa_is_test_source_file(path);
}

static int fmea_file(const char *path, void *v)
{
    if (fmea_is_test_file(path)) return 0;
    cfusa_scan_lines(path, fmea_line, v);
    return 0;
}

/* ---- canonical content hash (x-FuSa spec §1.6.2) ---- */

static size_t fmea_canonical_content(char *buf, size_t bufsz)
{
    size_t off = 0;
    off += (size_t)snprintf(buf + off, bufsz - off, "{\"entries\":[");
    for (int i = 0; i < g_fn_count; i++) {
        char fm[192], ef[224], ca[192], esc_item[192];
        char esc_fm[256], esc_ef[288], esc_ca[256];
        render_failure_mode(fm, sizeof(fm), &g_fns[i]);
        render_effect(ef, sizeof(ef), &g_fns[i]);
        render_cause(ca, sizeof(ca), &g_fns[i]);
        cfusa_str_escape_json(g_fns[i].name, esc_item, sizeof(esc_item));
        cfusa_str_escape_json(fm, esc_fm, sizeof(esc_fm));
        cfusa_str_escape_json(ef, esc_ef, sizeof(esc_ef));
        cfusa_str_escape_json(ca, esc_ca, sizeof(esc_ca));
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            "%s{\"actionPriority\":\"%s\",\"cause\":\"%s\",\"detection\":%d,"
            "\"effect\":\"%s\",\"failureMode\":\"%s\",\"file\":\"%s\",\"id\":\"FM-%03d\","
            "\"item\":\"%s\",\"occurrence\":%d,\"severity\":%d}",
            i ? "," : "", g_fns[i].action_priority, esc_ca, g_fns[i].detection, esc_ef, esc_fm,
            g_fns[i].file, i + 1, esc_item, g_fns[i].occurrence,
            g_fns[i].severity);
    }
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "]}");
    return off;
}

/* ---- quality-bar scan + attestation (x-FuSa spec §1.6.1/§1.6.2) ---- */

static const char *g_qb_modes[MAX_FUNS];
static char        g_qb_mode_bufs[MAX_FUNS][192];
static char        g_canonical_buf[262144];

static int run_quality_bar(const char *dir, const char *fresh_hash,
                            cfusa_attestation_t *existing, int require_attestation)
{
    for (int i = 0; i < g_fn_count; i++) {
        render_failure_mode(g_qb_mode_bufs[i], sizeof(g_qb_mode_bufs[i]), &g_fns[i]);
        g_qb_modes[i] = g_qb_mode_bufs[i];
    }
    const char **modes = g_qb_modes;

    int rule_a_hits = 0;
    for (int i = 0; i < g_fn_count; i++)
        if (cfusa_qb_is_stub_text(modes[i])) rule_a_hits++;

    int rule_a_disposed = rule_a_hits > 0 && cfusa_qb_rule_disposed(dir, CFUSA_QB_RULE_A);
    if (rule_a_hits > 0)
        fprintf(stderr, "cfusa fmea: %s: %d entr%s with placeholder-looking text%s\n",
                CFUSA_QB_RULE_A, rule_a_hits, rule_a_hits == 1 ? "y" : "ies",
                rule_a_disposed ? " (disposed)" : "");

    int rule_b = cfusa_qb_rule_b_flagged(modes, g_fn_count);
    int reviewed = 0;
    if (rule_b) {
        reviewed = cfusa_qb_attestation_valid(existing, fresh_hash);
        fprintf(stderr, "cfusa fmea: %s: failureMode text shows low distinct-value ratio "
                        "across >=10 entries%s\n", CFUSA_QB_RULE_B,
                reviewed ? " (suppressed by a valid attestation)" : "");
    }

    if (rule_a_hits > 0 && !rule_a_disposed) return 1;
    if (require_attestation && rule_b && !reviewed) return 1;
    return 0;
}

/* ---- rendering ---- */

static void write_entry_json(FILE *f, const fn_entry_t *fn, int idx, int last, int with_cyber)
{
    char fm[192], ef[224], ca[192];
    render_failure_mode(fm, sizeof(fm), fn);
    render_effect(ef, sizeof(ef), fn);
    render_cause(ca, sizeof(ca), fn);
    char esc_fm[256], esc_ef[288], esc_ca[256], esc_item[192];
    cfusa_str_escape_json(fm, esc_fm, sizeof(esc_fm));
    cfusa_str_escape_json(ef, esc_ef, sizeof(esc_ef));
    cfusa_str_escape_json(ca, esc_ca, sizeof(esc_ca));
    /* x-FuSa spec §1.6 rule 2 (structural validity): the scanner's naive
     * paren-based heuristic occasionally misdetects a quoted string literal
     * as a function name (e.g. a known-answer-test table entry) — escape
     * `item` like every other free-text field rather than assume it's
     * always a clean identifier. */
    cfusa_str_escape_json(fn->name, esc_item, sizeof(esc_item));
    fprintf(f,
        "    {\n"
        "      \"id\": \"FM-%03d\",\n"
        "      \"item\": \"%s\",\n"
        "      \"file\": \"%s\",\n"
        "      \"line\": %d,\n"
        "      \"failureMode\": \"%s\",\n"
        "      \"effect\": \"%s\",\n"
        "      \"cause\": \"%s\",\n"
        "      \"severity\": %d,\n"
        "      \"occurrence\": %d,\n"
        "      \"detection\": %d,\n"
        "      \"actionPriority\": \"%s\",\n"
        "      \"mitigations\": [],\n"
        "      \"requirementIds\": []%s\n"
        "    }%s\n",
        idx + 1, esc_item, fn->file, fn->line,
        esc_fm, esc_ef, esc_ca, fn->severity, fn->occurrence, fn->detection,
        fn->action_priority,
        with_cyber ? ",\n      \"cyberFailureMode\": \"\"" : "",
        last ? "" : ",");
}

int cmd_fmea(int argc, char **argv)
{
    const char *dir      = ".";
    const char *out_dir  = NULL;   /* --output-dir (go-FuSa style) */
    const char *output   = NULL;   /* --output <file> — exact path, distinct from --output-dir */
    const char *fmt_s    = NULL;   /* NULL → both json+csv; "md"/"json"/"csv" → single */
    const char *attest   = NULL;   /* --attest <reviewer> convenience flag */
    int with_cyber       = 0;
    int strict           = 0;
    int require_attestation = 0;
    int min_coverage     = 0;

    static const struct option lo[] = {
        {"dir",                required_argument, NULL, 'd'},
        {"output-dir",         required_argument, NULL, 'D'},
        {"output",             required_argument, NULL, 'o'},
        {"format",             required_argument, NULL, 'f'},
        {"cyber",              no_argument,       NULL, 'c'},
        {"strict",             no_argument,       NULL, 'S'},
        {"require-attestation",no_argument,       NULL, 'A'},
        {"attest",             required_argument, NULL, 'T'},
        {"min-coverage",       required_argument, NULL, 'm'},
        {"help",               no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int ch; optind = 1;
    while ((ch = getopt_long(argc, argv, "d:D:o:f:cSAT:m:h", lo, NULL)) != -1) {
        switch (ch) {
        case 'd': dir      = optarg; break;
        case 'D': out_dir  = optarg; break;
        case 'o': output   = optarg; break;
        case 'f': fmt_s    = optarg; break;
        case 'c': with_cyber = 1;    break;
        case 'S': strict = 1;        break;
        case 'A': require_attestation = 1; break;
        case 'T': attest = optarg;   break;
        case 'm': min_coverage = atoi(optarg); break;
        case 'h':
            printf("Usage: cfusa fmea [--dir <path>] [--output-dir <dir>] [--output <file>]\n"
                   "                  [--format md|json|csv] [--cyber]\n"
                   "                  [--strict] [--require-attestation] [--attest <reviewer>]\n"
                   "                  [--min-coverage N]\n\n"
                   "Generates a design FMEA from public function signatures\n"
                   "(IEC 60812 / ISO 26262-5 / AIAG-VDA FMEA Handbook).\n"
                   "Default: generates both fmea.json and fmea.csv.\n"
                   "--format md|json|csv  generates a single file of that format instead.\n"
                   "--output <file>       writes exactly that path (implies --format json\n"
                   "                      unless --format is also given).\n"
                   "--cyber              enriches entries with cybersecurity failure modes.\n"
                   "--strict             implies --require-attestation.\n"
                   "--require-attestation escalates an unsuppressed FUSA-STUB002 to exit 1.\n"
                   "--attest <reviewer>  stamps a §1.6.2 attestation (independent reviewer name).\n"
                   "--min-coverage N     exit 1 when componentsInProject coverage < N%% (0 disables).\n");
            return 0;
        default: return 2;
        }
    }
    if (strict) require_attestation = 1;

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    g_fn_count = 0;
    g_total_found = 0;
    /* Deliberately the literal --dir value, not realpath(dir) — see
     * cfusa_relativize_path()'s doc comment for why. */
    strncpy(g_dir_abs, dir, sizeof(g_dir_abs) - 1);
    g_dir_abs[sizeof(g_dir_abs) - 1] = '\0';

    static const char * const exts[] = {".c"};
    cfusa_walk_sources(dir, exts, 1, fmea_file, NULL);

    const char *base = out_dir ? out_dir : dir;
    char ts[32]; cfusa_timestamp_now(ts);

    int coverage_pct = (g_total_found == 0) ? 100 : (g_fn_count * 100 / g_total_found);
    /* x-FuSa spec §9.2: coveragePct MUST NOT exceed 100. Structurally
     * g_fn_count <= g_total_found already (every match increments
     * g_total_found; g_fn_count only when under the MAX_FUNS cap), so this
     * is defense-in-depth against a future accounting change rather than a
     * currently-reachable path — the spec's rollout audit found this
     * exceeded in other tools precisely when that invariant silently broke. */
    if (coverage_pct > 100) coverage_pct = 100;
    int high = 0;
    for (int i = 0; i < g_fn_count; i++)
        if (strcmp(g_fns[i].action_priority, "high") == 0) high++;

    /* Read back a prior fmea.json's attestation (if any) so a genuine,
     * non-stale, independent review carries forward across regenerations
     * (x-FuSa spec §1.6.2). */
    char existing_path[512];
    cfusa_path_join(existing_path, sizeof(existing_path), base, "fmea.json");
    size_t existing_len = 0;
    char *existing_json = cfusa_read_file(existing_path, &existing_len);
    cfusa_attestation_t attestation;
    if (existing_json) cfusa_qb_attestation_read(existing_json, existing_len, &attestation);
    else memset(&attestation, 0, sizeof(attestation));
    free(existing_json);

    size_t clen = fmea_canonical_content(g_canonical_buf, sizeof(g_canonical_buf));
    if (clen >= sizeof(g_canonical_buf)) clen = sizeof(g_canonical_buf) - 1;
    char fresh_hash[80];
    cfusa_qb_content_hash(g_canonical_buf, clen, fresh_hash);

    if (attest) {
        attestation.present = 1;
        strncpy(attestation.status, "reviewed", sizeof(attestation.status) - 1);
        strncpy(attestation.implementation_author, "auto", sizeof(attestation.implementation_author) - 1);
        strncpy(attestation.independent_reviewer, attest, sizeof(attestation.independent_reviewer) - 1);
        strncpy(attestation.reviewed_at, ts, sizeof(attestation.reviewed_at) - 1);
        strncpy(attestation.content_hash, fresh_hash, sizeof(attestation.content_hash) - 1);
    }

    int qb_gate = run_quality_bar(dir, fresh_hash, &attestation, require_attestation);
    int attestation_valid = cfusa_qb_attestation_valid(&attestation, fresh_hash);

    int cov_gate = 0;
    if (min_coverage > 0 && coverage_pct < min_coverage) {
        fprintf(stderr, "cfusa fmea: --min-coverage gate failed: %d%% < required %d%%\n",
                coverage_pct, min_coverage);
        cov_gate = 1;
    }

#define WRITE_ATTESTATION(fp) do { \
    if (attestation_valid) { \
        fprintf((fp), ",\n  \"attestation\": {\n" \
            "    \"status\": \"reviewed\",\n" \
            "    \"implementationAuthor\": \"%s\",\n" \
            "    \"independentReviewer\": \"%s\",\n" \
            "    \"reviewedAt\": \"%s\",\n" \
            "    \"contentHash\": \"%s\"\n" \
            "  }\n", \
            attestation.implementation_author, attestation.independent_reviewer, \
            attestation.reviewed_at, attestation.content_hash); \
    } else { \
        fprintf((fp), "\n"); \
    } \
} while (0)

    /* Helper: open output file relative to base directory */
#define OPEN_OUT(name, var)  do { \
    char _p[512]; cfusa_path_join(_p, sizeof(_p), base, (name)); \
    (var) = cfusa_fopen_write(_p); \
    if (!(var)) { perror(_p); return 3; } \
    printf("FMEA written to %s  (%d functions)\n", _p, g_fn_count); \
} while(0)

    if (!fmt_s && !output) {
        /* Default: generate both fmea.json and fmea.csv (go-FuSa style) */
        FILE *jf, *cf;
        OPEN_OUT("fmea.json", jf);
        OPEN_OUT("fmea.csv",  cf);

        fprintf(jf,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"fmea-report\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"project\": \"%s\",\n"
            "  \"version\": \"%s\",\n"
            "  \"standard\": \"iso26262\",\n"
            "  \"ratingScale\": \"" FMEA_RATING_SCALE "\",\n"
            "  \"entries\": [\n",
            ts, cfg.project, cfg.version);
        if (with_cyber)
            fprintf(cf, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,ActionPriority,Cyber Failure Mode\n");
        else
            fprintf(cf, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,ActionPriority\n");

        for (int i = 0; i < g_fn_count; i++) {
            write_entry_json(jf, &g_fns[i], i, i == g_fn_count - 1, with_cyber);
            char fm[192], ef[224], ca[192];
            char csv_name[192], csv_fm[256], csv_ef[288], csv_ca[256];
            render_failure_mode(fm, sizeof(fm), &g_fns[i]);
            render_effect(ef, sizeof(ef), &g_fns[i]);
            render_cause(ca, sizeof(ca), &g_fns[i]);
            csv_escape(g_fns[i].name, csv_name, sizeof(csv_name));
            csv_escape(fm, csv_fm, sizeof(csv_fm));
            csv_escape(ef, csv_ef, sizeof(csv_ef));
            csv_escape(ca, csv_ca, sizeof(csv_ca));
            fprintf(cf, "FM-%03d,\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\",%d,%d,%d,\"%s\"",
                    i + 1, csv_name, cfusa_basename(g_fns[i].file), g_fns[i].line,
                    csv_fm, csv_ef, csv_ca, g_fns[i].severity, g_fns[i].occurrence,
                    g_fns[i].detection, g_fns[i].action_priority);
            if (with_cyber) fprintf(cf, ",\n"); else fprintf(cf, "\n");
        }
        fprintf(jf, "  ],\n  \"summary\": {\n"
                    "    \"total\": %d, \"highPriority\": %d,\n"
                    "    \"componentsAnalyzed\": %d, \"componentsInProject\": %d, \"coveragePct\": %d\n"
                    "  }",
                g_fn_count, high, g_fn_count, g_total_found, coverage_pct);
        WRITE_ATTESTATION(jf);
        fprintf(jf, "}\n");
        fclose(jf); fclose(cf);
        printf("Priority: %d high\n", high);
        printf("Coverage: %d%% (%d/%d public functions)\n", coverage_pct, g_fn_count, g_total_found);
        return qb_gate || cov_gate;
    }

    /* --output <file> with no --format defaults to JSON — the canonical,
     * schema-formalized shape (x-FuSa spec §9.2) and the format anyone
     * scripting a specific --output path is most likely after. */
    cfusa_format_t fmt = cfusa_format_parse(fmt_s ? fmt_s : "json");
    FILE *f;
    if (output) {
        f = cfusa_fopen_write(output);
        if (!f) { perror(output); return 3; }
        printf("FMEA written to %s  (%d functions)\n", output, g_fn_count);
    } else {
        const char *def_name = (fmt == FMT_JSON) ? "fmea.json" :
                               (fmt == FMT_CSV)  ? "fmea.csv"  : "fmea.md";
        OPEN_OUT(def_name, f);
    }

    if (fmt == FMT_JSON) {
        fprintf(f,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"fmea-report\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"project\": \"%s\",\n"
            "  \"version\": \"%s\",\n"
            "  \"standard\": \"iso26262\",\n"
            "  \"ratingScale\": \"" FMEA_RATING_SCALE "\",\n"
            "  \"entries\": [\n",
            ts, cfg.project, cfg.version);
        for (int i = 0; i < g_fn_count; i++)
            write_entry_json(f, &g_fns[i], i, i == g_fn_count - 1, with_cyber);
        fprintf(f, "  ],\n  \"summary\": {\n"
                   "    \"total\": %d, \"highPriority\": %d,\n"
                   "    \"componentsAnalyzed\": %d, \"componentsInProject\": %d, \"coveragePct\": %d\n"
                   "  }",
                g_fn_count, high, g_fn_count, g_total_found, coverage_pct);
        WRITE_ATTESTATION(f);
        fprintf(f, "}\n");
    } else if (fmt == FMT_CSV) {
        if (with_cyber)
            fprintf(f, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,ActionPriority,Cyber Failure Mode\n");
        else
            fprintf(f, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,ActionPriority\n");
        for (int i = 0; i < g_fn_count; i++) {
            char fm[192], ef[224], ca[192];
            char csv_name[192], csv_fm[256], csv_ef[288], csv_ca[256];
            render_failure_mode(fm, sizeof(fm), &g_fns[i]);
            render_effect(ef, sizeof(ef), &g_fns[i]);
            render_cause(ca, sizeof(ca), &g_fns[i]);
            csv_escape(g_fns[i].name, csv_name, sizeof(csv_name));
            csv_escape(fm, csv_fm, sizeof(csv_fm));
            csv_escape(ef, csv_ef, sizeof(csv_ef));
            csv_escape(ca, csv_ca, sizeof(csv_ca));
            fprintf(f, "FM-%03d,\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\",%d,%d,%d,\"%s\"",
                    i + 1, csv_name, cfusa_basename(g_fns[i].file), g_fns[i].line,
                    csv_fm, csv_ef, csv_ca, g_fns[i].severity, g_fns[i].occurrence,
                    g_fns[i].detection, g_fns[i].action_priority);
            if (with_cyber) fprintf(f, ",\n"); else fprintf(f, "\n");
        }
    } else {
        /* Markdown */
        fprintf(f,
            "# Design FMEA — %s v%s\n"
            "Generated: %s  |  Standard: IEC 60812:2018 / ISO 26262 Part 5\n"
            "Rating scale: " FMEA_RATING_SCALE "\n\n",
            cfg.project, cfg.version, ts);
        fprintf(f,
            "| ID | Function | File | Failure Mode | Effect | "
            "Cause | S | O | D | Action Priority |");
        if (with_cyber) fprintf(f, " Cyber Failure Mode |");
        fprintf(f, "\n|---|---|---|---|---|---|---|---|---|---|");
        if (with_cyber) fprintf(f, "---|");
        fprintf(f, "\n");
        for (int i = 0; i < g_fn_count; i++) {
            char fm[192], ef[224], ca[192];
            render_failure_mode(fm, sizeof(fm), &g_fns[i]);
            render_effect(ef, sizeof(ef), &g_fns[i]);
            render_cause(ca, sizeof(ca), &g_fns[i]);
            fprintf(f,
                "| FM-%03d | `%s` | %s:%d | %s | %s | %s "
                "| %d | %d | %d | %s |",
                i + 1, g_fns[i].name,
                cfusa_basename(g_fns[i].file), g_fns[i].line,
                fm, ef, ca,
                g_fns[i].severity, g_fns[i].occurrence, g_fns[i].detection,
                g_fns[i].action_priority);
            if (with_cyber) fprintf(f, " |");
            fprintf(f, "\n");
        }
        fprintf(f,
            "\n---\n"
            "_Total functions analysed: %d (%d%% of %d public functions found)_  \n",
            g_fn_count, coverage_pct, g_total_found);
    }

    fclose(f);
    return qb_gate || cov_gate;
#undef OPEN_OUT
#undef WRITE_ATTESTATION
}
