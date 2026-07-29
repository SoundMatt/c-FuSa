/*
 * cfusa tara — Threat Analysis and Risk Assessment (ISO/SAE 21434:2021
 * Clause 15), x-FuSa spec §9.2.
 *
 * Scans C source for functions that look like they handle
 * external/untrusted data (network, file, credential, or raw-memory
 * input) — a keyword-based asset-discovery heuristic, documented as such
 * via `summary.assetInventoryMethod` rather than claimed as a formal asset
 * inventory. Each match becomes one asset + one threat scenario, with an
 * SFOP (Safety/Financial/Operational/Privacy) impact object per ISO 21434
 * Clause 15.7, rather than one generic severity. Threat/asset text is
 * templated from the actual function/file found, so it varies per entry
 * (x-FuSa spec §1.6.1 rule B) — never a fixed placeholder string.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/qualitybar.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

//cfusa:req REQ-CLI-TARA001 REQ-TARA001 REQ-TARA002 REQ-TARA003 REQ-TARA006

#define MAX_THREATS 512

/* Resolved absolute --dir, for project-relative `location.file` fields
 * (x-FuSa spec §4) regardless of whether --dir itself was given relative or
 * absolute — same pattern as cmd_trace.c's g_dir_abs / cmd_fmea.c's. */
static char g_dir_abs[512];

typedef struct {
    const char *category;      /* "network" | "file" | "auth" | "memory" */
    const char *attack_vector; /* "network" | "local" | "physical" */
    const char *feasibility;   /* high|medium|low|very-low */
    /* SFOP impact axes — x-FuSa spec §9.2 v1.14.1 closed enum:
     * critical|major|moderate|negligible (NOT high|medium|low, which is a
     * distinct scale used only for `feasibility` above). The four profiles
     * below mechanically remap this heuristic's original 3-level
     * high/medium/low scale onto the top three enum values
     * (high->critical, medium->major, low->moderate), preserving each
     * profile's relative severity ordering. */
    const char *safety, *financial, *operational, *privacy;
    const char *mitigations[3];
} category_profile_t;

static const category_profile_t PROFILE_NETWORK = {
    "network", "network", "medium", "major", "moderate", "major", "major",
    {"Validate and bound-check all network input before use",
     "Add fuzz/negative testing for this entry point", NULL}
};
static const category_profile_t PROFILE_FILE = {
    "file", "local", "medium", "moderate", "moderate", "major", "moderate",
    {"Validate file contents against an expected schema before use",
     "Reject unexpected file sizes/paths", NULL}
};
static const category_profile_t PROFILE_AUTH = {
    "auth", "local", "medium", "moderate", "major", "major", "critical",
    {"Store credentials/keys only in vetted secret storage",
     "Add independent review of authentication/authorization logic", NULL}
};
static const category_profile_t PROFILE_MEMORY = {
    "memory", "local", "medium", "critical", "moderate", "major", "moderate",
    {"Use bounds-checked copy/allocation APIs",
     "Add static analysis (cfusa analyze/lint) to the CI gate for this file", NULL}
};

typedef struct {
    char name[128];
    char file[256];
    int  line;
    const category_profile_t *profile;
} asset_entry_t;

static asset_entry_t g_assets[MAX_THREATS];
static int           g_asset_count = 0;
static int           g_total_found = 0;

static const category_profile_t *classify(const char *name)
{
    static const char * const net_kw[]  = {"recv","socket","connect","listen","accept","http","tcp","udp","fetch", NULL};
    static const char * const file_kw[] = {"fopen","fread","load","import","parse","decode","deserialize", NULL};
    static const char * const auth_kw[] = {"auth","login","token","credential","password","secret", NULL};
    static const char * const mem_kw[]  = {"alloc","copy","strcpy","memcpy","buffer","realloc", NULL};

    for (int i = 0; net_kw[i]; i++)  if (strstr(name, net_kw[i]))  return &PROFILE_NETWORK;
    for (int i = 0; auth_kw[i]; i++) if (strstr(name, auth_kw[i])) return &PROFILE_AUTH;
    for (int i = 0; file_kw[i]; i++) if (strstr(name, file_kw[i])) return &PROFILE_FILE;
    for (int i = 0; mem_kw[i]; i++)  if (strstr(name, mem_kw[i]))  return &PROFILE_MEMORY;
    return NULL;
}

/* ---- feasibility x max(SFOP) -> risk, via the x-FuSa spec §9.2 canonical
 * risk combination table (v1.14.1) — the same table implemented (and
 * tested) in FuSaOps' own `tara` package; not an ad hoc score. ---- */

/* Highest-ranked first: critical > major > moderate > negligible. */
static int impact_rank(const char *v)
{
    if (!strcmp(v, "critical")) return 3;
    if (!strcmp(v, "major")) return 2;
    if (!strcmp(v, "moderate")) return 1;
    return 0; /* negligible */
}
static const char *max_sfop(const category_profile_t *p)
{
    const char *best = p->safety; int br = impact_rank(best);
    const char *cand[3] = {p->financial, p->operational, p->privacy};
    for (int i = 0; i < 3; i++) {
        int r = impact_rank(cand[i]);
        if (r > br) { br = r; best = cand[i]; }
    }
    return best;
}
/* feasibility column: high | medium | low | very-low */
static int feasibility_col(const char *f)
{
    if (!strcmp(f, "high")) return 0;
    if (!strcmp(f, "medium")) return 1;
    if (!strcmp(f, "low")) return 2;
    return 3; /* very-low */
}
static const char *derive_risk(const category_profile_t *p)
{
    /* Row order matches impact_rank(): critical, major, moderate, negligible.
     * Column order matches feasibility_col(): high, medium, low, very-low.
     * Verbatim transcription of the x-FuSa spec §9.2 combination table. */
    static const char * const table[4][4] = {
        /* critical  */ {"critical", "critical", "high",   "medium"},
        /* major     */ {"high",     "high",     "medium", "medium"},
        /* moderate  */ {"medium",   "medium",   "low",    "low"},
        /* negligible*/ {"low",      "low",      "low",    "low"},
    };
    int row = 3 - impact_rank(max_sfop(p));
    int col = feasibility_col(p->feasibility);
    return table[row][col];
}
static const char *derive_treatment(const char *risk)
{
    return strcmp(risk, "low") == 0 ? "accept" : "mitigate";
}

/* ---- qualitative-field rendering (varies per entry — rule B) ---- */

static void render_asset(char *out, size_t sz, const asset_entry_t *a)
{
    snprintf(out, sz, "Data handled by %s (%s)", a->name, cfusa_basename(a->file));
}
static void render_threat(char *out, size_t sz, const asset_entry_t *a)
{
    snprintf(out, sz,
        "An attacker supplies malformed/untrusted input to %s, potentially causing "
        "incorrect behaviour, a crash, or information disclosure", a->name);
}

static void asset_line(const char *path, int lineno, const char *line, void *vctx)
{
    (void)vctx;
    /* cfusa_extract_call_name() (src/utils.c, shared with cmd_fmea.c)
     * centralises the match heuristic: skip control-flow/storage-class
     * keywords, require the "(" to be outside a string literal, and
     * exclude standard-library calls outright — x-FuSa spec §1.6 rule 4
     * ("real referents only"). A stdlib call like strcpy()/memcpy() is
     * excluded here even though `classify()` below would otherwise treat
     * its name as a memory-category asset keyword match. */
    char fn_name[128];
    if (!cfusa_extract_call_name(line, fn_name, sizeof(fn_name))) return;

    const category_profile_t *prof = classify(fn_name);
    if (!prof) return; /* not asset-relevant by this heuristic */

    g_total_found++;
    if (g_asset_count >= MAX_THREATS) return;

    strncpy(g_assets[g_asset_count].name, fn_name, 127);
    /* Project-relative (x-FuSa spec §4), regardless of whether --dir was
     * given relative or absolute. */
    cfusa_relativize_path(g_dir_abs, path, g_assets[g_asset_count].file,
                           sizeof(g_assets[g_asset_count].file));
    g_assets[g_asset_count].line = lineno;
    g_assets[g_asset_count].profile = prof;
    g_asset_count++;
}

/* Mirrors trace --func-coverage's is_test_file() / cmd_fmea.c's
 * fmea_is_test_file(): a TARA is over the project's own attack surface, not
 * its test scaffolding (a test helper calling e.g. strcpy() is not an
 * asset). */
static int tara_is_test_file(const char *path)
{
    return cfusa_is_test_source_file(path);
}

static int asset_file(const char *path, void *v)
{
    if (tara_is_test_file(path)) return 0;
    cfusa_scan_lines(path, asset_line, v);
    return 0;
}

/* ---- canonical content hash (x-FuSa spec §1.6.2) ---- */

static char g_canonical_buf[262144];

static size_t tara_canonical_content(char *buf, size_t bufsz)
{
    size_t off = 0;
    char esc_asset[256], esc_threat[320];
    off += (size_t)snprintf(buf + off, bufsz - off, "{\"threats\":[");
    for (int i = 0; i < g_asset_count; i++) {
        const asset_entry_t *a = &g_assets[i];
        const category_profile_t *p = a->profile;
        char asset[256], threat[320];
        render_asset(asset, sizeof(asset), a);
        render_threat(threat, sizeof(threat), a);
        cfusa_str_escape_json(asset, esc_asset, sizeof(esc_asset));
        cfusa_str_escape_json(threat, esc_threat, sizeof(esc_threat));
        const char *risk = derive_risk(p);
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            "%s{\"asset\":\"%s\",\"attackFeasibility\":\"%s\",\"attackVector\":\"%s\","
            "\"id\":\"TARA-%03d\",\"impact\":{\"financial\":\"%s\",\"operational\":\"%s\","
            "\"privacy\":\"%s\",\"safety\":\"%s\"},\"risk\":\"%s\",\"threat\":\"%s\","
            "\"treatment\":\"%s\"}",
            i ? "," : "", esc_asset, p->feasibility, p->attack_vector, i + 1,
            p->financial, p->operational, p->privacy, p->safety, risk, esc_threat,
            derive_treatment(risk));
    }
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "]}");
    return off;
}

/* ---- quality-bar scan + attestation ---- */

static const char *g_qb_threats[MAX_THREATS];
static char        g_qb_threat_bufs[MAX_THREATS][320];

static int run_quality_bar(const char *dir, const char *fresh_hash,
                            cfusa_attestation_t *existing, int require_attestation)
{
    for (int i = 0; i < g_asset_count; i++) {
        render_threat(g_qb_threat_bufs[i], sizeof(g_qb_threat_bufs[i]), &g_assets[i]);
        g_qb_threats[i] = g_qb_threat_bufs[i];
    }

    int rule_a_hits = 0;
    for (int i = 0; i < g_asset_count; i++)
        if (cfusa_qb_is_stub_text(g_qb_threats[i])) rule_a_hits++;
    int rule_a_disposed = rule_a_hits > 0 && cfusa_qb_rule_disposed(dir, CFUSA_QB_RULE_A);
    if (rule_a_hits > 0)
        fprintf(stderr, "cfusa tara: %s: %d entr%s with placeholder-looking text%s\n",
                CFUSA_QB_RULE_A, rule_a_hits, rule_a_hits == 1 ? "y" : "ies",
                rule_a_disposed ? " (disposed)" : "");

    int rule_b = cfusa_qb_rule_b_flagged(g_qb_threats, g_asset_count);
    int reviewed = 0;
    if (rule_b) {
        reviewed = cfusa_qb_attestation_valid(existing, fresh_hash);
        fprintf(stderr, "cfusa tara: %s: threat text shows low distinct-value ratio across "
                        ">=10 entries%s\n", CFUSA_QB_RULE_B,
                reviewed ? " (suppressed by a valid attestation)" : "");
    }

    if (rule_a_hits > 0 && !rule_a_disposed) return 1;
    if (require_attestation && rule_b && !reviewed) return 1;
    return 0;
}

/* ---- rendering ---- */

static void write_threat_json(FILE *f, const asset_entry_t *a, int idx, int last)
{
    const category_profile_t *p = a->profile;
    char asset[256], threat[320];
    render_asset(asset, sizeof(asset), a);
    render_threat(threat, sizeof(threat), a);
    char esc_asset[300], esc_threat[380];
    cfusa_str_escape_json(asset, esc_asset, sizeof(esc_asset));
    cfusa_str_escape_json(threat, esc_threat, sizeof(esc_threat));
    const char *risk = derive_risk(p);
    fprintf(f,
        "    {\n"
        "      \"id\": \"TARA-%03d\",\n"
        "      \"asset\": \"%s\",\n"
        "      \"threat\": \"%s\",\n"
        "      \"attackVector\": \"%s\",\n"
        "      \"attackFeasibility\": \"%s\",\n"
        "      \"impact\": {\"safety\": \"%s\", \"financial\": \"%s\", "
                          "\"operational\": \"%s\", \"privacy\": \"%s\"},\n"
        "      \"risk\": \"%s\",\n"
        "      \"treatment\": \"%s\",\n"
        "      \"mitigations\": [",
        idx + 1, esc_asset, esc_threat, p->attack_vector, p->feasibility,
        p->safety, p->financial, p->operational, p->privacy, risk, derive_treatment(risk));
    for (int i = 0; p->mitigations[i]; i++)
        fprintf(f, "%s\"%s\"", i ? ", " : "", p->mitigations[i]);
    fprintf(f, "],\n"
              "      \"location\": {\"file\": \"%s\", \"line\": %d}\n"
              "    }%s\n",
            a->file, a->line, last ? "" : ",");
}

static void render_markdown(FILE *f, const char *project, const char *version, const char *ts,
                             int coverage_pct)
{
    fprintf(f,
        "# Threat Analysis and Risk Assessment (TARA)\n"
        "## ISO/SAE 21434:2021 Clause 15 — %s v%s\n"
        "Generated: %s\n\n"
        "Assets and threats below were discovered by a keyword-based scan of "
        "public functions handling network, file, credential, or raw-memory "
        "input (see `assetInventoryMethod` in `tara.json`) — not a formal "
        "asset inventory.\n\n"
        "---\n\n"
        "| ID | Asset | Threat | Attack Vector | Feasibility | Safety | Financial | "
        "Operational | Privacy | Risk | Treatment |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n",
        project, version, ts);
    for (int i = 0; i < g_asset_count; i++) {
        const asset_entry_t *a = &g_assets[i];
        const category_profile_t *p = a->profile;
        char asset[256], threat[320];
        render_asset(asset, sizeof(asset), a);
        render_threat(threat, sizeof(threat), a);
        const char *risk = derive_risk(p);
        fprintf(f, "| TARA-%03d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
                i + 1, asset, threat, p->attack_vector, p->feasibility,
                p->safety, p->financial, p->operational, p->privacy, risk,
                derive_treatment(risk));
    }
    if (g_asset_count == 0)
        fprintf(f, "\n_No network/file/auth/memory-input functions were found by this "
                   "heuristic scan — threats table is honestly empty, not a template row._\n");
    fprintf(f, "\n---\n_Total assets analysed: %d (%d%% of %d discovered by the scan)_\n",
            g_asset_count, coverage_pct, g_total_found);
}

int cmd_tara(int argc, char **argv)
{
    const char *dir       = ".";
    const char *output    = NULL;
    const char *output_dir= NULL;
    const char *fmt_s     = NULL;  /* NULL = both tara.json + tara.md */
    const char *attest    = NULL;
    int strict = 0, require_attestation = 0, min_coverage = 0;

    static const struct option long_opts[] = {
        {"dir",                required_argument, NULL, 'd'},
        {"output",              required_argument, NULL, 'o'},
        {"output-dir",          required_argument, NULL, 'D'},
        {"format",              required_argument, NULL, 'f'},
        {"strict",              no_argument,       NULL, 'S'},
        {"require-attestation", no_argument,       NULL, 'A'},
        {"attest",              required_argument, NULL, 'T'},
        {"min-coverage",        required_argument, NULL, 'm'},
        {"help",                no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:D:f:SAT:m:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir        = optarg; break;
        case 'o': output     = optarg; break;
        case 'D': output_dir = optarg; break;
        case 'f': fmt_s      = optarg; break;
        case 'S': strict = 1; break;
        case 'A': require_attestation = 1; break;
        case 'T': attest = optarg; break;
        case 'm': min_coverage = atoi(optarg); break;
        case 'h':
            printf("Usage: cfusa tara [--dir <path>] [--output tara.md]\n"
                   "                  [--output-dir <dir>] [--format md|json]\n"
                   "                  [--strict] [--require-attestation] [--attest <reviewer>]\n"
                   "                  [--min-coverage N]\n\n"
                   "Generates an ISO/SAE 21434 Clause 15 TARA from a keyword-based scan of\n"
                   "network/file/auth/memory-input functions.\n"
                   "Default: writes both tara.json and tara.md.\n");
            return 0;
        default: return 2;
        }
    }
    if (strict) require_attestation = 1;

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char ts[32];
    cfusa_timestamp_now(ts);

    g_asset_count = 0;
    g_total_found = 0;
    /* Deliberately the literal --dir value, not realpath(dir) — see
     * cfusa_relativize_path()'s doc comment for why. */
    strncpy(g_dir_abs, dir, sizeof(g_dir_abs) - 1);
    g_dir_abs[sizeof(g_dir_abs) - 1] = '\0';
    static const char * const exts[] = {".c"};
    cfusa_walk_sources(dir, exts, 1, asset_file, NULL);

    int coverage_pct = (g_total_found == 0) ? 100 : (g_asset_count * 100 / g_total_found);
    /* x-FuSa spec §9.2: coveragePct MUST NOT exceed 100 — see cmd_fmea.c's
     * equivalent clamp for the rationale (defense-in-depth). */
    if (coverage_pct > 100) coverage_pct = 100;

    const char *base = output_dir ? output_dir : dir;
    char existing_path[512];
    cfusa_path_join(existing_path, sizeof(existing_path), base, "tara.json");
    size_t existing_len = 0;
    char *existing_json = cfusa_read_file(existing_path, &existing_len);
    cfusa_attestation_t attestation;
    if (existing_json) cfusa_qb_attestation_read(existing_json, existing_len, &attestation);
    else memset(&attestation, 0, sizeof(attestation));
    free(existing_json);

    size_t clen = tara_canonical_content(g_canonical_buf, sizeof(g_canonical_buf));
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

    int cov_gate = 0;
    if (min_coverage > 0 && coverage_pct < min_coverage) {
        fprintf(stderr, "cfusa tara: --min-coverage gate failed: %d%% < required %d%%\n",
                coverage_pct, min_coverage);
        cov_gate = 1;
    }

#define WRITE_JSON(fp) do { \
    fprintf((fp), "{\n" \
        "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n" \
        "  \"kind\": \"tara-report\",\n" \
        "  \"tool\": \"c-FuSa\",\n" \
        "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n" \
        "  \"language\": \"c\",\n" \
        "  \"generatedAt\": \"%s\",\n" \
        "  \"project\": \"%s\",\n" \
        "  \"version\": \"%s\",\n" \
        "  \"standard\": \"iso21434\",\n" \
        "  \"threats\": [\n", \
        ts, cfg.project, cfg.version); \
    for (int i = 0; i < g_asset_count; i++) \
        write_threat_json((fp), &g_assets[i], i, i == g_asset_count - 1); \
    fprintf((fp), "  ],\n" \
        "  \"summary\": {\n" \
        "    \"assetsAnalyzed\": %d, \"assetsInProject\": %d, \"coveragePct\": %d,\n" \
        "    \"assetInventoryMethod\": \"Keyword-based scan of public C function names " \
                "against a network/file/auth/memory-input vocabulary; not a formal asset " \
                "inventory.\"\n" \
        "  }", \
        g_asset_count, g_total_found, coverage_pct); \
    /* x-FuSa spec §1.6.2 MUST (carry-forward across regeneration): carry a \
     * prior attestation forward verbatim whenever one was read back, not \
     * only when it is still hash-valid — see cmd_fmea.c's WRITE_ATTESTATION \
     * for the full rationale. */ \
    if (attestation.present) { \
        fprintf((fp), ",\n  \"attestation\": {\n" \
            "    \"status\": \"%s\",\n" \
            "    \"implementationAuthor\": \"%s\",\n" \
            "    \"independentReviewer\": \"%s\",\n" \
            "    \"reviewedAt\": \"%s\",\n" \
            "    \"contentHash\": \"%s\"\n" \
            "  }\n", \
            attestation.status[0] ? attestation.status : "heuristic", \
            attestation.implementation_author, attestation.independent_reviewer, \
            attestation.reviewed_at, attestation.content_hash); \
    } else { \
        fprintf((fp), "\n"); \
    } \
    fprintf((fp), "}\n"); \
} while (0)

    /* Specific output file requested */
    if (output) {
        FILE *f = cfusa_fopen_write(output);
        if (!f) { perror(output); return 3; }
        if (fmt_s && !strcmp(fmt_s, "json")) WRITE_JSON(f);
        else render_markdown(f, cfg.project, cfg.version, ts, coverage_pct);
        fclose(f);
        printf("TARA written to %s\n", output);
        return qb_gate || cov_gate;
    }

    /* Single format */
    if (fmt_s) {
        char out_path[512];
        const char *fname = !strcmp(fmt_s,"json") ? "tara.json" : "tara.md";
        cfusa_path_join(out_path, sizeof(out_path), base, fname);
        FILE *f = cfusa_fopen_write(out_path);
        if (!f) { perror(out_path); return 3; }
        if (!strcmp(fmt_s, "json")) WRITE_JSON(f);
        else render_markdown(f, cfg.project, cfg.version, ts, coverage_pct);
        fclose(f);
        printf("TARA written to %s\n", out_path);
        return qb_gate || cov_gate;
    }

    /* Default: write both tara.json and tara.md */
    char json_path[512], md_path[512];
    cfusa_path_join(json_path, sizeof(json_path), base, "tara.json");
    cfusa_path_join(md_path,   sizeof(md_path),   base, "tara.md");

    FILE *jf = cfusa_fopen_write(json_path);
    if (!jf) { perror(json_path); return 3; }
    WRITE_JSON(jf);
    fclose(jf);
    printf("TARA written to %s\n", json_path);

    FILE *mf = cfusa_fopen_write(md_path);
    if (!mf) { perror(md_path); return 3; }
    render_markdown(mf, cfg.project, cfg.version, ts, coverage_pct);
    fclose(mf);
    printf("TARA written to %s\n", md_path);
    printf("Assets: %d analysed, %d%% coverage of %d discovered\n",
           g_asset_count, coverage_pct, g_total_found);
    return qb_gate || cov_gate;
#undef WRITE_JSON
}
