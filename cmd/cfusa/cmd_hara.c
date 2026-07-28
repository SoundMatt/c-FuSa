#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/asil.h"
#include "cfusa/config.h"
#include "cfusa/qualitybar.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * Hazard Analysis and Risk Assessment (ISO 26262-3:2018 Clause 6).
 *
 * .fusa-hara.json is an *input* file (like .fusa-reqs.json): a project
 * author writes/maintains it; `cfusa hara` validates and reports on it
 * (x-FuSa spec §1.2.5, §9.2). Three cross-referenced collections —
 * operationalSituations[] / hazards[] / safetyGoals[] — replace this
 * tool's previous single flat "hazards[]" shape.
 *
 * Subcommands:
 *   init  — write a .fusa-hara.json skeleton (empty collections, never
 *           dummy rows — x-FuSa spec §1.6 rule 1)
 *   show  — validate + report all three collections, with completeness and
 *           referential-integrity checks, and the §1.6.1 content-quality scan
 *   asil  — compute ASIL from S/E/C parameters
 */

#define HARA_FILE        ".fusa-hara.json"
#define HARA_FILE_LEGACY ".cfusa-hara.json"
#define REQS_FILE        ".fusa-reqs.json"
#define REQS_FILE_LEGACY ".cfusa-reqs.json"

#define MAX_ITEMS   256
#define MAX_REFS     16
#define REF_LEN      32

/*
 * ISO 26262-3:2018 Table 4 ASIL determination with C0 extension is now the
 * shared cfusa_compute_asil() (src/asil.c) — also used by check's HARA006
 * rule (cmd_safety_rules.c) so both call sites are provably consistent.
 */
//cfusa:req REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005 REQ-HARA006 REQ-HARA007 REQ-HARA008 REQ-HARA009

static void do_asil(int s, int e, int c)
{
    printf("ASIL Determination (ISO 26262-3:2018 Table 4)\n");
    printf("  Severity     S%d\n", s);
    printf("  Exposure     E%d\n", e);
    printf("  Controllability C%d\n", c);
    printf("  Result       %s\n", cfusa_compute_asil(s, e, c));
}

/* Parse a "Sx"/"Ex"/"Cx" (or bare "x") code into an integer. */
static int parse_sec_code(const char *v)
{
    if (!v || !*v) return -1;
    if (isalpha((unsigned char)v[0])) v++;
    return atoi(v);
}

/* ------------------------------------------------------------------ */
/* Minimal, schema-scoped JSON reading (no generic parser — mirrors the */
/* ad hoc field-extraction style already used by cmd_req.c/cmd_disposition.c) */
/* ------------------------------------------------------------------ */

/* Extracts the balanced bracket/brace substring (inclusive) for "key":
 * starting at `open` (`{` or `[`), string-aware so a literal delimiter
 * inside a quoted value doesn't miscount depth. Caller frees the result.
 * When `end_after` is non-NULL, it's set to a pointer just past the closing
 * delimiter *within the original `json` text* — so a caller can scope a
 * subsequent sibling-key search to start there, avoiding a false match on
 * a same-named key nested *inside* this bracket (e.g. .fusa-hara.json's
 * top-level "safetyGoals" collection vs. each hazard's own nested
 * "safetyGoals": [...] reference array — see x-FuSa spec §1.2.5). */
static char *extract_bracket_at(const char *json, const char *key, char open, char close,
                                 const char **end_after)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), open);
    if (!p) return NULL;

    int depth = 0, in_str = 0;
    const char *start = p, *end = NULL;
    for (; *p; p++) {
        if (in_str) {
            if (*p == '\\') { p++; continue; }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == open) depth++;
        else if (*p == close) { depth--; if (depth == 0) { end = p; break; } }
    }
    if (!end) return NULL;
    if (end_after) *end_after = end + 1;

    size_t n = (size_t)(end - start) + 1;
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, start, n);
    out[n] = '\0';
    return out;
}

static char *extract_bracket(const char *json, const char *key, char open, char close)
{
    return extract_bracket_at(json, key, open, close, NULL);
}

/* Splits the top-level elements of a `[ ... ]` array string (objects or
 * bare strings) into `elems`, string-content unescaped/unquoted for bare
 * string elements. Returns the element count. */
static int split_array(const char *arr, char elems[][512], int max_elems)
{
    if (!arr) return 0;
    const char *p = strchr(arr, '[');
    if (!p) return 0;
    p++;
    int n = 0;
    while (*p) {
        while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r' || *p == ',') p++;
        if (*p == ']' || !*p) break;

        const char *start = p;
        int is_str = (*p == '"');
        if (*p == '{') {
            int depth = 0, in_str = 0;
            for (; *p; p++) {
                if (in_str) {
                    if (*p == '\\') { p++; continue; }
                    if (*p == '"') in_str = 0;
                    continue;
                }
                if (*p == '"') { in_str = 1; continue; }
                if (*p == '{') depth++;
                else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
            }
        } else if (is_str) {
            p++;
            while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
            if (*p == '"') p++;
        } else {
            while (*p && *p != ',' && *p != ']') p++;
        }

        size_t len = (size_t)(p - start);
        if (n < max_elems && len < 511) {
            if (is_str && len >= 2) {
                /* strip surrounding quotes for bare string elements */
                memcpy(elems[n], start + 1, len - 2);
                elems[n][len - 2] = '\0';
            } else {
                memcpy(elems[n], start, len);
                elems[n][len] = '\0';
            }
            n++;
        }
    }
    return n;
}

static void extract_str(const char *block, const char *key, char *out, size_t out_sz)
{
    out[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *fp = strstr(block, pat);
    if (!fp) return;
    fp += strlen(pat);
    while (*fp == ' ' || *fp == '\t' || *fp == '\n') fp++;
    if (*fp != '"') return;
    fp++;
    size_t k = 0;
    while (*fp && *fp != '"' && k < out_sz - 1) {
        if (*fp == '\\' && fp[1]) fp++;
        out[k++] = *fp++;
    }
    out[k] = '\0';
}

typedef struct {
    char id[REF_LEN];
    char description[256];
} os_entry_t;

typedef struct {
    char id[REF_LEN];
    char description[256];
    char source[128];
    char situations[MAX_REFS][REF_LEN]; int situations_count;
    char severity[8], exposure[8], controllability[8], asil[16];
    char safety_goals[MAX_REFS][REF_LEN]; int safety_goals_count;
} hazard_entry_t;

typedef struct {
    char id[REF_LEN];
    char description[256];
    char hazards[MAX_REFS][REF_LEN]; int hazards_count;
    char asil[16];
    char safe_state[128];
    char fssr_refs[MAX_REFS][REF_LEN]; int fssr_refs_count;
} safety_goal_entry_t;

typedef struct {
    char project[128], standard[64], created_at[40];
    os_entry_t          situations[MAX_ITEMS]; int situations_count;
    hazard_entry_t      hazards[MAX_ITEMS];    int hazards_count;
    safety_goal_entry_t goals[MAX_ITEMS];      int goals_count;
    cfusa_attestation_t attestation;
} hara_doc_t;

static void parse_hara_doc(const char *json, size_t len, hara_doc_t *doc)
{
    memset(doc, 0, sizeof(*doc));
    extract_str(json, "project", doc->project, sizeof(doc->project));
    extract_str(json, "standard", doc->standard, sizeof(doc->standard));
    extract_str(json, "createdAt", doc->created_at, sizeof(doc->created_at));
    cfusa_qb_attestation_read(json, len, &doc->attestation);

    char *os_arr = extract_bracket(json, "operationalSituations", '[', ']');
    if (os_arr) {
        char elems[MAX_ITEMS][512];
        int n = split_array(os_arr, elems, MAX_ITEMS);
        for (int i = 0; i < n && i < MAX_ITEMS; i++) {
            extract_str(elems[i], "id", doc->situations[i].id, sizeof(doc->situations[i].id));
            extract_str(elems[i], "description", doc->situations[i].description,
                         sizeof(doc->situations[i].description));
        }
        doc->situations_count = n;
        free(os_arr);
    }

    const char *hz_end_ptr = NULL;
    char *hz_arr = extract_bracket_at(json, "hazards", '[', ']', &hz_end_ptr);
    if (hz_arr) {
        char elems[MAX_ITEMS][512];
        int n = split_array(hz_arr, elems, MAX_ITEMS);
        for (int i = 0; i < n && i < MAX_ITEMS; i++) {
            hazard_entry_t *h = &doc->hazards[i];
            extract_str(elems[i], "id", h->id, sizeof(h->id));
            extract_str(elems[i], "description", h->description, sizeof(h->description));
            extract_str(elems[i], "source", h->source, sizeof(h->source));

            char *sit_arr = extract_bracket(elems[i], "situations", '[', ']');
            if (sit_arr) {
                char sub[MAX_REFS][512];
                h->situations_count = split_array(sit_arr, sub, MAX_REFS);
                for (int k = 0; k < h->situations_count; k++)
                    strncpy(h->situations[k], sub[k], REF_LEN - 1);
                free(sit_arr);
            }

            char *risk = extract_bracket(elems[i], "risk", '{', '}');
            if (risk) {
                extract_str(risk, "severity", h->severity, sizeof(h->severity));
                extract_str(risk, "exposure", h->exposure, sizeof(h->exposure));
                extract_str(risk, "controllability", h->controllability, sizeof(h->controllability));
                extract_str(risk, "asil", h->asil, sizeof(h->asil));
                free(risk);
            }

            char *sg_arr = extract_bracket(elems[i], "safetyGoals", '[', ']');
            if (sg_arr) {
                char sub[MAX_REFS][512];
                h->safety_goals_count = split_array(sg_arr, sub, MAX_REFS);
                for (int k = 0; k < h->safety_goals_count; k++)
                    strncpy(h->safety_goals[k], sub[k], REF_LEN - 1);
                free(sg_arr);
            }
        }
        doc->hazards_count = n;
        free(hz_arr);
    }

    /* Scoped to start *after* the hazards array (when present) so this
     * doesn't match the first hazard's own nested "safetyGoals": [...]
     * reference array instead of the document's top-level collection. */
    char *sg_arr_top = extract_bracket(hz_end_ptr ? hz_end_ptr : json, "safetyGoals", '[', ']');
    if (sg_arr_top) {
        char elems[MAX_ITEMS][512];
        int n = split_array(sg_arr_top, elems, MAX_ITEMS);
        for (int i = 0; i < n && i < MAX_ITEMS; i++) {
            safety_goal_entry_t *g = &doc->goals[i];
            extract_str(elems[i], "id", g->id, sizeof(g->id));
            extract_str(elems[i], "description", g->description, sizeof(g->description));
            extract_str(elems[i], "asil", g->asil, sizeof(g->asil));
            extract_str(elems[i], "safeState", g->safe_state, sizeof(g->safe_state));

            char *hz_refs = extract_bracket(elems[i], "hazards", '[', ']');
            if (hz_refs) {
                char sub[MAX_REFS][512];
                g->hazards_count = split_array(hz_refs, sub, MAX_REFS);
                for (int k = 0; k < g->hazards_count; k++)
                    strncpy(g->hazards[k], sub[k], REF_LEN - 1);
                free(hz_refs);
            }

            char *fssr = extract_bracket(elems[i], "fssrRefs", '[', ']');
            if (fssr) {
                char sub[MAX_REFS][512];
                g->fssr_refs_count = split_array(fssr, sub, MAX_REFS);
                for (int k = 0; k < g->fssr_refs_count; k++)
                    strncpy(g->fssr_refs[k], sub[k], REF_LEN - 1);
                free(fssr);
            }
        }
        doc->goals_count = n;
        free(sg_arr_top);
    }
}

static char *read_hara_file(const char *dir, size_t *len_out)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, HARA_FILE);
    char *content = cfusa_read_file(path, len_out);
    if (!content) {
        cfusa_path_join(path, sizeof(path), dir, HARA_FILE_LEGACY);
        content = cfusa_read_file(path, len_out);
    }
    return content;
}

/* Loads just the requirement ids out of .fusa-reqs.json, for fssrRefs
 * referential-integrity checking (x-FuSa spec §1.2.5). */
#define MAX_REQ_IDS 2048
static int load_req_ids(const char *dir, char ids[][REF_LEN])
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, REQS_FILE);
    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) {
        cfusa_path_join(path, sizeof(path), dir, REQS_FILE_LEGACY);
        json = cfusa_read_file(path, &len);
    }
    if (!json) return 0;

    int n = 0;
    char *p = json;
    while ((p = strstr(p, "\"id\":")) != NULL && n < MAX_REQ_IDS) {
        char id[REF_LEN] = "";
        sscanf(p, "\"id\":\"%31[^\"]", id);
        if (id[0]) { strncpy(ids[n], id, REF_LEN - 1); n++; }
        p += 5;
    }
    free(json);
    return n;
}

static int id_in_set(const char *id, char set[][REF_LEN], int n)
{
    for (int i = 0; i < n; i++)
        if (strcmp(id, set[i]) == 0) return 1;
    return 0;
}

/* Builds the RFC-8785-style canonical fragment over the document's
 * substantive content (operationalSituations/hazards/safetyGoals) —
 * object members in ASCII-lexicographic key order, no insignificant
 * whitespace — for x-FuSa spec §1.6.2 attestation content-hashing.
 * Excludes `attestation` itself and any generatedAt/tool provenance, per
 * spec. Truncates silently on overflow (bufsz is sized generously by the
 * caller; a truncated-but-still-deterministic hash only ever produces a
 * false "stale" verdict, never a false "valid" one, so this is fail-safe). */
static size_t append_ref_array(char *buf, size_t bufsz, size_t off,
                                char refs[][REF_LEN], int n)
{
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "[");
    for (int i = 0; i < n; i++)
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
                                 "%s\"%s\"", i ? "," : "", refs[i]);
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "]");
    return off;
}

static size_t hara_canonical_content(hara_doc_t *doc, char *buf, size_t bufsz)
{
    size_t off = 0;
    char esc[256];

    off += (size_t)snprintf(buf + off, bufsz - off, "{\"hazards\":[");
    for (int i = 0; i < doc->hazards_count; i++) {
        hazard_entry_t *h = &doc->hazards[i];
        cfusa_str_escape_json(h->description, esc, sizeof(esc));
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            "%s{\"asil\":\"%s\",\"controllability\":\"%s\",\"description\":\"%s\","
            "\"exposure\":\"%s\",\"id\":\"%s\",\"safetyGoals\":",
            i ? "," : "", h->asil, h->controllability, esc, h->exposure, h->id);
        off = append_ref_array(buf, bufsz, off, h->safety_goals, h->safety_goals_count);
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            ",\"severity\":\"%s\",\"situations\":", h->severity);
        off = append_ref_array(buf, bufsz, off, h->situations, h->situations_count);
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            ",\"source\":\"%s\"}", h->source);
    }
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
                             "],\"operationalSituations\":[");
    for (int i = 0; i < doc->situations_count; i++) {
        cfusa_str_escape_json(doc->situations[i].description, esc, sizeof(esc));
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            "%s{\"description\":\"%s\",\"id\":\"%s\"}",
            i ? "," : "", esc, doc->situations[i].id);
    }
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "],\"safetyGoals\":[");
    for (int i = 0; i < doc->goals_count; i++) {
        safety_goal_entry_t *g = &doc->goals[i];
        cfusa_str_escape_json(g->description, esc, sizeof(esc));
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            "%s{\"asil\":\"%s\",\"description\":\"%s\",\"fssrRefs\":",
            i ? "," : "", g->asil, esc);
        off = append_ref_array(buf, bufsz, off, g->fssr_refs, g->fssr_refs_count);
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, ",\"hazards\":");
        off = append_ref_array(buf, bufsz, off, g->hazards, g->hazards_count);
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            ",\"id\":\"%s\",\"safeState\":\"%s\"}", g->id, g->safe_state);
    }
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "]}");
    return off;
}

/* ------------------------------------------------------------------ */
/* init                                                                 */
/* ------------------------------------------------------------------ */

static int do_init(const char *dir, const char *project)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, HARA_FILE);

    if (cfusa_file_exists(path)) {
        fprintf(stderr, "cfusa hara init: %s already exists\n", HARA_FILE);
        return 2;
    }

    FILE *f = cfusa_fopen_write(path);
    if (!f) { perror(path); return 3; }

    char ts[32]; cfusa_timestamp_now(ts);
    char esc_project[256];
    cfusa_str_escape_json(project, esc_project, sizeof(esc_project));

    /* x-FuSa spec §1.6 rule 1: an unanalyzed section MUST be an empty
     * array, never a dummy/placeholder row. */
    fprintf(f,
        "{\n"
        "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
        "  \"kind\": \"hara\",\n"
        "  \"tool\": \"c-FuSa\",\n"
        "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
        "  \"language\": \"c\",\n"
        "  \"project\": \"%s\",\n"
        "  \"standard\": \"iso26262\",\n"
        "  \"createdAt\": \"%s\",\n"
        "  \"operationalSituations\": [],\n"
        "  \"hazards\": [],\n"
        "  \"safetyGoals\": []\n"
        "}\n",
        esc_project, ts);
    fclose(f);

    printf("HARA skeleton written to %s\n", path);
    printf("Edit operationalSituations/hazards/safetyGoals and run 'cfusa hara show' to review.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* show — text                                                         */
/* ------------------------------------------------------------------ */

/* Runs the x-FuSa spec §1.6.1 content-quality scan over every qualitative
 * field in `doc`. Returns the number of Rule A (always-ERROR,
 * disposition-suppressible-only) hits still outstanding after disposition
 * lookup, for the caller's exit-code decision. Rule B is advisory
 * (WARNING) unless `require_attestation`, and is suppressed entirely by a
 * valid, non-stale, independent attestation. */
static int run_quality_bar(const char *dir, hara_doc_t *doc, int require_attestation,
                            FILE *out, int quiet)
{
    int rule_a_hits = 0, rule_a_disposed = 0;
    const char *texts[3 * MAX_ITEMS];
    int ntext = 0;

    for (int i = 0; i < doc->situations_count; i++) {
        const char *d = doc->situations[i].description;
        if (cfusa_qb_is_stub_text(d)) {
            rule_a_hits++;
            if (!quiet) fprintf(out, "  [ERROR] %s operationalSituations[%s].description contains placeholder text\n",
                                 CFUSA_QB_RULE_A, doc->situations[i].id);
        }
        if (d[0]) texts[ntext++] = d;
    }
    for (int i = 0; i < doc->hazards_count; i++) {
        const char *d = doc->hazards[i].description;
        if (cfusa_qb_is_stub_text(d)) {
            rule_a_hits++;
            if (!quiet) fprintf(out, "  [ERROR] %s hazards[%s].description contains placeholder text\n",
                                 CFUSA_QB_RULE_A, doc->hazards[i].id);
        }
        if (d[0]) texts[ntext++] = d;
    }
    for (int i = 0; i < doc->goals_count; i++) {
        const char *d = doc->goals[i].description;
        if (cfusa_qb_is_stub_text(d)) {
            rule_a_hits++;
            if (!quiet) fprintf(out, "  [ERROR] %s safetyGoals[%s].description contains placeholder text\n",
                                 CFUSA_QB_RULE_A, doc->goals[i].id);
        }
        if (d[0]) texts[ntext++] = d;
    }

    if (rule_a_hits > 0 && cfusa_qb_rule_disposed(dir, CFUSA_QB_RULE_A)) {
        rule_a_disposed = 1;
        if (!quiet) fprintf(out, "  (%s disposed — see cfusa disposition list)\n", CFUSA_QB_RULE_A);
    }

    int rule_b = cfusa_qb_rule_b_flagged(texts, ntext);
    if (rule_b) {
        char canonical[16384];
        size_t clen = hara_canonical_content(doc, canonical, sizeof(canonical));
        if (clen >= sizeof(canonical)) clen = sizeof(canonical) - 1;
        char fresh[80];
        cfusa_qb_content_hash(canonical, clen, fresh);
        int reviewed = cfusa_qb_attestation_valid(&doc->attestation, fresh);
        if (!reviewed && !quiet)
            fprintf(out, "  [WARNING] %s hazard/safety-goal descriptions show low distinct-value "
                         "ratio across >=10 entries (possible templated content)\n", CFUSA_QB_RULE_B);
        rule_b = (!reviewed && require_attestation) ? 1 : 0;
    }

    if (rule_a_hits > 0 && !rule_a_disposed) return 1;   /* Rule A always gates unless disposed */
    if (require_attestation && rule_b) return 1;
    return 0;
}

static void print_completeness(FILE *out, hara_doc_t *doc, const char *dir)
{
    int total_hazards = doc->hazards_count;
    int hazards_with_asil = 0, hazards_with_sg = 0;
    int total_goals = doc->goals_count;
    int goals_with_fssr = 0;
    int dangling = 0;

    for (int i = 0; i < total_hazards; i++) {
        hazard_entry_t *h = &doc->hazards[i];
        if (h->asil[0]) hazards_with_asil++;
        if (h->safety_goals_count > 0) hazards_with_sg++;
        for (int k = 0; k < h->situations_count; k++) {
            int found = 0;
            for (int s = 0; s < doc->situations_count; s++)
                if (strcmp(h->situations[k], doc->situations[s].id) == 0) { found = 1; break; }
            if (!found) dangling++;
        }
        for (int k = 0; k < h->safety_goals_count; k++) {
            int found = 0;
            for (int g = 0; g < doc->goals_count; g++)
                if (strcmp(h->safety_goals[k], doc->goals[g].id) == 0) { found = 1; break; }
            if (!found) dangling++;
        }
    }

    char req_ids[MAX_REQ_IDS][REF_LEN];
    int req_count = load_req_ids(dir, req_ids);

    for (int i = 0; i < total_goals; i++) {
        safety_goal_entry_t *g = &doc->goals[i];
        if (g->fssr_refs_count > 0) goals_with_fssr++;
        for (int k = 0; k < g->hazards_count; k++) {
            int found = 0;
            for (int h = 0; h < doc->hazards_count; h++)
                if (strcmp(g->hazards[k], doc->hazards[h].id) == 0) { found = 1; break; }
            if (!found) dangling++;
        }
        for (int k = 0; k < g->fssr_refs_count; k++) {
            if (req_count == 0 || !id_in_set(g->fssr_refs[k], req_ids, req_count)) dangling++;
        }
    }

    fprintf(out, "\nCompleteness:\n");
    fprintf(out, "  totalHazards:            %d\n", total_hazards);
    fprintf(out, "  hazardsWithAsil:         %d\n", hazards_with_asil);
    fprintf(out, "  hazardsWithSafetyGoal:   %d\n", hazards_with_sg);
    fprintf(out, "  safetyGoalsWithFssrRefs: %d / %d\n", goals_with_fssr, total_goals);
    fprintf(out, "  danglingReferences:      %d\n", dangling);
    if (total_goals > 0 && goals_with_fssr < total_goals)
        fprintf(out, "  WARNING: %d safety goal(s) missing fssrRefs (MUST, >=1 entry — x-FuSa spec §1.2.5)\n",
                total_goals - goals_with_fssr);
}

static int do_show(const char *dir, FILE *out, int require_attestation)
{
    size_t len;
    char *content = read_hara_file(dir, &len);
    if (!content) {
        fprintf(stderr, "cfusa hara: no %s found — run 'cfusa hara init' first\n", HARA_FILE);
        return 3;
    }

    hara_doc_t doc;
    parse_hara_doc(content, len, &doc);
    free(content);

    fprintf(out, "Hazard Analysis and Risk Assessment\n");
    fprintf(out, "=====================================\n");
    fprintf(out, "Project: %s   Standard: %s\n", doc.project, doc.standard);

    fprintf(out, "\nOperational Situations (%d):\n", doc.situations_count);
    for (int i = 0; i < doc.situations_count; i++)
        fprintf(out, "  %-10s %s\n", doc.situations[i].id, doc.situations[i].description);

    fprintf(out, "\nHazards (%d):\n", doc.hazards_count);
    for (int i = 0; i < doc.hazards_count; i++) {
        hazard_entry_t *h = &doc.hazards[i];
        int s = parse_sec_code(h->severity), e = parse_sec_code(h->exposure),
            c = parse_sec_code(h->controllability);
        const char *computed = cfusa_compute_asil(s, e, c);
        fprintf(out, "\n%s  [%s]\n", h->id, h->asil[0] ? h->asil : "(no asil)");
        fprintf(out, "  Description: %s\n", h->description);
        fprintf(out, "  %s/%s/%s\n", h->severity, h->exposure, h->controllability);
        if (h->asil[0] && strcmp(computed, h->asil) != 0)
            fprintf(out, "  WARNING: stored ASIL %s differs from computed %s\n", h->asil, computed);
    }

    fprintf(out, "\nSafety Goals (%d):\n", doc.goals_count);
    for (int i = 0; i < doc.goals_count; i++) {
        safety_goal_entry_t *g = &doc.goals[i];
        fprintf(out, "\n%s  [%s]\n", g->id, g->asil[0] ? g->asil : "(no asil)");
        fprintf(out, "  Description: %s\n", g->description);
        fprintf(out, "  fssrRefs: %d\n", g->fssr_refs_count);
        if (g->fssr_refs_count == 0)
            fprintf(out, "  WARNING: no fssrRefs (MUST, >=1 entry per x-FuSa spec §1.2.5)\n");
    }

    print_completeness(out, &doc, dir);

    fprintf(out, "\nContent-quality scan (x-FuSa spec §1.6.1):\n");
    int gate = run_quality_bar(dir, &doc, require_attestation, out, 0);

    if (doc.situations_count == 0 && doc.hazards_count == 0 && doc.goals_count == 0)
        fprintf(out, "\n(No hazards/safety-goals/operational-situations recorded yet.)\n");

    return gate;
}

static int do_show_json(const char *dir, FILE *out, int require_attestation)
{
    size_t len;
    char *content = read_hara_file(dir, &len);
    if (!content) {
        fprintf(stderr, "cfusa hara: no %s found — run 'cfusa hara init' first\n", HARA_FILE);
        return 3;
    }

    hara_doc_t doc;
    parse_hara_doc(content, len, &doc);

    int total_hazards = doc.hazards_count, hazards_with_asil = 0, hazards_with_sg = 0;
    int goals_with_fssr = 0, dangling = 0, asil_mismatches = 0;
    for (int i = 0; i < total_hazards; i++) {
        hazard_entry_t *h = &doc.hazards[i];
        if (h->asil[0]) hazards_with_asil++;
        if (h->safety_goals_count > 0) hazards_with_sg++;
        /* x-FuSa spec §1.2.5: risk.asil MUST derive from S×E×C (ISO 26262-3
         * Table 4) — cross-check the stored value the same way `hara show`
         * (text) already warns about, but surface it in the JSON
         * completeness block too so it's machine-checkable, not just a
         * human-readable warning line. */
        if (h->asil[0] && h->severity[0] && h->exposure[0] && h->controllability[0]) {
            int s = parse_sec_code(h->severity), e = parse_sec_code(h->exposure),
                c = parse_sec_code(h->controllability);
            if (strcmp(cfusa_compute_asil(s, e, c), h->asil) != 0) asil_mismatches++;
        }
    }
    char req_ids[MAX_REQ_IDS][REF_LEN];
    int req_count = load_req_ids(dir, req_ids);
    for (int i = 0; i < doc.goals_count; i++) {
        if (doc.goals[i].fssr_refs_count > 0) goals_with_fssr++;
        for (int k = 0; k < doc.goals[i].fssr_refs_count; k++)
            if (req_count == 0 || !id_in_set(doc.goals[i].fssr_refs[k], req_ids, req_count)) dangling++;
    }

    char ts[32]; cfusa_timestamp_now(ts);

    fprintf(out,
        "{\n"
        "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
        "  \"kind\": \"hara-report\",\n"
        "  \"tool\": \"c-FuSa\",\n"
        "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
        "  \"language\": \"c\",\n"
        "  \"generatedAt\": \"%s\",\n"
        "  \"project\": \"%s\",\n"
        "  \"standard\": \"%s\",\n",
        ts, doc.project, doc.standard);

    fprintf(out, "  \"operationalSituations\": [\n");
    for (int i = 0; i < doc.situations_count; i++) {
        char esc[256]; cfusa_str_escape_json(doc.situations[i].description, esc, sizeof(esc));
        fprintf(out, "    {\"id\": \"%s\", \"description\": \"%s\"}%s\n",
                doc.situations[i].id, esc, (i < doc.situations_count - 1) ? "," : "");
    }
    fprintf(out, "  ],\n");

    /* x-FuSa spec §9.2: `hara --format json` MUST be a verbatim passthrough
     * of .fusa-hara.json's own §1.2.5 shape — source/situations/safetyGoals
     * on each hazard, and hazards/safeState on each safety goal, not just
     * the id/description/risk subset. */
    fprintf(out, "  \"hazards\": [\n");
    for (int i = 0; i < doc.hazards_count; i++) {
        hazard_entry_t *h = &doc.hazards[i];
        char esc[256]; cfusa_str_escape_json(h->description, esc, sizeof(esc));
        char esc_src[128]; cfusa_str_escape_json(h->source, esc_src, sizeof(esc_src));
        fprintf(out, "    {\"id\": \"%s\", \"description\": \"%s\", \"source\": \"%s\", "
                     "\"situations\": [",
                h->id, esc, esc_src);
        for (int k = 0; k < h->situations_count; k++)
            fprintf(out, "%s\"%s\"", k ? ", " : "", h->situations[k]);
        fprintf(out, "], \"risk\": "
                     "{\"severity\": \"%s\", \"exposure\": \"%s\", \"controllability\": \"%s\", "
                     "\"asil\": \"%s\"}, \"safetyGoals\": [",
                h->severity, h->exposure, h->controllability, h->asil);
        for (int k = 0; k < h->safety_goals_count; k++)
            fprintf(out, "%s\"%s\"", k ? ", " : "", h->safety_goals[k]);
        fprintf(out, "]}%s\n", (i < doc.hazards_count - 1) ? "," : "");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"safetyGoals\": [\n");
    for (int i = 0; i < doc.goals_count; i++) {
        safety_goal_entry_t *g = &doc.goals[i];
        char esc[256]; cfusa_str_escape_json(g->description, esc, sizeof(esc));
        char esc_safe[128]; cfusa_str_escape_json(g->safe_state, esc_safe, sizeof(esc_safe));
        fprintf(out, "    {\"id\": \"%s\", \"description\": \"%s\", \"hazards\": [",
                g->id, esc);
        for (int k = 0; k < g->hazards_count; k++)
            fprintf(out, "%s\"%s\"", k ? ", " : "", g->hazards[k]);
        fprintf(out, "], \"asil\": \"%s\", \"safeState\": \"%s\", \"fssrRefs\": [",
                g->asil, esc_safe);
        for (int k = 0; k < g->fssr_refs_count; k++)
            fprintf(out, "%s\"%s\"", k ? ", " : "", g->fssr_refs[k]);
        fprintf(out, "]}%s\n", (i < doc.goals_count - 1) ? "," : "");
    }
    fprintf(out, "  ],\n");

    fprintf(out,
        "  \"completeness\": {\n"
        "    \"totalHazards\": %d, \"hazardsWithAsil\": %d, \"hazardsWithSafetyGoal\": %d,\n"
        "    \"safetyGoalsWithFssrRefs\": %d, \"danglingReferences\": %d, "
        "\"asilMismatches\": %d\n"
        "  }",
        total_hazards, hazards_with_asil, hazards_with_sg, goals_with_fssr, dangling,
        asil_mismatches);

    /* x-FuSa spec §1.6.2: an attestation on the input file is a passthrough
     * into the report, not something `hara` re-derives (it has no --attest
     * flag of its own — the attestation is authored alongside the rest of
     * .fusa-hara.json). */
    if (doc.attestation.present) {
        fprintf(out,
            ",\n  \"attestation\": {\n"
            "    \"status\": \"%s\",\n"
            "    \"implementationAuthor\": \"%s\",\n"
            "    \"independentReviewer\": \"%s\",\n"
            "    \"reviewedAt\": \"%s\",\n"
            "    \"contentHash\": \"%s\"\n"
            "  }\n",
            doc.attestation.status[0] ? doc.attestation.status : "heuristic",
            doc.attestation.implementation_author, doc.attestation.independent_reviewer,
            doc.attestation.reviewed_at, doc.attestation.content_hash);
    } else {
        fprintf(out, "\n");
    }
    fprintf(out, "}\n");

    /* Quality-bar scan drives the exit code but is not re-printed as JSON
     * members here (this document mirrors the x-FuSa spec §9.2 shape
     * verbatim); it still gates like `show` (text) does. */
    int gate = run_quality_bar(dir, &doc, require_attestation, stderr, 1);

    free(content);
    return gate;
}

int cmd_hara(int argc, char **argv)
{
    const char *subcmd  = "show";
    const char *dir     = ".";
    const char *format  = "text";
    const char *output  = NULL;
    int s = -1, e = -1, c = -1;
    int strict = 0, require_attestation = 0;

    static const struct option long_opts[] = {
        {"dir",                required_argument, NULL, 'd'},
        {"format",              required_argument, NULL, 'F'},
        {"output",              required_argument, NULL, 'o'},
        {"severity",            required_argument, NULL, 's'},
        {"exposure",            required_argument, NULL, 'e'},
        {"controllability",     required_argument, NULL, 'c'},
        {"strict",              no_argument,       NULL, 'S'},
        {"require-attestation", no_argument,       NULL, 'A'},
        {"help",                no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    /* First non-option arg is subcommand */
    if (argc >= 2 && argv[1][0] != '-') {
        subcmd = argv[1];
        argv++;
        argc--;
    }

    int opt;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "d:F:o:s:e:c:SAh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd': dir    = optarg; break;
        case 'F': format = optarg; break;
        case 'o': output = optarg; break;
        case 's': { const char *v = optarg; if (v[0]=='S'||v[0]=='s') v++; s = atoi(v); break; }
        case 'e': { const char *v = optarg; if (v[0]=='E'||v[0]=='e') v++; e = atoi(v); break; }
        case 'c': { const char *v = optarg; if (v[0]=='C'||v[0]=='c') v++; c = atoi(v); break; }
        case 'S': strict = 1; break;
        case 'A': require_attestation = 1; break;
        case 'h':
            printf("Usage: cfusa hara <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  init   Write a .fusa-hara.json skeleton\n"
                   "  show   Validate + report all hazard/safety-goal entries\n"
                   "  asil   Compute ASIL from S/E/C parameters\n\n"
                   "Options for 'show':\n"
                   "  --format text|json|markdown  Output format (default: text)\n"
                   "  --output <file>              Write output to file (default: stdout)\n"
                   "  --strict                     Implies --require-attestation\n"
                   "  --require-attestation        Escalate an unsuppressed FUSA-STUB002 to exit 1\n\n"
                   "Options for 'asil':\n"
                   "  --severity N        Severity class S0-S3 (0-3, per ISO 26262-3 Table 4)\n"
                   "  --exposure N        Exposure class E0-E4 (0-4)\n"
                   "  --controllability N Controllability class C0-C3 (0-3)\n\n"
                   "ISO 26262-3:2018 Clause 6 — Hazard Analysis and Risk Assessment.\n");
            return 0;
        default: return 2;
        }
    }
    if (strict) require_attestation = 1;

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "init")) {
        return do_init(dir, cfg.project);
    } else if (!strcmp(subcmd, "asil")) {
        if (s < 0 || e < 0 || c < 0) {
            fprintf(stderr, "cfusa hara asil: requires --severity, --exposure, --controllability\n");
            return 2;
        }
        do_asil(s, e, c);
        return 0;
    } else if (!strcmp(subcmd, "show")) {
        FILE *out = stdout;
        if (output) {
            out = cfusa_fopen_write(output);
            if (!out) { perror(output); return 3; }
        }
        int rc;
        if (!strcmp(format, "json"))
            rc = do_show_json(dir, out, require_attestation);
        else
            rc = do_show(dir, out, require_attestation);
        /* markdown output not yet formalized for the new schema; fall back
         * to the text report rather than emit stale field names. */
        if (output && out != stdout) fclose(out);
        return rc;
    } else {
        fprintf(stderr, "cfusa hara: unknown subcommand '%s' (init|show|asil)\n", subcmd);
        return 2;
    }
}
