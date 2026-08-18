/*
 * cmd_safety_rules.c — Project-level safety engine rules.
 *
 * Registers rules that run during `cfusa check`:
 *   HARA001-006   — HARA file and content validation (ISO 26262-3)
 *   ISO26262001-3 — ISO 26262 evidence and qualification checks
 *   DUPREQ001     — Duplicate requirement ids (x-FuSa spec §1.2.2)
 *   COUP001-003   — Data/control coupling (DO-178C §6.4.4.3)
 *   DISP001       — Undispositioned ERROR findings
 *   COMP001       — Cyclomatic complexity (DO-178C §6.3.4)
 */
#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cfusa/asil.h"
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/severity.h"
#include "cfusa/utils.h"

//cfusa:req REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005 REQ-HARA010
//cfusa:req REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
//cfusa:req REQ-DISP001 REQ-COMP001 REQ-DUPREQ001

/* ── File helpers ────────────────────────────────────────────────────── */

static int path_exists(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

static char *read_file_at(const char *dir, const char *name, size_t *out_len)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return cfusa_read_file(path, out_len);
}

/* Finds the balanced `open`...`close` substring for the first `"key"` at or
 * after `from` (string-aware, so a literal delimiter inside a quoted value
 * doesn't miscount depth). Sets *end_after to just past the closing
 * delimiter and returns a pointer to the opening delimiter, or NULL. Used
 * to scope a scan to (e.g.) .fusa-hara.json's "hazards": [...] array so it
 * doesn't also match "id"/"asil" fields belonging to the sibling
 * operationalSituations[]/safetyGoals[] collections (x-FuSa spec §1.2.5). */
static const char *json_bracket(const char *from, const char *key,
                                 char open, char close, const char **end_after)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(from, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), open);
    if (!p) return NULL;

    int depth = 0, in_str = 0;
    const char *start = p;
    for (; *p; p++) {
        if (in_str) {
            if (*p == '\\') { p++; continue; }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == open) depth++;
        else if (*p == close) {
            depth--;
            if (depth == 0) { if (end_after) *end_after = p + 1; return start; }
        }
    }
    return NULL;
}

/* Extracts a quoted string field's value from `block` (bounded at `blk_end`). */
static void json_str_field(const char *block, const char *blk_end, const char *key,
                            char *out, size_t out_sz)
{
    out[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *fp = strstr(block, pat);
    if (!fp || (blk_end && fp >= blk_end)) return;
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

/* Parses a "Sx"/"Ex"/"Cx" (or bare "x") risk code into an integer, -1 when
 * absent/unparseable. Mirrors cmd_hara.c's parse_sec_code(). */
static int json_sec_code(const char *v)
{
    if (!v || !*v) return -1;
    if (isalpha((unsigned char)v[0])) v++;
    if (!*v) return -1;
    return atoi(v);
}

/* ── HARA001 — .fusa-hara.json must be present ───────────────────────── */

static int rule_hara001(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, ".fusa-hara.json") &&
        !path_exists(dir, ".cfusa-hara.json")) {
        cfusa_report_add(rpt, "HARA001", "safety", SEV_ERROR,
            dir, 0,
            ".fusa-hara.json not found — run 'cfusa hara init' to create it "
            "(ISO 26262-3 Clause 6 requires a HARA document)");
        return 1;
    }
    return 0;
}

/* ── HARA002 — hazard risk ratings complete (S, E, C all non-zero) ────── */

static int rule_hara002(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len; char *json = read_file_at(dir, ".fusa-hara.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-hara.json", &len);
    if (!json) return 0; /* HARA001 already fired */

    /* x-FuSa spec §1.2.5: risk ratings live in each hazard's nested "risk"
     * object as "Sx"/"Ex"/"Cx" strings, not flat integer fields — and the
     * scan MUST be scoped to the "hazards" array so it doesn't also walk
     * the sibling operationalSituations[]/safetyGoals[] collections'
     * unrelated "id" entries. */
    const char *hz_end = NULL;
    const char *hz_start = json_bracket(json, "hazards", '[', ']', &hz_end);

    int findings = 0;
    if (hz_start) {
        const char *p = hz_start;
        while ((p = strstr(p, "\"id\"")) != NULL && p < hz_end) {
            char id[64] = "";
            const char *blk = p;
            const char *blk_end = strstr(blk + 1, "\"id\"");
            if (!blk_end || blk_end > hz_end) blk_end = hz_end;

            json_str_field(blk, blk_end, "id", id, sizeof(id));

            const char *risk_end = NULL;
            const char *risk = json_bracket(blk, "risk", '{', '}', &risk_end);
            int sev = -1, exp = -1, ctl = -1;
            if (risk && risk < blk_end) {
                char sevs[8] = "", exps[8] = "", ctls[8] = "";
                json_str_field(risk, risk_end, "severity", sevs, sizeof(sevs));
                json_str_field(risk, risk_end, "exposure", exps, sizeof(exps));
                json_str_field(risk, risk_end, "controllability", ctls, sizeof(ctls));
                sev = json_sec_code(sevs);
                exp = json_sec_code(exps);
                ctl = json_sec_code(ctls);
            }

            if (id[0] && (sev < 0 || exp < 0 || ctl < 0)) {
                cfusa_report_add(rpt, "HARA002", "safety", SEV_ERROR,
                    ".fusa-hara.json", 0,
                    "hazard '%s' has an incomplete risk rating (missing/unparseable "
                    "risk.severity/exposure/controllability); ISO 26262-3 Clause 6.4 "
                    "requires all three (x-FuSa spec §1.2.5)",
                    id);
                findings++;
            }
            p = blk_end;
        }
    }
    free(json);
    return findings;
}

/* ── HARA003 — every hazard must have a safety goal ─────────────────── */

static int rule_hara003(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len; char *json = read_file_at(dir, ".fusa-hara.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-hara.json", &len);
    if (!json) return 0;

    /* x-FuSa spec §1.2.5: a hazard's safety goal(s) live in its
     * "safetyGoals": [...] reference array (>=1 entry required), not a
     * single "safety_goal" string field — scoped to "hazards" for the same
     * reason as HARA002. */
    const char *hz_end = NULL;
    const char *hz_start = json_bracket(json, "hazards", '[', ']', &hz_end);

    int findings = 0;
    if (hz_start) {
        const char *p = hz_start;
        while ((p = strstr(p, "\"id\"")) != NULL && p < hz_end) {
            char id[64] = "";
            const char *blk = p;
            const char *blk_end = strstr(blk + 1, "\"id\"");
            if (!blk_end || blk_end > hz_end) blk_end = hz_end;

            json_str_field(blk, blk_end, "id", id, sizeof(id));

            const char *sg_end = NULL;
            const char *sg = json_bracket(blk, "safetyGoals", '[', ']', &sg_end);
            int has_goal = 0;
            if (sg && sg < blk_end) {
                for (const char *q = sg; q < sg_end; q++)
                    if (*q == '"') { has_goal = 1; break; }
            }

            if (id[0] && !has_goal) {
                cfusa_report_add(rpt, "HARA003", "safety", SEV_ERROR,
                    ".fusa-hara.json", 0,
                    "hazard '%s' has no safetyGoals reference — ISO 26262-3 §6.4.9 "
                    "requires every hazard to drive at least one safety goal "
                    "(x-FuSa spec §1.2.5)", id);
                findings++;
            }
            p = blk_end;
        }
    }
    free(json);
    return findings;
}

/* ── HARA004 — safety goals must have ASIL assigned ─────────────────── */

/* Shared by rule_hara004: scans one already-bracket-scoped collection
 * ("hazards", where asil lives nested in "risk", or "safetyGoals", where
 * it's a direct field) for entries with a missing/placeholder asil.
 * `search_from` lets the caller scope the collection lookup itself — the
 * top-level "safetyGoals" collection must be searched for *after* the
 * "hazards" array ends, since each hazard also carries its own nested
 * "safetyGoals": [...] reference array under the same key name (x-FuSa
 * spec §1.2.5). When `end_after` is non-NULL it receives a pointer just
 * past this collection's closing bracket, for exactly that chaining. */
static int hara004_scan(const char *json, const char *search_from, const char *collection_key,
                         int asil_is_nested, cfusa_report_t *rpt, const char **end_after)
{
    const char *end = NULL;
    const char *start = json_bracket(search_from ? search_from : json, collection_key,
                                      '[', ']', &end);
    if (end_after) *end_after = end;
    if (!start) return 0;

    int findings = 0;
    const char *p = start;
    while ((p = strstr(p, "\"id\"")) != NULL && p < end) {
        char id[64] = "", asil[32] = "";
        const char *blk = p;
        const char *blk_end = strstr(blk + 1, "\"id\"");
        if (!blk_end || blk_end > end) blk_end = end;

        json_str_field(blk, blk_end, "id", id, sizeof(id));

        if (asil_is_nested) {
            const char *risk_end = NULL;
            const char *risk = json_bracket(blk, "risk", '{', '}', &risk_end);
            if (risk && risk < blk_end)
                json_str_field(risk, risk_end, "asil", asil, sizeof(asil));
        } else {
            json_str_field(blk, blk_end, "asil", asil, sizeof(asil));
        }

        if (id[0] && (asil[0] == '\0' || strcmp(asil, "TBD") == 0 ||
                      strcmp(asil, "unknown") == 0)) {
            cfusa_report_add(rpt, "HARA004", "safety", SEV_WARNING,
                ".fusa-hara.json", 0,
                "'%s' has undetermined ASIL '%s' — "
                "must be QM, ASIL-A, B, C, or D (ISO 26262-3 §6.4.6)",
                id, asil[0] ? asil : "(empty)");
            findings++;
        }
        p = blk_end;
    }
    return findings;
}

static int rule_hara004(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len; char *json = read_file_at(dir, ".fusa-hara.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-hara.json", &len);
    if (!json) return 0;

    /* x-FuSa spec §1.2.5: both hazards[].risk.asil and safetyGoals[].asil
     * are MUST fields; operationalSituations[] carries no asil and is
     * deliberately excluded from this scan. */
    const char *hz_end = NULL;
    int findings = hara004_scan(json, json, "hazards", 1, rpt, &hz_end);
    findings += hara004_scan(json, hz_end ? hz_end : json, "safetyGoals", 0, rpt, NULL);
    free(json);
    return findings;
}

/* ── HARA005 — max hazard ASIL must not exceed project ASIL ─────────── */

/* ASIL ranking is the shared cfusa_asil_rank() (include/cfusa/severity.h)
 * — previously a local copy here, consolidated so this and every other
 * ASIL/DAL-scaled gate (see issue #104) rank ASIL strings identically. */

static int rule_hara005(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    size_t len; char *json = read_file_at(dir, ".fusa-hara.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-hara.json", &len);
    if (!json) return 0;

    /* Determine project ASIL from config standards */
    int proj_rank = 4; /* default ASIL-D (strictest) — no false negatives */
    char proj_asil[32] = "ASIL-D";
    for (int i = 0; i < cfg->standards_count; i++) {
        const char *s = cfg->standards[i];
        if (strncmp(s, "iso26262", 8) == 0 || strncmp(s, "ISO 26262", 9) == 0) {
            /* Look for ASIL annotation in standard string, e.g. "iso26262:ASIL-B" */
            const char *colon = strchr(s, ':');
            if (colon) {
                snprintf(proj_asil, sizeof(proj_asil), "%s", colon + 1);
                proj_rank = cfusa_asil_rank(proj_asil);
            }
        }
    }

    int max_haz_rank = 0;
    char max_haz_asil[32] = "QM";
    char max_haz_id[64]   = "";

    const char *p = json;
    while ((p = strstr(p, "\"asil\"")) != NULL) {
        char asil[32] = "";
        const char *fp = p + 6;
        while (*fp == ':' || *fp == ' ') fp++;
        if (*fp == '"') fp++;
        sscanf(fp, "%31[^\"]", asil);
        int r = cfusa_asil_rank(asil);
        if (r > max_haz_rank) {
            max_haz_rank = r;
            strncpy(max_haz_asil, asil, sizeof(max_haz_asil) - 1);
            /* Try to get the id of this hazard */
            const char *blk = p;
            while (blk > json && *(blk-1) != '}') blk--;
            char *idp = strstr(blk, "\"id\":");
            if (idp) {
                idp += 5; while (*idp==' ') idp++;
                if (*idp=='"') idp++;
                sscanf(idp, "%63[^\"]", max_haz_id);
            }
        }
        p++;
    }
    free(json);

    if (proj_rank >= 0 && max_haz_rank > proj_rank) {
        cfusa_report_add(rpt, "HARA005", "safety", SEV_ERROR,
            ".fusa-hara.json", 0,
            "hazard '%s' has ASIL %s which exceeds project ASIL %s "
            "(ISO 26262-3 §6.4.6 — update project config or review HARA)",
            max_haz_id[0] ? max_haz_id : "?", max_haz_asil, proj_asil);
        return 1;
    }
    return 0;
}

/* ── HARA006 — stored ASIL must match the S×E×C table (x-FuSa spec §1.2.5) ── */

/* `hara show` (text mode) has long printed a "stored ASIL differs from
 * computed" warning line, but that never became a `Finding` and never
 * gated `check`'s exit code — a hazard could carry a self-consistent-
 * looking but wrong ASIL and pass every machine-readable gate. This rule
 * recomputes ISO 26262-3 Table 4 from each hazard's own S/E/C and compares
 * it to the stored risk.asil, the same way cmd_hara.c's do_show()/
 * do_show_json() now do (via the shared cfusa_compute_asil()), so the
 * mismatch also surfaces here where it can fail `check`. */
static int rule_hara006(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len; char *json = read_file_at(dir, ".fusa-hara.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-hara.json", &len);
    if (!json) return 0; /* HARA001 already fired */

    const char *hz_end = NULL;
    const char *hz_start = json_bracket(json, "hazards", '[', ']', &hz_end);

    int findings = 0;
    if (hz_start) {
        const char *p = hz_start;
        while ((p = strstr(p, "\"id\"")) != NULL && p < hz_end) {
            char id[64] = "";
            const char *blk = p;
            const char *blk_end = strstr(blk + 1, "\"id\"");
            if (!blk_end || blk_end > hz_end) blk_end = hz_end;

            json_str_field(blk, blk_end, "id", id, sizeof(id));

            const char *risk_end = NULL;
            const char *risk = json_bracket(blk, "risk", '{', '}', &risk_end);
            char sevs[8] = "", exps[8] = "", ctls[8] = "", asils[16] = "";
            if (risk && risk < blk_end) {
                json_str_field(risk, risk_end, "severity", sevs, sizeof(sevs));
                json_str_field(risk, risk_end, "exposure", exps, sizeof(exps));
                json_str_field(risk, risk_end, "controllability", ctls, sizeof(ctls));
                json_str_field(risk, risk_end, "asil", asils, sizeof(asils));
            }

            if (id[0] && sevs[0] && exps[0] && ctls[0] && asils[0]) {
                int sev = json_sec_code(sevs), exp = json_sec_code(exps),
                    ctl = json_sec_code(ctls);
                const char *computed = cfusa_compute_asil(sev, exp, ctl);
                if (strcmp(computed, asils) != 0) {
                    cfusa_report_add(rpt, "HARA006", "safety", SEV_ERROR,
                        ".fusa-hara.json", 0,
                        "hazard '%s' has stored ASIL %s but S%d/E%d/C%d derives to %s "
                        "per ISO 26262-3 Table 4 (x-FuSa spec §1.2.5 — risk.asil MUST "
                        "derive from severity x exposure x controllability)",
                        id, asils, sev, exp, ctl, computed);
                    findings++;
                }
            }
            p = blk_end;
        }
    }
    free(json);
    return findings;
}

/* ── ISO26262001 — iso26262-gap-report.json should be present ─────────── */

static int rule_iso26262001(const char *dir, const cfusa_config_t *cfg,
                              cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, "iso26262-gap-report.json") &&
        !path_exists(dir, "iso26262.json")) {
        cfusa_report_add(rpt, "ISO26262001", "safety", SEV_WARNING,
            dir, 0,
            "iso26262-gap-report.json not found — "
            "run 'cfusa iso26262 --format json --output iso26262-gap-report.json'");
        return 1;
    }
    return 0;
}

/* ── ISO26262002 — requirements in .fusa-reqs.json should have ASIL ──── */

static int rule_iso26262002(const char *dir, const cfusa_config_t *cfg,
                              cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len;
    char *json = read_file_at(dir, ".fusa-reqs.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-reqs.json", &len);
    if (!json) return 0;

    int missing = 0, total = 0;
    const char *p = json;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[64] = "";
        const char *blk = p;
        const char *end = strstr(blk + 1, "\"id\"");
        if (!end) end = json + len;

        { char *fp = strstr(blk, "\"id\":");
          if (fp) { fp += 5; while (*fp==' ') fp++; if (*fp=='"') fp++;
                    sscanf(fp, "%63[^\"]", id); } }

        if (!id[0] || strncmp(id, "REQ-", 4) != 0) { p++; continue; }
        total++;

        /* Check for "asil" or "level" field in this requirement block */
        int has_asil = (strstr(blk, "\"asil\"") != NULL &&
                        (strstr(blk, "\"asil\"") < end)) ||
                       (strstr(blk, "\"level\"") != NULL &&
                        (strstr(blk, "\"level\"") < end));
        if (!has_asil) missing++;
        p = end;
    }

    if (total > 0 && missing > 0) {
        cfusa_report_add(rpt, "ISO26262002", "safety", SEV_WARNING,
            ".fusa-reqs.json", 0,
            "%d of %d requirements lack ASIL/level annotation "
            "(ISO 26262-6 §7.2 traceability requires ASIL tagging)",
            missing, total);
        free(json);
        return 1;
    }
    free(json);
    return 0;
}

/* ── ISO26262003 — tool qualification report must have zero failures ──── */

static int rule_iso26262003(const char *dir, const cfusa_config_t *cfg,
                              cfusa_report_t *rpt)
{
    (void)cfg;
    /* Check .cfusa_qualification.json for failures */
    size_t len;
    char *json = read_file_at(dir, ".cfusa_qualification.json", &len);
    if (!json) {
        /* also check qualify-report.json */
        json = read_file_at(dir, "qualify-report.json", &len);
        if (!json) return 0;
    }

    int failed = 0;
    char *fp = strstr(json, "\"tests_failed\":");
    if (fp) sscanf(fp, "\"tests_failed\": %d", &failed);
    /* Legacy: "failed" */
    if (!fp) { fp = strstr(json, "\"failed\":"); if (fp) sscanf(fp, "\"failed\": %d", &failed); }

    int qualified = 1;
    char *qp = strstr(json, "\"qualified\":");
    if (qp) {
        char qval[16] = "";
        sscanf(qp, "\"qualified\": %15s", qval);
        if (strncmp(qval, "false", 5) == 0) qualified = 0;
    }

    free(json);

    if (failed > 0 || !qualified) {
        cfusa_report_add(rpt, "ISO26262003", "safety", SEV_ERROR,
            ".cfusa_qualification.json", 0,
            "tool qualification report has %d failure(s) or qualified=false "
            "(ISO 26262-8 §11 requires tool qualification evidence)",
            failed);
        return 1;
    }
    return 0;
}

/* ── DUPREQ001 — requirement ids must be unique (x-FuSa spec §1.2.2) ──── */

/* cmd_trace.c's load_reqs() has long detected duplicate requirement ids
 * in .fusa-reqs.json/.cfusa-reqs.json and printed a "cfusa trace: ERROR:
 * duplicate requirement id" line to stderr — but that line never became a
 * `Finding` and never gated any exit code, so a requirements registry with
 * colliding ids (silently shadowing one of the two reqs for traceability
 * purposes) could still pass `cfusa check` cleanly. This rule re-parses the
 * same file and surfaces each duplicate as a real, fingerprinted §4 Finding
 * that fails `check` (ISO 26262-6 §7.2 requires unambiguous bidirectional
 * traceability, which a duplicated id breaks). Only the *first* repeat of
 * each id is reported (not every pairwise collision), so an id appearing
 * N times yields N-1 findings rather than a combinatorial blow-up. */
#define DUPREQ001_MAX_IDS 2048

static int rule_dupreq001(const char *dir, const cfusa_config_t *cfg,
                           cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len;
    const char *reqs_name = ".fusa-reqs.json";
    char *json = read_file_at(dir, reqs_name, &len);
    if (!json) {
        reqs_name = ".cfusa-reqs.json";
        json = read_file_at(dir, reqs_name, &len);
    }
    if (!json) return 0;

    static char seen[DUPREQ001_MAX_IDS][64];
    int seen_count = 0;
    int findings = 0;

    const char *p = json;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[64] = "";
        char *fp = strstr(p, "\"id\":");
        if (fp) {
            fp += 5;
            while (*fp == ' ') fp++;
            if (*fp == '"') {
                fp++;
                sscanf(fp, "%63[^\"]", id);
            }
        }
        if (id[0]) {
            int dup = 0;
            for (int i = 0; i < seen_count; i++) {
                if (!strcmp(seen[i], id)) { dup = 1; break; }
            }
            if (dup) {
                cfusa_report_add(rpt, "DUPREQ001", "safety", SEV_ERROR,
                    reqs_name, 0,
                    "duplicate requirement id '%s' in %s — requirement ids "
                    "MUST be unique within the registry (x-FuSa spec §1.2.2, "
                    "ISO 26262-6 §7.2 bidirectional traceability)",
                    id, reqs_name);
                findings++;
            } else if (seen_count < DUPREQ001_MAX_IDS) {
                strncpy(seen[seen_count], id, sizeof(seen[seen_count]) - 1);
                seen_count++;
            }
        }
        p += 4;
    }
    free(json);
    return findings;
}

/* ── COUP001 — data coupling: extern mutable global variables ─────────── */

/* issue #182: `added` accumulates the number of findings this rule's
 * callbacks actually add, so rule_coup001()/rule_coup002() below can
 * honor the run()-returns-finding-count contract every other rule in
 * this file follows, instead of hardcoding `return 0;`.
 * in_block_comment (COUP001 only) persists across cfusa_scan_lines()
 * calls within one file — reset per file in coup001_file() — mirroring
 * L003/L006's fix (cmd_lint.c) for the same comment-continuation gap. */
typedef struct { cfusa_report_t *rpt; int in_block_comment; int added; } coup_ctx_t;

static void coup001_line(const char *path, int lineno, const char *line,
                           void *vctx)
{
    coup_ctx_t *ctx = vctx;

    /* issue #181: strip block-comment and string-literal content before
     * matching, so a multi-line "/* ... * /" comment's continuation
     * lines (a legal, common C style with no leading '*') can never be
     * scanned as code -- only the first line of such a comment used to
     * be recognized, via the bare "starts with '/' or '*'" check below. */
    char code[4096];
    size_t n = 0;
    int in_str = 0;
    for (const char *q = line; *q && n < sizeof(code) - 1; q++) {
        if (ctx->in_block_comment) {
            if (q[0] == '*' && q[1] == '/') { ctx->in_block_comment = 0; q++; }
            continue;
        }
        if (in_str) {
            if (*q == '\\' && q[1]) { q++; continue; }
            if (*q == '"') in_str = 0;
            continue;
        }
        if (q[0] == '"') { in_str = 1; continue; }
        if (q[0] == '/' && q[1] == '*') { ctx->in_block_comment = 1; q++; continue; }
        if (q[0] == '/' && q[1] == '/') break; /* rest of line is comment */
        code[n++] = *q;
    }
    code[n] = '\0';

    const char *p = code;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#') return;

    /* issue #181: anchor the match to the start of the (comment/string-
     * stripped) trimmed line -- matching cmd_coupling.c's scan_line() --
     * instead of an unanchored strstr() that could match "extern " text
     * appearing mid-line in prose or a trailing comment. Mutable vars
     * only; skip fn decls (have '('). */
    if (strncmp(p, "extern ", 7) == 0 && !strstr(p, "const ") &&
        !strchr(p, '(') && strchr(p, ';') &&
        strncmp(p, "extern \"C\"", 10) != 0) {
        cfusa_report_add(ctx->rpt,
            "COUP001", "analyze", SEV_WARNING,
            path, lineno,
            "data coupling: exported mutable variable via 'extern' declaration; "
            "consider passing state explicitly (DO-178C §6.4.4.3)");
        ctx->added++;
    }
}

static int coup001_file(const char *path, void *v)
{
    /* `ctx` is shared across every file in the tree walk — reset the
     * per-file comment state here, same rationale as l003_file(). */
    coup_ctx_t *ctx = v;
    ctx->in_block_comment = 0;
    cfusa_scan_lines(path, coup001_line, v); return 0;
}

static int rule_coup001(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c", ".h"};
    coup_ctx_t ctx = {rpt, 0, 0};
    cfusa_walk_sources(dir, exts, 2, coup001_file, &ctx);
    return ctx.added;
}

/* ── COUP002 — control coupling: function pointer parameters ─────────── */

static void coup002_line(const char *path, int lineno, const char *line,
                           void *vctx)
{
    coup_ctx_t *ctx = vctx;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (*p == '#') return;

    /* Match: function parameter containing "(*" (function pointer) */
    if (strstr(line, "(*") && strchr(line, ')') &&
        strchr(line, '(') < strstr(line, "(*")) {
        /* Must look like a function definition/declaration, not a call */
        if (!strstr(line, "=") || strstr(line, "))(")) {
            cfusa_report_add(ctx->rpt,
                "COUP002", "analyze", SEV_WARNING,
                path, lineno,
                "control coupling: function pointer parameter detected; "
                "use explicit dispatch tables with documented coupling rationale "
                "(DO-178C §6.4.4.3)");
            ctx->added++;
        }
    }
}

static int coup002_file(const char *path, void *v)
{
    cfusa_scan_lines(path, coup002_line, v); return 0;
}

static int rule_coup002(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c", ".h"};
    coup_ctx_t ctx = {rpt, 0, 0};
    cfusa_walk_sources(dir, exts, 2, coup002_file, &ctx);
    return ctx.added;
}

/* ── COUP003 — coupling-report.json should be present ──────────────── */

static int rule_coup003(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, "coupling-report.json")) {
        cfusa_report_add(rpt, "COUP003", "safety", SEV_INFO,
            dir, 0,
            "coupling-report.json not found — "
            "run 'cfusa coupling --dir <src>' to generate coupling evidence "
            "(DO-178C §6.4.4.3)");
        return 1;
    }
    return 0;
}

/* Finds the '}' matching the '{' at `obj` (string-literal-aware, so a
 * literal '}' inside a quoted message doesn't miscount depth). Returns
 * NULL if unbalanced. */
static const char *json_obj_end(const char *obj)
{
    int depth = 0, in_str = 0;
    for (const char *p = obj; *p; p++) {
        if (in_str) {
            if (*p == '\\' && p[1]) { p++; continue; }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) return p; }
    }
    return NULL;
}

/* ── DISP001 — ERROR findings with no disposition record ──────────────── */

static int rule_disp001(const char *dir, const cfusa_config_t *cfg,
                          cfusa_report_t *rpt)
{
    (void)cfg;
    /* Load check-report.json to find ERROR findings */
    size_t clen;
    char *check_json = read_file_at(dir, "check-report.json", &clen);
    if (!check_json) return 0;

    int findings = 0;
    const char *p = check_json;
    /* Scan for error-level findings */
    while ((p = strstr(p, "\"severity\"")) != NULL) {
        char sev[32] = "", rule_id[64] = "";
        const char *blk = p;

        { const char *fp = p + 10;
          while (*fp == ':' || *fp == ' ' || *fp == '"') fp++;
          sscanf(fp, "%31[^\",}]", sev); }

        if (strcmp(sev, "error") == 0 || strcmp(sev, "ERROR") == 0) {
            /* Walk back to find ruleId */
            const char *scan = blk;
            while (scan > check_json && *scan != '{') scan--;
            char *rp = strstr(scan, "\"ruleId\":");
            if (!rp) rp = strstr(scan, "\"rule_id\":");
            if (rp) {
                rp += (strstr(rp, "ruleId") ? 9 : 10);
                while (*rp == ':' || *rp == ' ' || *rp == '"') rp++;
                sscanf(rp, "%63[^\",}]", rule_id);
            }

            if (rule_id[0]) {
                /* issue #148: DISP001 used to decide "dispositioned" via a
                 * raw strstr(disp_json, rule_id) over the ENTIRE
                 * .fusa-dispositions.json text — matching free-text
                 * rationale/ref fields that merely *mention* the rule id,
                 * completely bypassing the fingerprint-scoped matching
                 * cfusa_report_apply_dispositions() (the one authoritative
                 * suppression mechanism) actually requires. Rather than
                 * re-implement that matching here, defer to it entirely:
                 * cfusa_report_apply_dispositions() already ran when
                 * check-report.json was generated and stamps a
                 * "dispositionId" field onto exactly the findings it
                 * matched (src/report.c print_json) — a real ERROR finding
                 * is dispositioned if and only if that field is present in
                 * *this* finding's own JSON object. */
                int dispositioned = 0;
                const char *obj_end = json_obj_end(scan);
                if (obj_end) {
                    const char *dp = strstr(scan, "\"dispositionId\":");
                    if (dp && dp < obj_end) dispositioned = 1;
                }
                if (!dispositioned) {
                    cfusa_report_add(rpt, "DISP001", "safety", SEV_WARNING,
                        "check-report.json", 0,
                        "ERROR finding '%s' has no disposition record — "
                        "run 'cfusa disposition add --rule %s --action accept|fix "
                        "--fingerprint <sha256:...>' (ISO 26262-8 §9 requires "
                        "findings to be dispositioned)",
                        rule_id, rule_id);
                    findings++;
                }
            }
        }
        p++;
    }

    free(check_json);
    return findings;
}

/* ── COMP001 — cyclomatic complexity ─────────────────────────────────── */

typedef struct {
    cfusa_report_t *rpt;
    const cfusa_config_t *cfg;
} comp_ctx_t;

//cfusa:req REQ-COMPTHR001
/*
 * Threshold by declared standard: DO-178C DAL A=4,B=10,C=15,D=20 (matches
 * cmd_comp.c's --dal-a/b/c/d); ISO 26262 ASIL D=4,C=10,B=15,A=20 (matches
 * cmd_comp.c's --asil-d/c/b/a aliases). Default 10 when neither is
 * declared.
 *
 * c-FuSa issue #107: this automatic `check` gate previously only
 * recognized DO-178C DAL tags in .fusa.json's standards[], so a project
 * declaring only ISO 26262 (e.g. "iso26262:ASIL-D") silently got the
 * unscaled default threshold instead of the ASIL-appropriate one, unless
 * it separately ran `cfusa comp --asil-d`. When both a DAL and an ASIL
 * tag are declared, the stricter (lower/more demanding) threshold wins —
 * a project claiming both standards must satisfy whichever is more
 * demanding, same combination rule as --dal/--asil in cfusa coverage
 * (#106).
 */
static int comp_threshold(const cfusa_config_t *cfg)
{
    int dal_t = -1, asil_t = -1;
    for (int i = 0; i < cfg->standards_count; i++) {
        const char *s = cfg->standards[i];
        if (strncmp(s, "do178", 5) == 0 || strncmp(s, "DO-178", 6) == 0) {
            if (strstr(s, "dal-a") || strstr(s, "DAL-A")) dal_t = 4;
            else if (strstr(s, "dal-b") || strstr(s, "DAL-B")) dal_t = 10;
            else if (strstr(s, "dal-c") || strstr(s, "DAL-C")) dal_t = 15;
            else if (strstr(s, "dal-d") || strstr(s, "DAL-D")) dal_t = 20;
        }
        if (strncmp(s, "iso26262", 8) == 0 || strncmp(s, "ISO 26262", 9) == 0) {
            if (strstr(s, "asil-d") || strstr(s, "ASIL-D")) asil_t = 4;
            else if (strstr(s, "asil-c") || strstr(s, "ASIL-C")) asil_t = 10;
            else if (strstr(s, "asil-b") || strstr(s, "ASIL-B")) asil_t = 15;
            else if (strstr(s, "asil-a") || strstr(s, "ASIL-A")) asil_t = 20;
        }
    }
    if (dal_t < 0 && asil_t < 0) return 10;              /* default */
    if (dal_t < 0)  return asil_t;
    if (asil_t < 0) return dal_t;
    return (dal_t < asil_t) ? dal_t : asil_t;             /* stricter wins */
}

/* Count decision points in a single line of C source. */
static int count_decisions(const char *line)
{
    int n = 0;
    const char *p = line;
    /* Skip comment lines */
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return 0;

    /* if/else if/for/while/do/case keywords */
    /* Use word-boundary checks to avoid partial matches */
    while (*p) {
        if      (strncmp(p, "if(",   3)==0 || strncmp(p, "if (",  4)==0)   { n++; p+=2; }
        else if (strncmp(p, "else if", 7)==0)  { n++; p+=7; }
        else if (strncmp(p, "for(",  4)==0 || strncmp(p, "for (", 5)==0)  { n++; p+=3; }
        else if (strncmp(p, "while(",6)==0 || strncmp(p, "while (",7)==0) { n++; p+=5; }
        else if (strncmp(p, "case ", 5)==0)    { n++; p+=4; }
        else if (*p == '?' && *(p+1) != '?')   { n++; p++; } /* ternary */
        /* logical operators */
        else if (*p == '&' && *(p+1) == '&')   { n++; p+=2; }
        else if (*p == '|' && *(p+1) == '|')   { n++; p+=2; }
        else p++;
    }
    return n;
}

typedef struct {
    cfusa_report_t *rpt;
    int threshold;
    int added; /* issue #182: findings actually added, for the run() contract */
} comp_file_ctx_t;

static int comp001_file(const char *path, void *vctx)
{
    comp_file_ctx_t *ctx = vctx;
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[4096];
    int  lineno = 0, fn_start = 0, brace_depth = 0;
    int  in_fn  = 0, complexity = 0;
    char fn_name[128] = "";

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char trimmed[4096];
        strncpy(trimmed, line, sizeof(trimmed) - 1);
        trimmed[sizeof(trimmed) - 1] = '\0';
        cfusa_str_trim(trimmed);

        /* Detect function start (same heuristic as L001) */
        if (!in_fn && brace_depth == 0
            && strstr(trimmed, "(") && strstr(trimmed, ")")
            && trimmed[0] != '#' && trimmed[0] != '/'
            && trimmed[0] != '*' && trimmed[0] != ' ') {
            char *paren = strchr(trimmed, '(');
            if (paren) {
                char before[128] = "";
                size_t blen = (size_t)(paren - trimmed);
                if (blen < 128) {
                    strncpy(before, trimmed, blen);
                    char *sp = strrchr(before, ' ');
                    strncpy(fn_name, sp ? sp + 1 : before, sizeof(fn_name) - 1);
                    while (fn_name[0] == '*') memmove(fn_name, fn_name+1, strlen(fn_name));
                }
                in_fn   = 1;
                fn_start = lineno;
                complexity = 1; /* base complexity */
            }
        }

        if (in_fn) complexity += count_decisions(line);

        /* Track brace depth */
        for (const char *ch = line; *ch; ch++) {
            if (*ch == '{') brace_depth++;
            else if (*ch == '}') {
                brace_depth--;
                if (brace_depth == 0 && in_fn) {
                    /* function closed */
                    if (complexity > ctx->threshold) {
                        cfusa_report_add(ctx->rpt,
                            "COMP001", "analyze", SEV_WARNING,
                            path, fn_start,
                            "function '%s' has cyclomatic complexity V(G)=%d "
                            "(threshold %d) — refactor to reduce branching paths "
                            "(DO-178C §6.3.4)",
                            fn_name, complexity, ctx->threshold);
                        ctx->added++;
                    }
                    in_fn      = 0;
                    complexity = 0;
                    fn_start   = 0;
                    fn_name[0] = '\0';
                }
            }
        }
    }

    if (fclose(f) != 0)
        fprintf(stderr, "cfusa: warning: fclose failed for %s\n", path);
    return 0;
}

static int rule_comp001(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    static const char * const exts[] = {".c"};
    comp_file_ctx_t ctx = {rpt, comp_threshold(cfg), 0};
    cfusa_walk_sources(dir, exts, 1, comp001_file, &ctx);
    return ctx.added;
}

/* ── Registration ────────────────────────────────────────────────────── */

/* ── FUSA001 — .fusa.json present ───────────────────────────────────── */

static int rule_fusa001(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, ".fusa.json") && !path_exists(dir, ".cfusa.json"))
        cfusa_report_add(rpt, "FUSA001", "safety", SEV_INFO, dir, 0,
            ".fusa.json not found — run 'cfusa init' to create project configuration");
    return 0;
}

/* ── FUSA002 — CMakeLists.txt (or Makefile) present ────────────────── */

static int rule_fusa002(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, "CMakeLists.txt") && !path_exists(dir, "Makefile")
        && !path_exists(dir, "meson.build"))
        cfusa_report_add(rpt, "FUSA002", "safety", SEV_INFO, dir, 0,
            "No build system file found (CMakeLists.txt/Makefile/meson.build) — "
            "add a build system for reproducible compilation");
    return 0;
}

/* ── FUSA003 — LICENSE present ───────────────────────────────────────── */

static int rule_fusa003(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, "LICENSE") && !path_exists(dir, "LICENSE.txt")
        && !path_exists(dir, "LICENSE.md"))
        cfusa_report_add(rpt, "FUSA003", "safety", SEV_INFO, dir, 0,
            "LICENSE file not found — add a license to clarify usage rights");
    return 0;
}

/* ── FUSA004 — README present ────────────────────────────────────────── */

static int rule_fusa004(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    if (!path_exists(dir, "README.md") && !path_exists(dir, "README.txt")
        && !path_exists(dir, "README"))
        cfusa_report_add(rpt, "FUSA004", "safety", SEV_INFO, dir, 0,
            "README not found — add documentation describing project purpose and usage");
    return 0;
}

/* ── FUSA005 — CI workflow present ───────────────────────────────────── */

static int rule_fusa005(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    /* Check for GitHub Actions, GitLab CI, or generic CI config */
    char ci_path[512];
    snprintf(ci_path, sizeof(ci_path), "%s/.github/workflows", dir);
    int has_gh = cfusa_dir_exists(ci_path);
    int has_gitlab = path_exists(dir, ".gitlab-ci.yml");
    int has_jenkins = path_exists(dir, "Jenkinsfile");
    if (!has_gh && !has_gitlab && !has_jenkins)
        cfusa_report_add(rpt, "FUSA005", "safety", SEV_INFO, dir, 0,
            "No CI configuration found (.github/workflows, .gitlab-ci.yml, Jenkinsfile) — "
            "add continuous integration for automated safety checks");
    return 0;
}

static const cfusa_rule_t SAFETY_RULES[] = {
    /* FUSA project structure — tool-self-check, not tied to an external
     * x-FuSa-spec-registry standard id (§2.4.1), so standard_id is omitted. */
    {"FUSA001", "safety", ".fusa.json present",
     ".fusa.json project configuration required for cfusa tooling",
     NULL, NULL, rule_fusa001},
    {"FUSA002", "safety", "Build system file present",
     "CMakeLists.txt or equivalent required for reproducible builds",
     NULL, NULL, rule_fusa002},
    {"FUSA003", "safety", "LICENSE present",
     "LICENSE file required for open-source compliance",
     NULL, NULL, rule_fusa003},
    {"FUSA004", "safety", "README present",
     "README required for project documentation",
     NULL, NULL, rule_fusa004},
    {"FUSA005", "safety", "CI configuration present",
     "CI configuration required for automated safety verification",
     NULL, NULL, rule_fusa005},
    /* HARA */
    {"HARA001", "safety", "HARA file present",
     ".fusa-hara.json must exist for ISO 26262-3 Clause 6 compliance",
     "iso26262", "Part 3", rule_hara001},
    {"HARA002", "safety", "HARA risk ratings complete",
     "All hazards must have non-zero S, E, C values",
     "iso26262", "Part 3", rule_hara002},
    {"HARA003", "safety", "HARA safety goals defined",
     "Every hazard must have a safety goal",
     "iso26262", "Part 3", rule_hara003},
    {"HARA004", "safety", "HARA ASIL assigned",
     "Safety goals must have ASIL assigned (not TBD or empty)",
     "iso26262", "Part 3", rule_hara004},
    {"HARA005", "safety", "HARA max ASIL within project ASIL",
     "Hazard ASIL must not exceed project ASIL in .fusa.json",
     "iso26262", "Part 3", rule_hara005},
    {"HARA006", "safety", "HARA stored ASIL matches S x E x C table",
     "risk.asil MUST derive from severity x exposure x controllability "
     "(ISO 26262-3 Table 4, x-FuSa spec §1.2.5)",
     "iso26262", "Table 4", rule_hara006},
    /* ISO 26262 */
    {"ISO26262001", "safety", "ISO 26262 gap report present",
     "iso26262-gap-report.json should be generated and committed",
     "iso26262", NULL, rule_iso26262001},
    {"ISO26262002", "safety", "Requirements have ASIL annotations",
     "All requirements in .fusa-reqs.json should have ASIL/level fields",
     "iso26262", NULL, rule_iso26262002},
    {"ISO26262003", "safety", "Tool qualification passes",
     "Tool qualification report must have zero failures",
     "iso26262", "Part 8", rule_iso26262003},
    {"DUPREQ001", "safety", "Requirement ids unique",
     "Requirement ids in .fusa-reqs.json/.cfusa-reqs.json must be unique "
     "(x-FuSa spec §1.2.2)",
     "iso26262", "Part 6 §7.2", rule_dupreq001},
    /* Coupling */
    {"COUP001", "analyze", "Data coupling — extern mutable vars",
     "Exported mutable variables create data coupling (DO-178C §6.4.4.3)",
     "do178c", "6.4.4.3", rule_coup001},
    {"COUP002", "analyze", "Control coupling — function pointer params",
     "Function pointer parameters create control coupling (DO-178C §6.4.4.3)",
     "do178c", "6.4.4.3", rule_coup002},
    {"COUP003", "safety", "Coupling report present",
     "coupling-report.json should exist as DO-178C coupling evidence",
     "do178c", NULL, rule_coup003},
    /* Disposition */
    {"DISP001", "safety", "ERROR findings dispositioned",
     "All ERROR findings in check-report.json must have a disposition record",
     "iso26262", NULL, rule_disp001},
    /* Complexity */
    {"COMP001", "analyze", "Cyclomatic complexity within threshold",
     "V(G) = 1 + decision nodes; threshold varies by DAL (DO-178C §6.3.4)",
     "do178c", "6.3.4", rule_comp001},
};

void cfusa_safety_register_rules(void)
{
    int n = (int)(sizeof(SAFETY_RULES) / sizeof(SAFETY_RULES[0]));
    for (int i = 0; i < n; i++)
        cfusa_engine_register(&SAFETY_RULES[i]);
}

/* Expose count for test introspection. */
int cfusa_safety_rule_count(void)
{
    return (int)(sizeof(SAFETY_RULES) / sizeof(SAFETY_RULES[0]));
}
