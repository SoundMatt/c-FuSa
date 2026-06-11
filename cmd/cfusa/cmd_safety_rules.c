/*
 * cmd_safety_rules.c — Project-level safety engine rules.
 *
 * Registers rules that run during `cfusa check`:
 *   HARA001-005   — HARA file and content validation (ISO 26262-3)
 *   ISO26262001-3 — ISO 26262 evidence and qualification checks
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
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

//cfusa:req REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005
//cfusa:req REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
//cfusa:req REQ-DISP001 REQ-COMP001

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

    int findings = 0;
    const char *p = json;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[64] = ""; int sev = -1, exp = -1, ctl = -1;
        const char *blk = p;
        const char *end = strstr(blk + 1, "\"id\"");
        if (!end) end = json + len;

        { char *fp = strstr(blk, "\"id\":");
          if (fp) { fp += 5; while (*fp==' ') fp++; if (*fp=='"') fp++;
                    sscanf(fp, "%63[^\"]", id); } }
        { char *fp = strstr(blk, "\"severity\":");
          if (fp && fp < end) sscanf(fp, "\"severity\": %d", &sev); }
        { char *fp = strstr(blk, "\"exposure\":");
          if (fp && fp < end) sscanf(fp, "\"exposure\": %d", &exp); }
        { char *fp = strstr(blk, "\"controllability\":");
          if (fp && fp < end) sscanf(fp, "\"controllability\": %d", &ctl); }

        if (id[0] && (sev <= 0 || exp <= 0 || ctl <= 0)) {
            cfusa_report_add(rpt, "HARA002", "safety", SEV_ERROR,
                ".fusa-hara.json", 0,
                "hazard '%s' has incomplete risk rating (S=%d E=%d C=%d); "
                "all must be > 0 (ISO 26262-3 Clause 6.4)",
                id, sev, exp, ctl);
            findings++;
        }
        p = end;
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

    int findings = 0;
    const char *p = json;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[64] = "", goal[256] = "";
        const char *blk = p;
        const char *end = strstr(blk + 1, "\"id\"");
        if (!end) end = json + len;

        { char *fp = strstr(blk, "\"id\":");
          if (fp) { fp += 5; while (*fp==' ') fp++; if (*fp=='"') fp++;
                    sscanf(fp, "%63[^\"]", id); } }
        { char *fp = strstr(blk, "\"safety_goal\":");
          if (fp && fp < end) {
              fp += 14; while (*fp==' ') fp++;
              if (*fp=='"') fp++;
              sscanf(fp, "%255[^\"]", goal); } }

        if (id[0] && (goal[0] == '\0' ||
                      strncmp(goal, "[", 1) == 0 ||
                      strstr(goal, "derive safety goal") != NULL)) {
            cfusa_report_add(rpt, "HARA003", "safety", SEV_ERROR,
                ".fusa-hara.json", 0,
                "hazard '%s' has no safety goal — required by ISO 26262-3 §6.4.9", id);
            findings++;
        }
        p = end;
    }
    free(json);
    return findings;
}

/* ── HARA004 — safety goals must have ASIL assigned ─────────────────── */

static int rule_hara004(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    size_t len; char *json = read_file_at(dir, ".fusa-hara.json", &len);
    if (!json) json = read_file_at(dir, ".cfusa-hara.json", &len);
    if (!json) return 0;

    int findings = 0;
    const char *p = json;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[64] = "", asil[32] = "";
        const char *blk = p;
        const char *end = strstr(blk + 1, "\"id\"");
        if (!end) end = json + len;

        { char *fp = strstr(blk, "\"id\":");
          if (fp) { fp += 5; while (*fp==' ') fp++; if (*fp=='"') fp++;
                    sscanf(fp, "%63[^\"]", id); } }
        { char *fp = strstr(blk, "\"asil\":");
          if (fp && fp < end) {
              fp += 7; while (*fp==' ') fp++;
              if (*fp=='"') fp++;
              sscanf(fp, "%31[^\"]", asil); } }

        if (id[0] && (asil[0] == '\0' || strcmp(asil, "TBD") == 0 ||
                      strcmp(asil, "unknown") == 0)) {
            cfusa_report_add(rpt, "HARA004", "safety", SEV_WARNING,
                ".fusa-hara.json", 0,
                "hazard '%s' has undetermined ASIL '%s' — "
                "must be QM, ASIL-A, B, C, or D (ISO 26262-3 §6.4.6)",
                id, asil[0] ? asil : "(empty)");
            findings++;
        }
        p = end;
    }
    free(json);
    return findings;
}

/* ── HARA005 — max hazard ASIL must not exceed project ASIL ─────────── */

static int asil_rank(const char *s)
{
    if (!s) return -1;
    if (strcmp(s,"QM")==0)     return 0;
    if (strcmp(s,"ASIL-A")==0) return 1;
    if (strcmp(s,"ASIL-B")==0) return 2;
    if (strcmp(s,"ASIL-C")==0) return 3;
    if (strcmp(s,"ASIL-D")==0) return 4;
    return -1;
}

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
                proj_rank = asil_rank(proj_asil);
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
        int r = asil_rank(asil);
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

/* ── COUP001 — data coupling: extern mutable global variables ─────────── */

typedef struct { cfusa_report_t *rpt; } coup_ctx_t;

static void coup001_line(const char *path, int lineno, const char *line,
                           void *vctx)
{
    coup_ctx_t *ctx = vctx;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    if (*p == '#') return;

    /* Match: "extern <type> <name>;" with no "const" and no "(*" fn-ptr */
    if (strstr(p, "extern ") && !strstr(p, "const ") &&
        !strstr(p, "(*") && strchr(p, ';') &&
        !strstr(p, "extern \"C\"")) {
        cfusa_report_add(ctx->rpt,
            "COUP001", "analyze", SEV_WARNING,
            path, lineno,
            "data coupling: exported mutable variable via 'extern' declaration; "
            "consider passing state explicitly (DO-178C §6.4.4.3)");
    }
}

static int coup001_file(const char *path, void *v)
{
    cfusa_scan_lines(path, coup001_line, v); return 0;
}

static int rule_coup001(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    (void)cfg;
    static const char * const exts[] = {".c", ".h"};
    coup_ctx_t ctx = {rpt};
    cfusa_walk_sources(dir, exts, 2, coup001_file, &ctx);
    return 0;
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
    coup_ctx_t ctx = {rpt};
    cfusa_walk_sources(dir, exts, 2, coup002_file, &ctx);
    return 0;
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

/* ── DISP001 — ERROR findings with no disposition record ──────────────── */

static int rule_disp001(const char *dir, const cfusa_config_t *cfg,
                          cfusa_report_t *rpt)
{
    (void)cfg;
    /* Load check-report.json to find ERROR findings */
    size_t clen;
    char *check_json = read_file_at(dir, "check-report.json", &clen);
    if (!check_json) return 0;

    /* Load .fusa-dispositions.json */
    size_t dlen;
    char *disp_json = read_file_at(dir, ".fusa-dispositions.json", &dlen);
    if (!disp_json) disp_json = read_file_at(dir, ".cfusa-dispositions.json", &dlen);

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
                /* Check disposition file for this rule */
                int dispositioned = 0;
                if (disp_json && strstr(disp_json, rule_id)) dispositioned = 1;
                if (!dispositioned) {
                    cfusa_report_add(rpt, "DISP001", "safety", SEV_WARNING,
                        "check-report.json", 0,
                        "ERROR finding '%s' has no disposition record — "
                        "run 'cfusa disposition add --rule %s --action accept|fix' "
                        "(ISO 26262-8 §9 requires findings to be dispositioned)",
                        rule_id, rule_id);
                    findings++;
                }
            }
        }
        p++;
    }

    free(check_json);
    if (disp_json) free(disp_json);
    return findings;
}

/* ── COMP001 — cyclomatic complexity ─────────────────────────────────── */

typedef struct {
    cfusa_report_t *rpt;
    const cfusa_config_t *cfg;
} comp_ctx_t;

/* Threshold by DAL: A=4, B=10, C=15, D=20, default=10 */
static int comp_threshold(const cfusa_config_t *cfg)
{
    for (int i = 0; i < cfg->standards_count; i++) {
        const char *s = cfg->standards[i];
        if (strncmp(s, "do178", 5) == 0 || strncmp(s, "DO-178", 6) == 0) {
            if (strstr(s, "dal-a") || strstr(s, "DAL-A")) return 4;
            if (strstr(s, "dal-b") || strstr(s, "DAL-B")) return 10;
            if (strstr(s, "dal-c") || strstr(s, "DAL-C")) return 15;
            if (strstr(s, "dal-d") || strstr(s, "DAL-D")) return 20;
        }
    }
    return 10; /* default */
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
                    }
                    in_fn      = 0;
                    complexity = 0;
                    fn_start   = 0;
                    fn_name[0] = '\0';
                }
            }
        }
    }

    fclose(f);
    return 0;
}

static int rule_comp001(const char *dir, const cfusa_config_t *cfg,
                         cfusa_report_t *rpt)
{
    static const char * const exts[] = {".c"};
    comp_file_ctx_t ctx = {rpt, comp_threshold(cfg)};
    cfusa_walk_sources(dir, exts, 1, comp001_file, &ctx);
    return 0;
}

/* ── Registration ────────────────────────────────────────────────────── */

static const cfusa_rule_t SAFETY_RULES[] = {
    /* HARA */
    {"HARA001", "safety", "HARA file present",
     ".fusa-hara.json must exist for ISO 26262-3 Clause 6 compliance",
     "ISO 26262-3", rule_hara001},
    {"HARA002", "safety", "HARA risk ratings complete",
     "All hazards must have non-zero S, E, C values",
     "ISO 26262-3", rule_hara002},
    {"HARA003", "safety", "HARA safety goals defined",
     "Every hazard must have a safety goal",
     "ISO 26262-3", rule_hara003},
    {"HARA004", "safety", "HARA ASIL assigned",
     "Safety goals must have ASIL assigned (not TBD or empty)",
     "ISO 26262-3", rule_hara004},
    {"HARA005", "safety", "HARA max ASIL within project ASIL",
     "Hazard ASIL must not exceed project ASIL in .fusa.json",
     "ISO 26262-3", rule_hara005},
    /* ISO 26262 */
    {"ISO26262001", "safety", "ISO 26262 gap report present",
     "iso26262-gap-report.json should be generated and committed",
     "ISO 26262", rule_iso26262001},
    {"ISO26262002", "safety", "Requirements have ASIL annotations",
     "All requirements in .fusa-reqs.json should have ASIL/level fields",
     "ISO 26262", rule_iso26262002},
    {"ISO26262003", "safety", "Tool qualification passes",
     "Tool qualification report must have zero failures",
     "ISO 26262-8", rule_iso26262003},
    /* Coupling */
    {"COUP001", "analyze", "Data coupling — extern mutable vars",
     "Exported mutable variables create data coupling (DO-178C §6.4.4.3)",
     "DO-178C", rule_coup001},
    {"COUP002", "analyze", "Control coupling — function pointer params",
     "Function pointer parameters create control coupling (DO-178C §6.4.4.3)",
     "DO-178C", rule_coup002},
    {"COUP003", "safety", "Coupling report present",
     "coupling-report.json should exist as DO-178C coupling evidence",
     "DO-178C", rule_coup003},
    /* Disposition */
    {"DISP001", "safety", "ERROR findings dispositioned",
     "All ERROR findings in check-report.json must have a disposition record",
     "ISO 26262", rule_disp001},
    /* Complexity */
    {"COMP001", "analyze", "Cyclomatic complexity within threshold",
     "V(G) = 1 + decision nodes; threshold varies by DAL (DO-178C §6.3.4)",
     "DO-178C", rule_comp001},
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
