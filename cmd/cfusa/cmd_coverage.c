#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/report.h"
#include "cfusa/severity.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/* Parses lcov .info files for line, function, and branch coverage */

/* ── MC/DC analysis (REQ-COV015) ──────────────────────────────────────────── */

typedef struct {
    long total_conditions;
    long covered_conditions;
    double coverage_pct;
    int   passed;
    char  note[256];
} mcdc_report_t;

/*
 * issue #129: the previous version of this parser scanned for
 * {"covered_true_count":N,"covered_false_count":M} objects — a schema
 * that does not exist in real `llvm-cov export -format=text` output and
 * never did; verified directly (`grep -c covered_true_count` on a
 * genuine export is always 0). Real `mcdc_records[]` entries are
 * positional arrays — [LineStart, ColumnStart, LineEnd, ColumnEnd,
 * TrueDecisions, FalseDecisions, FileID, ExpandedFileID, Kind,
 * ConditionsArray] — duplicated at both per-file ("summary") and
 * per-data-entry aggregate ("totals") scope, which makes counting raw
 * records directly risk double-counting (confirmed empirically: a
 * 2-condition decision shows up once under files[].mcdc_records AND
 * once under functions[].mcdc_records with identical content).
 *
 * llvm-cov itself already computes the exact aggregate this tool needs
 * — data[].totals.mcdc.{count,covered} — the same official summary
 * `llvm-cov report` surfaces to a human. Reading that directly avoids
 * the double-counting class of bug entirely and is far less exposed to
 * mcdc_records[]'s positional-array shape changing between LLVM
 * versions than re-deriving the aggregate from per-condition booleans
 * would be. Verified against a real `-fcoverage-mcdc` export (2026-08,
 * Apple clang 21 / current upstream LLVM lineage): a 2-condition `a &&
 * b` decision reports totals.mcdc = {"count":2,"covered":2}, matching
 * ground truth exactly.
 *
 * `llvm-cov export` can emit more than one data[] entry when invoked
 * with multiple `-object` binaries — every "totals":{...} block found is
 * summed, not just the first, so a multi-binary export isn't silently
 * under-counted.
 */
//cfusa:req REQ-COV015 REQ-COV016
static void mcdc_field_value(const char *obj, const char *key, long *out)
{
    char pat[32];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(obj, pat);
    *out = p ? atol(p + strlen(pat)) : 0;
}

/* Finds the next "mcdc":{...} value strictly inside the next top-level
 * "totals":{...} object starting at *cursor, using string-aware
 * brace-depth tracking (a filename inside a quoted string could contain
 * '{'/'}' otherwise) — same technique as cmd_hara.c's
 * extract_bracket_at(). Advances *cursor past the totals object either
 * way so repeated calls walk every data[] entry's totals in turn.
 * Returns a malloc'd "count":N,"covered":M,... fragment (caller frees),
 * or NULL once no further "totals" object exists. */
static char *next_totals_mcdc(const char **cursor)
{
    const char *tp = strstr(*cursor, "\"totals\":{");
    if (!tp) { *cursor = NULL; return NULL; }
    const char *obj_start = tp + strlen("\"totals\":{");

    int depth = 1, in_str = 0;
    const char *p = obj_start, *totals_end = NULL;
    for (; *p; p++) {
        if (in_str) {
            if (*p == '\\') { p++; continue; }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { totals_end = p; break; } }
    }
    *cursor = totals_end ? totals_end + 1 : NULL;
    if (!totals_end) return NULL;

    const char *mp = strstr(obj_start, "\"mcdc\":{");
    if (!mp || mp >= totals_end) return NULL;
    const char *mcdc_start = mp + strlen("\"mcdc\":{");
    /* mcdc's own value object is flat (count/covered/notcovered/percent,
     * no nested braces) — its own closing '}' is the first one found. */
    const char *me = strchr(mcdc_start, '}');
    if (!me || me > totals_end) return NULL;

    size_t n = (size_t)(me - mcdc_start);
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, mcdc_start, n);
    out[n] = '\0';
    return out;
}

static void parse_mcdc_json(const char *path, int threshold, mcdc_report_t *rep)
{
    rep->total_conditions = rep->covered_conditions = 0;
    rep->coverage_pct = 100.0;
    rep->passed = 1;
    rep->note[0] = '\0';

    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) {
        snprintf(rep->note, sizeof(rep->note),
                 "cannot read MC/DC file: %s", path);
        rep->passed = 0;
        return;
    }

    const char *cursor = json;
    char *mcdc_obj;
    while (cursor && (mcdc_obj = next_totals_mcdc(&cursor)) != NULL) {
        long count = 0, covered = 0;
        mcdc_field_value(mcdc_obj, "count", &count);
        mcdc_field_value(mcdc_obj, "covered", &covered);
        free(mcdc_obj);
        rep->total_conditions   += count;
        rep->covered_conditions += covered;
    }

    free(json);

    /* A --mcdc-file that parses to zero condition objects is never treated
     * as a vacuous pass: it can't be distinguished from a wrong/empty/
     * malformed export (bad path, truncated file, an LLVM export-format
     * change the string-scan above no longer recognizes) purely from
     * content, and "found nothing, so nothing to fail" is exactly the
     * silent-incomplete-data-reads-as-complete failure mode this tool
     * spent real effort eliminating elsewhere (see MAX_REQS, issue #100).
     * A genuinely branch-free file the caller doesn't want MC/DC-gated at
     * all should simply not pass --mcdc-file, not rely on this parsing to
     * a harmless-looking pass. */
    if (rep->total_conditions == 0) {
        snprintf(rep->note, sizeof(rep->note),
                 "no MC/DC condition records found in %s — cannot verify "
                 "MC/DC coverage from this file (check the path and that "
                 "it is a genuine LLVM MC/DC JSON export)", path);
        rep->coverage_pct = 0.0; /* not "100.0% covered, but FAIL" */
        rep->passed = 0;
        return;
    }

    rep->coverage_pct = (double)rep->covered_conditions
                        * 100.0 / (double)rep->total_conditions;

    int thr = (threshold <= 0) ? 100 : threshold;
    rep->passed = (rep->coverage_pct >= (double)thr);
    if (!rep->passed) {
        snprintf(rep->note, sizeof(rep->note),
                 "MC/DC gate failed: %.1f%% covered (threshold %d%%)",
                 rep->coverage_pct, thr);
    }
}

typedef struct {
    long   lines_found;
    long   lines_hit;
    long   funcs_found;
    long   funcs_hit;
    long   branches_found;
    long   branches_hit;
    char   current_file[512];
    int    in_record;
} lcov_state_t;

/* Returns 1 on a successful open+read (even if the file turned out to
 * contain no recognized records — the caller separately checks
 * s->lines_found for that), 0 if the file could not even be opened. */
static int parse_lcov(const char *path, lcov_state_t *s)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "SF:", 3) == 0) {
            strncpy(s->current_file, line + 3, sizeof(s->current_file) - 1);
            s->in_record = 1;
        } else if (strcmp(line, "end_of_record") == 0) {
            s->in_record = 0;
        } else if (strncmp(line, "LF:", 3) == 0) {
            s->lines_found += atol(line + 3);
        } else if (strncmp(line, "LH:", 3) == 0) {
            s->lines_hit += atol(line + 3);
        } else if (strncmp(line, "FNF:", 4) == 0) {
            s->funcs_found += atol(line + 4);
        } else if (strncmp(line, "FNH:", 4) == 0) {
            s->funcs_hit += atol(line + 4);
        } else if (strncmp(line, "BRF:", 4) == 0) {
            s->branches_found += atol(line + 4);
        } else if (strncmp(line, "BRH:", 4) == 0) {
            s->branches_hit += atol(line + 4);
        }
    }
    if (fclose(f) != 0) { perror(path); return 0; }
    return 1;
}

static double pct(long hit, long found)
{
    if (found == 0) return 100.0;
    return (double)hit / (double)found * 100.0;
}

/* dal_thresholds: line_pct, branch_pct, mcdc_required */
static void apply_dal(const char *dal, double *threshold_line,
                      double *threshold_branch, int *need_mcdc)
{
    if (!dal) return;
    if (!strcmp(dal, "DAL-A")) {
        *threshold_line   = 100.0;
        *threshold_branch = 100.0;
        *need_mcdc        = 1;
    } else if (!strcmp(dal, "DAL-B")) {
        *threshold_line   = 100.0;
        *threshold_branch = 100.0;
        *need_mcdc        = 0;
    } else if (!strcmp(dal, "DAL-C")) {
        *threshold_line   = 100.0;
        *threshold_branch = 0.0;
        *need_mcdc        = 0;
    }
    /* issue #172: DAL-D means "no DO-178C coverage requirement", not
     * "your project has no coverage requirement" — unconditionally
     * zeroing *threshold_line here used to silently discard whatever
     * floor the caller already had (the 80% default, or an explicit
     * --threshold the user passed), asymmetric with how apply_asil()'s
     * QM tier (the identical "no requirement" case) deliberately leaves
     * its outputs unchanged rather than lowering them. DAL-D now does
     * the same: no branch here at all, so the caller's existing
     * threshold_line/threshold_branch/need_mcdc simply pass through
     * untouched. */
}

//cfusa:req REQ-COV020
/*
 * asil_thresholds: line_pct, branch_pct, mcdc_required — the ISO 26262-6
 * counterpart to apply_dal() above, c-FuSa issue #106.
 *
 * ISO 26262-6:2018 Table 12 rates statement/branch/MC/DC coverage
 * "+" (recommended) through "++" (highly recommended) by ASIL rather than
 * DO-178C's binary "required at Level A" framing — this mapping treats
 * Table 12's "++" MC/DC rating at ASIL-D as a hard requirement, mirroring
 * how this command already treats DO-178C's own recommendation levels as
 * hard gates via --dal: ASIL-D requires MC/DC (same tier as DAL-A);
 * ASIL-C requires full branch coverage but not yet MC/DC (same tier as
 * DAL-B); ASIL-A/B require full statement coverage only (same tier as
 * DAL-C); QM has no coverage requirement (same tier as DAL-D).
 *
 * Uses the shared cfusa_asil_rank() (include/cfusa/severity.h, #104)
 * rather than its own string table, so this and every other ASIL-scaled
 * gate rank ASIL strings identically.
 */
static void apply_asil(const char *asil, double *threshold_line,
                        double *threshold_branch, int *need_mcdc)
{
    int rank = cfusa_asil_rank(asil); /* 0=QM .. 4=ASIL-D, -1=invalid */
    if (rank == 4) {                       /* ASIL-D */
        *threshold_line   = 100.0;
        *threshold_branch = 100.0;
        *need_mcdc        = 1;
    } else if (rank == 3) {                /* ASIL-C */
        *threshold_line   = 100.0;
        *threshold_branch = 100.0;
        *need_mcdc        = 0;
    } else if (rank == 1 || rank == 2) {   /* ASIL-A / ASIL-B */
        *threshold_line   = 100.0;
        *threshold_branch = 0.0;
        *need_mcdc        = 0;
    }
    /* QM (rank 0) or invalid (-1): leave outputs unchanged — caller only
     * raises its existing thresholds when this function's outputs exceed
     * them (see the --asil max-combine below), so QM contributes nothing
     * rather than lowering an already-stricter --dal/--threshold. */
}

//cfusa:req REQ-COV001 REQ-COV002 REQ-COV003 REQ-COV004
int cmd_coverage(int argc, char **argv)
{
    const char *dir          = ".";
    const char *lcov_in      = NULL;
    const char *fmt_s        = "text";
    const char *output       = NULL;
    const char *dal          = NULL;
    const char *asil         = NULL;  /* REQ-COV020 (issue #106) */
    double threshold         = 80.0;
    double threshold_branch  = 0.0;   /* 0 = not enforced unless set by DAL/ASIL/--branch-threshold */
    int    dal_explicit      = 0;
    int    asil_explicit     = 0;
    /* issue #137: an independent branch-coverage regression floor,
     * separate from --threshold's line-only gate — for a project that
     * wants to enforce "don't regress below the currently-measured
     * branch number" without committing to --dal/--asil's fixed 100%
     * bundling. Captured separately from threshold_branch itself (which
     * --dal/--asil also write to) so it can act as a floor below the
     * option-parsing loop regardless of flag order — see below. */
    int    branch_threshold_explicit = 0;
    double branch_threshold_pct      = 0.0;
    int    mcdc              = 0;
    int    mutate            = 0;
    double mutate_score      = -1.0;  /* <0 = not provided */
    /* Feature 3 — MC/DC LLVM JSON (REQ-COV015) */
    //cfusa:req REQ-COV015
    const char *mcdc_file    = NULL;
    int    mcdc_threshold    = 100;
    int    mcdc_threshold_explicit = 0; /* issue #152 */

    static const struct option long_opts[] = {
        {"dir",            required_argument, NULL, 'd'},
        {"lcov",           required_argument, NULL, 'L'},
        {"format",         required_argument, NULL, 'f'},
        {"output",         required_argument, NULL, 'o'},
        {"dal",            required_argument, NULL, 'D'},
        {"asil",           required_argument, NULL, 'A'}, /* REQ-COV020 */
        {"threshold",      required_argument, NULL, 't'},
        {"branch-threshold", required_argument, NULL, 'B'}, /* REQ-COV022, issue #137 */
        {"mcdc",           no_argument,       NULL, 'm'},
        {"mcdc-file",      required_argument, NULL, 'C'}, /* REQ-COV015 */
        {"mcdc-threshold", required_argument, NULL, 'T'}, /* REQ-COV015 */
        {"mutate",         no_argument,       NULL, 'M'},
        {"mutate-score",   required_argument, NULL, 'S'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:L:f:o:D:A:t:B:mC:T:MS:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir          = optarg;          break;
        case 'L': lcov_in      = optarg;          break;
        case 'f': fmt_s        = optarg;          break;
        case 'o': output       = optarg;          break;
        case 'D': dal          = optarg;
                  dal_explicit = 1;               break;
        case 'A': asil          = optarg;
                  asil_explicit = 1;              break; /* REQ-COV020 */
        case 't': threshold    = atof(optarg);    break;
        case 'B': branch_threshold_pct      = atof(optarg);
                  branch_threshold_explicit = 1;  break; /* REQ-COV022 */
        case 'm': mcdc         = 1;               break;
        case 'C': mcdc_file    = optarg;
                  mcdc         = 1;               break; /* --mcdc-file implies --mcdc */
        case 'T': mcdc_threshold = atoi(optarg);
                  mcdc_threshold_explicit = 1;   break;
        case 'M': mutate       = 1;               break;
        case 'S': mutate_score = atof(optarg);
                  mutate       = 1;               break;
        case 'h':
            printf("Usage: cfusa coverage [--dir <path>] [--lcov <file.info>]\n"
                   "                      [--format text|json] [--output <file>]\n"
                   "                      [--dal DAL-A|DAL-B|DAL-C|DAL-D]\n"
                   "                      [--asil QM|ASIL-A|ASIL-B|ASIL-C|ASIL-D]\n"
                   "                      [--threshold <pct>] [--branch-threshold <pct>] [--mcdc]\n"
                   "                      [--mcdc-file <llvm.json>] [--mcdc-threshold <pct>]\n"
                   "                      [--mutate] [--mutate-score <pct>]\n\n"
                   "Parses gcov/lcov output and reports statement, function, and\n"
                   "branch coverage. --dal sets DO-178C level requirements:\n"
                   "  DAL-A: 100%% line + branch + MC/DC (mutation testing)\n"
                   "  DAL-B: 100%% line + branch\n"
                   "  DAL-C: 100%% line (statement)\n"
                   "  DAL-D: no coverage threshold\n"
                   "--asil sets ISO 26262-6 Table 12 structural-coverage requirements:\n"
                   "  ASIL-D: 100%% line + branch + MC/DC (same tier as DAL-A)\n"
                   "  ASIL-C: 100%% line + branch (same tier as DAL-B)\n"
                   "  ASIL-A/B: 100%% line (same tier as DAL-C)\n"
                   "  QM: no coverage threshold (same tier as DAL-D)\n"
                   "--dal and --asil may both be given; the stricter requirement of the two\n"
                   "applies to each of line/branch/MC/DC independently.\n"
                   "--branch-threshold N gates branch coverage independently of --threshold\n"
                   "(which is line-only): fail if measured branch coverage is below N%%.\n"
                   "Acts as a floor even alongside --dal/--asil (never weakened by them,\n"
                   "only ever raised if their own branch requirement is stricter) — for a\n"
                   "regression-floor gate below the fixed 100%% --dal/--asil bundle, e.g.\n"
                   "while working incrementally toward full branch coverage.\n"
                   "--mcdc flags decision coverage <100%%.\n"
                   "--mcdc-file parses an LLVM coverage JSON export for a verified MC/DC gate.\n"
                   "--mcdc-threshold N sets the minimum %% of conditions covered (default 100).\n"
                   "NOTE: when MC/DC is required (--mcdc, or implied by --dal DAL-A /\n"
                   "--asil ASIL-D) but --mcdc-file is not given, the gate falls back to\n"
                   "100%% branch coverage as a proxy — this is NOT verified MC/DC evidence\n"
                   "(100%% branch coverage does not establish that every condition within\n"
                   "each decision independently affects its outcome). Provide --mcdc-file\n"
                   "for a real MC/DC gate.\n"
                   "--mutate reads mutation-report.json (or --mutate-score N) as\n"
                   "MC/DC mutation-testing evidence for DO-178C DAL A/B / ISO 26262 ASIL C/D.\n"
                   "Generate lcov data with: lcov --capture --directory . -o coverage.info\n");
            return 0;
        default: return 2;
        }
    }

    /* Validate and apply DAL if specified */
    if (dal_explicit) {
        if (strcmp(dal, "DAL-A") && strcmp(dal, "DAL-B") &&
            strcmp(dal, "DAL-C") && strcmp(dal, "DAL-D")) {
            fprintf(stderr, "cfusa coverage: invalid --dal %s (use DAL-A|DAL-B|DAL-C|DAL-D)\n", dal);
            return 2;
        }
        apply_dal(dal, &threshold, &threshold_branch, &mcdc);
    }

    /* Validate and apply ASIL if specified (REQ-COV020, issue #106).
     * Combined with --dal (if also given) by taking the stricter of the
     * two requirements for each of line/branch/MC/DC independently,
     * rather than one overriding the other — a project declaring both
     * standards must satisfy whichever is more demanding. */
    if (asil_explicit) {
        if (cfusa_asil_rank(asil) < 0) {
            fprintf(stderr,
                "cfusa coverage: invalid --asil %s "
                "(use QM|ASIL-A|ASIL-B|ASIL-C|ASIL-D)\n", asil);
            return 2;
        }
        double asil_line = 0.0, asil_branch = 0.0;
        int asil_mcdc = 0;
        apply_asil(asil, &asil_line, &asil_branch, &asil_mcdc);
        if (asil_line   > threshold)        threshold        = asil_line;
        if (asil_branch > threshold_branch) threshold_branch = asil_branch;
        if (asil_mcdc)                      mcdc              = 1;
    }

    /* issue #152: --dal DAL-A / --asil ASIL-D are documented (--help,
     * above) as requiring 100% MC/DC, but nothing floored
     * --mcdc-threshold to match — a weaker explicit --mcdc-threshold
     * could silently coexist with a DAL-A/ASIL-D claim, producing a
     * "passing" MC/DC gate (and a mcdcReport in the emitted JSON) well
     * below the compliance level the DAL/ASIL label next to it claims.
     * Only DAL-A/ASIL-D specifically require the floor — a plain --mcdc
     * or --mcdc-file without --dal/--asil (or at a lower DAL/ASIL tier)
     * legitimately wants to track MC/DC progress at any threshold. */
    {
        int mcdc_requires_100 = (dal_explicit && !strcmp(dal, "DAL-A")) ||
                                 (asil_explicit && cfusa_asil_rank(asil) == 4);
        if (mcdc_requires_100 && mcdc_threshold < 100) {
            if (mcdc_threshold_explicit)
                fprintf(stderr,
                    "cfusa coverage: WARNING: --mcdc-threshold %d is below "
                    "100%%, but %s%s%s requires 100%% MC/DC — raising the "
                    "gate to 100%%.\n",
                    mcdc_threshold,
                    dal_explicit ? dal : "",
                    (dal_explicit && asil_explicit) ? " / " : "",
                    asil_explicit ? asil : "");
            mcdc_threshold = 100;
        }
    }

    //cfusa:req REQ-COV022
    /* issue #137: an explicit --branch-threshold is applied last, as a
     * floor — --dal/--asil (above) may have already set threshold_branch
     * to their own fixed 100%, and an explicit --branch-threshold should
     * never silently weaken that; it only ever raises threshold_branch
     * when the user's own value is stricter than whatever --dal/--asil
     * already computed (mirroring how --asil itself only raises, never
     * lowers, --dal's threshold_branch just above). */
    if (branch_threshold_explicit && branch_threshold_pct > threshold_branch)
        threshold_branch = branch_threshold_pct;

    /* Locate lcov file if not specified.
     * Skip auto-detection in MC/DC-file-only mode (REQ-COV015): when
     * --mcdc-file is the sole input, lcov is not required. */
    char auto_path[512];
    if (!lcov_in && !mcdc_file) {
        cfusa_path_join(auto_path, sizeof(auto_path), dir, "coverage.info");
        if (!cfusa_file_exists(auto_path)) {
            cfusa_path_join(auto_path, sizeof(auto_path), dir, "lcov.info");
        }
        if (cfusa_file_exists(auto_path))
            lcov_in = auto_path;
    }

    /* --mutate with no score: try reading mutation-report.json */
    if (mutate && mutate_score < 0.0) {
        char mpath[512];
        cfusa_path_join(mpath, sizeof(mpath), dir, "mutation-report.json");
        size_t mlen;
        char *mjson = cfusa_read_file(mpath, &mlen);
        if (mjson) {
            const char *p = strstr(mjson, "\"score\"");
            if (!p) p = strstr(mjson, "\"mutation_score\"");
            if (!p) p = strstr(mjson, "\"mutationScore\"");
            if (p) {
                p = strchr(p, ':');
                if (p) mutate_score = atof(p + 1);
            }
            free(mjson);
        }
        if (mutate_score < 0.0) {
            fprintf(stderr,
                "cfusa coverage --mutate: no mutation-report.json found in %s.\n"
                "  Run a mutation testing tool and provide --mutate-score <pct>\n"
                "  or write mutation-report.json with a \"score\" field.\n", dir);
            return 1;
        }
    }

    if (!lcov_in || !cfusa_file_exists(lcov_in)) {
        if (mutate && mutate_score >= 0.0) {
            /* mutation-only mode: no lcov required */
        } else if (mcdc_file) {
            /* REQ-COV015: MC/DC-file-only mode: no lcov required */
        } else {
            fprintf(stderr, "cfusa coverage: no lcov .info file found.\n"
                    "  Generate with: lcov --capture --directory %s -o coverage.info\n"
                    "  Or specify:    cfusa coverage --lcov <file.info>\n", dir);
            return 1;
        }
    }

    lcov_state_t state = {0};
    int lcov_opened = 1;
    if (lcov_in && cfusa_file_exists(lcov_in))
        lcov_opened = parse_lcov(lcov_in, &state);

    double line_pct   = pct(state.lines_hit,    state.lines_found);
    double func_pct   = pct(state.funcs_hit,    state.funcs_found);
    double branch_pct = pct(state.branches_hit, state.branches_found);

    /* issue #142: an empty, corrupted, or unreadable lcov .info file must
     * never silently read as 100% coverage via pct(0,0)'s vacuous-pass
     * default. A real project always has at least one coverable line, so
     * lines_found == 0 after actually attempting to parse a supplied lcov
     * file is a reliable signal something went wrong (0-byte file, a
     * lcov grammar change this string-scan no longer recognizes, or a
     * permission/read failure) — never a legitimate "0 lines found"
     * result. Mirrors parse_mcdc_json()'s existing zero-conditions
     * handling below. */
    int lcov_data_missing = lcov_in && (!lcov_opened || state.lines_found == 0);
    char lcov_note[256] = "";
    if (lcov_data_missing) {
        snprintf(lcov_note, sizeof(lcov_note),
            lcov_opened
                ? "%s parsed but contained no LF:/LH: records — treating "
                  "as a failed/empty measurement, not 100%% coverage"
                : "%s could not be opened — treating as a failed "
                  "measurement, not 100%% coverage",
            lcov_in);
    }

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    FILE *out_f = stdout;
    if (output) { out_f = fopen(output, "w"); if (!out_f) { perror(output); return 3; } }

    char ts[32]; cfusa_timestamp_now(ts);

    /* Parse LLVM MC/DC JSON if --mcdc-file given (REQ-COV015) */
    mcdc_report_t mcdc_rep = {0, 0, 100.0, 1, ""};
    int have_mcdc_rep = 0;
    if (mcdc_file) {
        parse_mcdc_json(mcdc_file, mcdc_threshold, &mcdc_rep);
        have_mcdc_rep = 1;
    }

    int line_pass   = !lcov_in || (!lcov_data_missing && line_pct   >= threshold);
    int branch_pass = !lcov_in || (!lcov_data_missing &&
                       (threshold_branch <= 0.0 || branch_pct >= threshold_branch));
    int mcdc_pass   = !mcdc    || !lcov_in   || (!lcov_data_missing && branch_pct >= 100.0);
    if (have_mcdc_rep) mcdc_pass = mcdc_rep.passed; /* LLVM MC/DC overrides branch proxy */
    int mut_pass    = !mutate  || mutate_score < 0.0 || mutate_score >= 100.0;
    int overall_pass = line_pass && branch_pass && mcdc_pass && mut_pass;

    /* MC/DC is required at this level (--mcdc, or implied by --dal/--asil)
     * but no --mcdc-file was given: the gate above falls back to treating
     * 100% branch coverage as a proxy for MC/DC. That is NOT the same
     * thing — 100% branch/decision coverage does not establish that every
     * condition within each decision independently affects its outcome
     * (e.g. `if (a && b && c)` reaches 100% branch coverage with 2 test
     * vectors; MC/DC needs enough vectors to isolate each condition).
     * Say so loudly rather than let a proxy pass read as verified MC/DC
     * evidence. */
    if (mcdc && lcov_in && !have_mcdc_rep) {
        fprintf(stderr,
            "cfusa coverage: WARNING: MC/DC is required at this DAL/ASIL "
            "level, but no --mcdc-file was given — falling back to 100%% "
            "branch coverage as a proxy. Branch/decision coverage does NOT "
            "establish MC/DC coverage; this is not verified MC/DC evidence. "
            "Provide --mcdc-file <llvm-mcdc.json> (e.g. from "
            "clang -fcoverage-mcdc) for a real MC/DC gate.\n");
    }
    if (lcov_data_missing)
        fprintf(stderr, "cfusa coverage: WARNING: %s\n", lcov_note);

    if (fmt == FMT_JSON) {
        fprintf(out_f,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"coverage\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"lcovFile\": \"%s\",\n",
            ts,
            lcov_in ? lcov_in : "");
        if (dal)
            fprintf(out_f, "  \"dal\": \"%s\",\n", dal);
        if (asil)
            fprintf(out_f, "  \"asil\": \"%s\",\n", asil);
        fprintf(out_f,
            "  \"lineCoverage\":     {\"hit\": %ld, \"found\": %ld, \"pct\": %.2f},\n"
            "  \"functionCoverage\": {\"hit\": %ld, \"found\": %ld, \"pct\": %.2f},\n"
            "  \"branchCoverage\":   {\"hit\": %ld, \"found\": %ld, \"pct\": %.2f},\n"
            "  \"threshold\": %.1f,\n"
            "  \"passed\": %s",
            state.lines_hit,    state.lines_found,    line_pct,
            state.funcs_hit,    state.funcs_found,    func_pct,
            state.branches_hit, state.branches_found, branch_pct,
            threshold,
            overall_pass ? "true" : "false");
        if (lcov_data_missing)
            fprintf(out_f, ",\n  \"lcovNote\": \"%s\"", lcov_note);
        /* issue #137: surfaced only when actually enforced (--dal/--asil/
         * --branch-threshold), matching "threshold" above being always
         * shown but "mcdcReport" only appearing when MC/DC is relevant —
         * an unenforced 0.0 would misread as "0% required". */
        if (threshold_branch > 0.0)
            fprintf(out_f, ",\n  \"branchThreshold\": %.1f", threshold_branch);
        if (mutate && mutate_score >= 0.0) {
            fprintf(out_f,
                ",\n"
                "  \"mutationScore\": %.2f,\n"
                "  \"mutationMcdcPass\": %s",
                mutate_score,
                mutate_score >= 100.0 ? "true" : "false");
        }
        /* REQ-COV015: structured MC/DC report */
        if (have_mcdc_rep) {
            fprintf(out_f,
                ",\n"
                "  \"mcdcReport\": {\n"
                "    \"sourceFile\": \"%s\",\n"
                "    \"threshold\": %d,\n"
                "    \"totalConditions\": %ld,\n"
                "    \"coveredConditions\": %ld,\n"
                "    \"coveragePct\": %.2f,\n"
                "    \"passed\": %s",
                mcdc_file ? mcdc_file : "",
                mcdc_threshold,
                mcdc_rep.total_conditions,
                mcdc_rep.covered_conditions,
                mcdc_rep.coverage_pct,
                mcdc_rep.passed ? "true" : "false");
            if (mcdc_rep.note[0])
                fprintf(out_f, ",\n    \"note\": \"%s\"", mcdc_rep.note);
            fprintf(out_f, "\n  }");
        } else if (mcdc && lcov_in) {
            /* REQ-COV021: machine-readable flag that the MC/DC gate above
             * was satisfied by the branch-coverage proxy, not a verified
             * LLVM MC/DC export — a consumer parsing this JSON for
             * certification evidence must not read mcdcPass/passed here as
             * genuine MC/DC coverage. */
            fprintf(out_f,
                ",\n"
                "  \"mcdcProxy\": {\n"
                "    \"verified\": false,\n"
                "    \"branchCoveragePct\": %.2f,\n"
                "    \"note\": \"MC/DC required at this level but no "
                "--mcdc-file given; branch coverage is NOT equivalent to "
                "verified MC/DC coverage\"\n"
                "  }",
                branch_pct);
        }
        fprintf(out_f, "\n}\n");
    } else {
        if (lcov_in)
            fprintf(out_f, "Coverage report  source: %s\n\n", lcov_in);
        else
            fprintf(out_f, "Coverage report  (mutation-only mode)\n\n");
        if (dal)
            fprintf(out_f, "  Design Assurance Level: %s\n\n", dal);
        if (asil)
            fprintf(out_f, "  ASIL:                    %s\n\n", asil);
        if (lcov_in) {
            fprintf(out_f, "  Line      coverage: %6.2f%%  (%ld / %ld)  %s\n",
                    line_pct,   state.lines_hit,    state.lines_found,
                    line_pass ? "PASS" : "FAIL");
            fprintf(out_f, "  Function  coverage: %6.2f%%  (%ld / %ld)\n",
                    func_pct,   state.funcs_hit,    state.funcs_found);
            fprintf(out_f, "  Branch    coverage: %6.2f%%  (%ld / %ld)  %s\n",
                    branch_pct, state.branches_hit, state.branches_found,
                    branch_pass ? "PASS" : "FAIL");
            if (lcov_data_missing)
                fprintf(out_f, "  NOTE: %s\n", lcov_note);
        }
        if (mcdc && lcov_in && !have_mcdc_rep) {
            fprintf(out_f,
                "\n  MC/DC gate (branch-coverage proxy — NOT verified "
                "MC/DC): %.2f%%", branch_pct);
            if (!mcdc_pass)
                fprintf(out_f, "  [FAIL — DO-178C requires 100%%]");
            fprintf(out_f, "\n  NOTE: no --mcdc-file was given; this result "
                "is NOT verified MC/DC evidence — provide --mcdc-file "
                "<llvm-mcdc.json> for a real MC/DC gate.\n");
        }
        /* REQ-COV015: LLVM MC/DC structured report */
        if (have_mcdc_rep) {
            fprintf(out_f, "\n  MC/DC coverage (LLVM): %.2f%%"
                    "  (%ld/%ld conditions)  [%s]  (threshold: %d%%)\n",
                    mcdc_rep.coverage_pct,
                    mcdc_rep.covered_conditions, mcdc_rep.total_conditions,
                    mcdc_rep.passed ? "PASS" : "FAIL",
                    mcdc_threshold);
            if (mcdc_rep.note[0])
                fprintf(out_f, "  Note: %s\n", mcdc_rep.note);
        }
        if (mutate && mutate_score >= 0.0) {
            fprintf(out_f, "\n  Mutation score: %.2f%%", mutate_score);
            if (!mut_pass)
                fprintf(out_f, "  [FAIL — DO-178C MC/DC mutation evidence requires 100%%]");
            else
                fprintf(out_f, "  [PASS]");
            fprintf(out_f, "\n");
        }
        if (lcov_in)
            fprintf(out_f, "\n  Overall: %s\n", overall_pass ? "PASS" : "FAIL");
    }

    if (output && out_f != stdout) fclose(out_f);

    return overall_pass ? 0 : 1;
}
