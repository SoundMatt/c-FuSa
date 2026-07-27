#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/report.h"
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
 * Parse LLVM MC/DC coverage JSON export.
 * The file is an array of test-run objects; each contains a "functions" array
 * whose entries each carry an "mcdc_records" array of condition objects with
 * covered_true_count and covered_false_count integer fields.
 * A condition is MC/DC covered when both counts are positive.
 */
//cfusa:req REQ-COV015
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

    /*
     * Walk all {"covered_true_count":N,"covered_false_count":M} objects.
     * We scan for the key "covered_true_count" and then "covered_false_count"
     * within the same braced object.
     */
    const char *p = json;
    while ((p = strstr(p, "\"covered_true_count\"")) != NULL) {
        /* Find the next closing brace for this condition object */
        const char *obj_end = strchr(p, '}');
        if (!obj_end) { p++; continue; }

        /* Extract covered_true_count */
        const char *tp = strchr(p, ':');
        long true_count = 0, false_count = 0;
        if (tp && tp < obj_end) true_count = atol(tp + 1);

        /* Extract covered_false_count within the same object */
        const char *fp = strstr(p, "\"covered_false_count\"");
        if (fp && fp < obj_end) {
            fp = strchr(fp, ':');
            if (fp) false_count = atol(fp + 1);
        }

        rep->total_conditions++;
        if (true_count > 0 && false_count > 0)
            rep->covered_conditions++;

        p = obj_end + 1;
    }

    free(json);

    if (rep->total_conditions == 0) {
        snprintf(rep->note, sizeof(rep->note),
                 "no MC/DC records found in coverage export");
        rep->passed = 1;
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

static void parse_lcov(const char *path, lcov_state_t *s)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return; }

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
    fclose(f);
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
    } else if (!strcmp(dal, "DAL-D")) {
        *threshold_line   = 0.0;
        *threshold_branch = 0.0;
        *need_mcdc        = 0;
    }
}

//cfusa:req REQ-COV001 REQ-COV002 REQ-COV003 REQ-COV004
int cmd_coverage(int argc, char **argv)
{
    const char *dir          = ".";
    const char *lcov_in      = NULL;
    const char *fmt_s        = "text";
    const char *output       = NULL;
    const char *dal          = NULL;
    double threshold         = 80.0;
    double threshold_branch  = 0.0;   /* 0 = not enforced unless set by DAL */
    int    dal_explicit      = 0;
    int    mcdc              = 0;
    int    mutate            = 0;
    double mutate_score      = -1.0;  /* <0 = not provided */
    /* Feature 3 — MC/DC LLVM JSON (REQ-COV015) */
    //cfusa:req REQ-COV015
    const char *mcdc_file    = NULL;
    int    mcdc_threshold    = 100;

    static const struct option long_opts[] = {
        {"dir",            required_argument, NULL, 'd'},
        {"lcov",           required_argument, NULL, 'L'},
        {"format",         required_argument, NULL, 'f'},
        {"output",         required_argument, NULL, 'o'},
        {"dal",            required_argument, NULL, 'D'},
        {"threshold",      required_argument, NULL, 't'},
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
    while ((c = getopt_long(argc, argv, "d:L:f:o:D:t:mC:T:MS:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir          = optarg;          break;
        case 'L': lcov_in      = optarg;          break;
        case 'f': fmt_s        = optarg;          break;
        case 'o': output       = optarg;          break;
        case 'D': dal          = optarg;
                  dal_explicit = 1;               break;
        case 't': threshold    = atof(optarg);    break;
        case 'm': mcdc         = 1;               break;
        case 'C': mcdc_file    = optarg;
                  mcdc         = 1;               break; /* --mcdc-file implies --mcdc */
        case 'T': mcdc_threshold = atoi(optarg); break;
        case 'M': mutate       = 1;               break;
        case 'S': mutate_score = atof(optarg);
                  mutate       = 1;               break;
        case 'h':
            printf("Usage: cfusa coverage [--dir <path>] [--lcov <file.info>]\n"
                   "                      [--format text|json] [--output <file>]\n"
                   "                      [--dal DAL-A|DAL-B|DAL-C|DAL-D]\n"
                   "                      [--threshold <pct>] [--mcdc]\n"
                   "                      [--mcdc-file <llvm.json>] [--mcdc-threshold <pct>]\n"
                   "                      [--mutate] [--mutate-score <pct>]\n\n"
                   "Parses gcov/lcov output and reports statement, function, and\n"
                   "branch coverage. --dal sets DO-178C level requirements:\n"
                   "  DAL-A: 100%% line + branch + MC/DC (mutation testing)\n"
                   "  DAL-B: 100%% line + branch\n"
                   "  DAL-C: 100%% line (statement)\n"
                   "  DAL-D: no coverage threshold\n"
                   "--mcdc flags decision coverage <100%%.\n"
                   "--mcdc-file parses an LLVM coverage JSON export for MC/DC analysis.\n"
                   "--mcdc-threshold N sets the minimum %% of conditions covered (default 100).\n"
                   "--mutate reads mutation-report.json (or --mutate-score N) as\n"
                   "MC/DC mutation-testing evidence for DO-178C DAL A/B.\n"
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
    if (lcov_in && cfusa_file_exists(lcov_in))
        parse_lcov(lcov_in, &state);

    double line_pct   = pct(state.lines_hit,    state.lines_found);
    double func_pct   = pct(state.funcs_hit,    state.funcs_found);
    double branch_pct = pct(state.branches_hit, state.branches_found);

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

    int line_pass   = !lcov_in || line_pct   >= threshold;
    int branch_pass = !lcov_in || threshold_branch <= 0.0 || branch_pct >= threshold_branch;
    int mcdc_pass   = !mcdc    || !lcov_in   || branch_pct >= 100.0;
    if (have_mcdc_rep) mcdc_pass = mcdc_rep.passed; /* LLVM MC/DC overrides branch proxy */
    int mut_pass    = !mutate  || mutate_score < 0.0 || mutate_score >= 100.0;
    int overall_pass = line_pass && branch_pass && mcdc_pass && mut_pass;

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
        }
        fprintf(out_f, "\n}\n");
    } else {
        if (lcov_in)
            fprintf(out_f, "Coverage report  source: %s\n\n", lcov_in);
        else
            fprintf(out_f, "Coverage report  (mutation-only mode)\n\n");
        if (dal)
            fprintf(out_f, "  Design Assurance Level: %s\n\n", dal);
        if (lcov_in) {
            fprintf(out_f, "  Line      coverage: %6.2f%%  (%ld / %ld)  %s\n",
                    line_pct,   state.lines_hit,    state.lines_found,
                    line_pass ? "PASS" : "FAIL");
            fprintf(out_f, "  Function  coverage: %6.2f%%  (%ld / %ld)\n",
                    func_pct,   state.funcs_hit,    state.funcs_found);
            fprintf(out_f, "  Branch    coverage: %6.2f%%  (%ld / %ld)  %s\n",
                    branch_pct, state.branches_hit, state.branches_found,
                    branch_pass ? "PASS" : "FAIL");
        }
        if (mcdc && lcov_in && !have_mcdc_rep) {
            fprintf(out_f, "\n  MC/DC analysis: branch coverage %.2f%%", branch_pct);
            if (!mcdc_pass)
                fprintf(out_f, "  [FAIL — DO-178C requires 100%%]");
            fprintf(out_f, "\n");
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
