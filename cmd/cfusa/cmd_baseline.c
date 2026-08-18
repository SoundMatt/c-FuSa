#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/disposition.h"

/*
 * cfusa baseline — issue #208.
 *
 * Dispositions (`cfusa disposition add`) are a reviewed, one-at-a-time
 * judgment call on a single finding. That doesn't scale to turning the
 * gate on for an existing codebase with hundreds or thousands of
 * pre-existing findings nobody has looked at yet. `cfusa baseline`
 * snapshots every CURRENT finding's fingerprint into .fusa-baseline.json;
 * cmd_check.c/cmd_lint.c then exclude baselined fingerprints from the
 * exit-code gate the same way an accepted disposition is (fingerprint-
 * scoped, findings stay visible in output, tagged
 * disposition_action="baseline" so a report reader can tell "predates
 * policy enrollment" apart from "reviewed and accepted") — genuinely NEW
 * findings introduced after the snapshot still fail the gate as normal.
 *
 * Re-running `cfusa baseline` OVERWRITES the file with a fresh snapshot
 * of whatever findings exist right now (a finding that's since been
 * fixed simply drops out) — this is a bulk, regenerable starting point,
 * not a permanent record; use `cfusa disposition add` for a durable,
 * reviewed exception to a specific finding.
 */

//cfusa:req REQ-BASELINE001 REQ-BASELINE002
int cmd_baseline(int argc, char **argv)
{
    const char *dir = ".";

    static const struct option long_opts[] = {
        {"dir",  required_argument, NULL, 'd'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir = optarg; break;
        case 'h':
            printf("Usage: cfusa baseline [--dir <path>]\n\n"
                   "Snapshots every current finding's fingerprint into\n"
                   ".fusa-baseline.json. cfusa check/lint then exclude\n"
                   "baselined findings from the exit-code gate -- they stay\n"
                   "visible in output, just don't fail the build. New\n"
                   "findings introduced after the snapshot still fail the\n"
                   "gate as normal.\n\n"
                   "Re-running this command OVERWRITES the file with a fresh\n"
                   "snapshot of whatever findings exist right now. Use\n"
                   "'cfusa disposition add' instead for a durable, reviewed\n"
                   "exception to one specific finding.\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_analyze_register_rules();
    cfusa_cyber_register_rules();
    cfusa_safety_register_rules();

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    {
        char *abs = realpath(dir, NULL);
        if (abs) {
            strncpy(rpt.project_root, abs, sizeof(rpt.project_root) - 1);
            free(abs);
        } else {
            strncpy(rpt.project_root, dir, sizeof(rpt.project_root) - 1);
        }
    }
    cfusa_engine_run_all(dir, &cfg, &rpt);

    /* A finding already covered by a reviewed disposition doesn't need
     * baseline coverage too -- keeps the baseline focused on genuinely
     * un-reviewed pre-existing findings, matching the "bulk, unreviewed
     * snapshot" framing in cfusa_baseline_load()'s doc comment. */
    cfusa_disposition_list_t disps;
    if (!cfusa_dispositions_load(dir, &disps))
        fprintf(stderr, "cfusa baseline: WARNING: dispositions may be incomplete\n");
    cfusa_report_apply_dispositions(&rpt, &disps);
    cfusa_dispositions_free(&disps);

    char path[512];
    cfusa_path_join(path, sizeof(path), dir, CFUSA_BASELINE_FILE);
    char tmppath[550];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", path, (int)getpid());

    /* cfusa_fopen_write(): explicit 0600, not fopen()'s umask-dependent
     * mode. Written to a temp file and rename()'d into place so a reader
     * never observes a partially-written file. */
    FILE *f = cfusa_fopen_write(tmppath);
    if (!f) {
        perror(tmppath);
        cfusa_report_free(&rpt);
        return 3;
    }

    fprintf(f, "{\n  \"baseline\": [\n");
    int written = 0;
    int skipped_dispositioned = 0;
    for (int i = 0; i < rpt.count; i++) {
        const cfusa_finding_t *finding = &rpt.findings[i];
        if (!finding->fingerprint[0]) continue;
        if (finding->disposition_id[0]) { skipped_dispositioned++; continue; }

        char esc_rule[64];
        cfusa_str_escape_json(finding->rule_id, esc_rule, sizeof(esc_rule));
        fprintf(f, "%s    {\"id\":\"BASELINE-%04d\",\"rule\":\"%s\","
                   "\"fingerprint\":\"%s\",\"action\":\"baseline\"}",
                written ? ",\n" : "", written + 1, esc_rule, finding->fingerprint);
        written++;
    }
    fprintf(f, "%s  ]\n}\n", written ? "\n" : "");

    if (fclose(f) != 0) {
        perror(tmppath);
        remove(tmppath);
        cfusa_report_free(&rpt);
        return 3;
    }
    if (rename(tmppath, path) != 0) {
        perror(path);
        remove(tmppath);
        cfusa_report_free(&rpt);
        return 3;
    }

    printf("Wrote %s: %d finding(s) baselined", path, written);
    if (skipped_dispositioned)
        printf(" (%d already covered by a disposition, not duplicated)",
               skipped_dispositioned);
    printf("\n");

    cfusa_report_free(&rpt);
    return 0;
}
