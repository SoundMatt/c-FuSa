/*
 * Regression tests for issue #122: wiring .fusa-dispositions.json into
 * cfusa check/lint enforcement. Previously `cfusa disposition add` was a
 * standalone audit log — nothing ever read it back, so a recorded
 * disposition had no effect on a later run's findings or exit code.
 *
 * Covers: cfusa_dispositions_load()/cfusa_report_apply_dispositions()
 * (unit level) and cmd_check/cmd_lint/cmd_disposition end-to-end.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/disposition.h"
#include "../include/cfusa/utils.h"

extern int cmd_check(int argc, char **argv);
extern int cmd_lint(int argc, char **argv);
extern int cmd_analyze(int argc, char **argv);
extern int cmd_disposition(int argc, char **argv);
extern int cmd_baseline(int argc, char **argv);

#define DE_DIR "/tmp/cfusa_dispenf_testdir"

void setUp(void)    { (void)mkdir(DE_DIR, 0700); }
void tearDown(void) {}

static void write_disp_json(const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-dispositions.json", DE_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) { fputs(content, f); if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed"); }
}

static void rm_disp_json(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-dispositions.json", DE_DIR);
    remove(path);
}

/* ---- cfusa_dispositions_load() ---- */

//cfusa:req REQ-DISP-ENFORCE001
//cfusa:test REQ-DISP-ENFORCE001
void test_dispositions_load_missing_file_is_not_an_error(void)
{
    rm_disp_json();
    cfusa_disposition_list_t list;
    int ok = cfusa_dispositions_load(DE_DIR, &list);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(0, list.count);
    cfusa_dispositions_free(&list);
}

//cfusa:req REQ-DISP-ENFORCE001
//cfusa:test REQ-DISP-ENFORCE001
void test_dispositions_load_parses_fingerprint_field(void)
{
    write_disp_json(
        "{\"dispositions\":[\n"
        "  {\"id\":\"DISP-0001\",\"rule\":\"CFUSA-L003\","
        "\"fingerprint\":\"sha256:abcd1234\",\"action\":\"accept\","
        "\"rationale\":\"reviewed\",\"reviewer\":\"Jane\"}\n"
        "]}\n");

    cfusa_disposition_list_t list;
    int ok = cfusa_dispositions_load(DE_DIR, &list);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(1, list.count);
    TEST_ASSERT_EQUAL_STRING("DISP-0001", list.items[0].id);
    TEST_ASSERT_EQUAL_STRING("CFUSA-L003", list.items[0].rule);
    TEST_ASSERT_EQUAL_STRING("sha256:abcd1234", list.items[0].fingerprint);
    TEST_ASSERT_EQUAL_STRING("accept", list.items[0].action);
    cfusa_dispositions_free(&list);
    rm_disp_json();
}

//cfusa:req REQ-DISP-ENFORCE001
//cfusa:test REQ-DISP-ENFORCE001
void test_dispositions_load_tolerates_whitespace_after_colon(void)
{
    /* issue #143: a pretty-printed .fusa-dispositions.json (space after
     * every colon, as json.dump(indent=2)/jq/most editors' format-on-save
     * produce) used to silently fail to extract every field via the old
     * rigid `sscanf(p, "\"key\":\"%N[^\"]", ...)` literal-adjacency match. */
    write_disp_json(
        "{\n"
        "  \"dispositions\": [\n"
        "    {\n"
        "      \"id\": \"DISP-0002\",\n"
        "      \"rule\": \"CFUSA-A001\",\n"
        "      \"fingerprint\": \"sha256:deadbeef\",\n"
        "      \"action\": \"mitigate\",\n"
        "      \"rationale\": \"reviewed\"\n"
        "    }\n"
        "  ]\n"
        "}\n");

    cfusa_disposition_list_t list;
    int ok = cfusa_dispositions_load(DE_DIR, &list);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(1, list.count);
    TEST_ASSERT_EQUAL_STRING("DISP-0002", list.items[0].id);
    TEST_ASSERT_EQUAL_STRING("CFUSA-A001", list.items[0].rule);
    TEST_ASSERT_EQUAL_STRING("sha256:deadbeef", list.items[0].fingerprint);
    TEST_ASSERT_EQUAL_STRING("mitigate", list.items[0].action);
    cfusa_dispositions_free(&list);
    rm_disp_json();
}

//cfusa:req REQ-DISP-ENFORCE001
//cfusa:test REQ-DISP-ENFORCE001
void test_dispositions_load_normalizes_accepted_to_accept(void)
{
    /* issue #175: a hand-edited/migrated entry naturally spelled past-tense
     * ("accepted") must still normalize to the "accept" value
     * cfusa_report_apply_dispositions() actually matches on. */
    write_disp_json(
        "{\"dispositions\":[\n"
        "  {\"id\":\"DISP-0003\",\"rule\":\"CFUSA-L003\","
        "\"fingerprint\":\"sha256:aaaa\",\"action\":\"Accepted\"}\n"
        "]}\n");

    cfusa_disposition_list_t list;
    int ok = cfusa_dispositions_load(DE_DIR, &list);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(1, list.count);
    TEST_ASSERT_EQUAL_STRING("accept", list.items[0].action);
    cfusa_dispositions_free(&list);
    rm_disp_json();
}

/* ---- cfusa_report_apply_dispositions() ---- */

static void one_finding(cfusa_report_t *rpt, const char *rule, cfusa_severity_t sev)
{
    cfusa_report_init(rpt);
    cfusa_report_add(rpt, rule, "lint", sev, "f.c", 1, "msg");
}

/* Gets the fingerprint `cmd` (cmd_check, cmd_lint, or cmd_analyze) would
 * itself compute for `rule` in DE_DIR, by actually running `cmd --format
 * json` and reading the value back out of its own output — rather than
 * re-invoking the engine directly and computing one independently.
 *
 * This indirection matters: a caller computing a fingerprint
 * independently of the command it's meant to match can silently diverge
 * from what that command actually produces. It used to matter even more
 * — until issue #153 was fixed, cmd_check set rpt.project_root via
 * realpath(dir) before scanning (which cfusa_report_add() then uses to
 * relativize each finding's file path into the fingerprint's canonical
 * input) while cmd_lint/cmd_analyze/cmd_cyber did not, so the identical
 * real finding got a different fingerprint depending on which command
 * produced it — see test_check_and_lint_fingerprints_match_for_same_rule
 * / test_check_and_analyze_fingerprints_match_for_same_rule below, which
 * exist specifically to guard against that regressing. Always fetching
 * the fingerprint from the exact command under test (rather than a
 * fixed reference command) still avoids the whole class of bug, on every
 * platform, regardless of whether all commands agree. */
static void get_fingerprint_for_rule(int (*cmd)(int, char **), const char *rule,
                                      char *out, size_t out_sz)
{
    out[0] = '\0';

    char jpath[256];
    snprintf(jpath, sizeof(jpath), "%s/fp_lookup.json", DE_DIR);
    char *argv[] = {"cfusa", "--dir", DE_DIR, "--format", "json",
                     "--output", jpath, NULL};
    cmd(7, argv);

    size_t len = 0;
    char *buf = cfusa_read_file(jpath, &len);
    remove(jpath);
    if (!buf) return;

    char pat[64];
    snprintf(pat, sizeof(pat), "\"ruleId\": \"%s\"", rule);
    char *p = strstr(buf, pat);
    if (p) {
        char *fp = strstr(p, "\"fingerprint\":");
        if (fp) sscanf(fp, "\"fingerprint\": \"%79[^\"]", out);
        /* out_sz is always >= 80 at every call site; guard anyway */
        if (out_sz < 80) out[out_sz - 1] = '\0';
    }
    free(buf);
}

//cfusa:req REQ-DISP-ENFORCE002
//cfusa:test REQ-DISP-ENFORCE002
void test_apply_dispositions_accept_suppresses_matching_fingerprint(void)
{
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-L003", SEV_WARNING);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));
    list.items = malloc(sizeof(cfusa_disposition_t));
    list.count = 1; list.cap = 1;
    memset(&list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(list.items[0].id, "DISP-0001");
    strcpy(list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(list.items[0].action, "accept");

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    TEST_ASSERT_EQUAL_INT(1, rpt.dispositioned_count);
    TEST_ASSERT_EQUAL_INT(1, rpt.count); /* finding still present, never dropped */
    TEST_ASSERT_EQUAL_STRING("DISP-0001", rpt.findings[0].disposition_id);
    TEST_ASSERT_EQUAL_STRING("accept", rpt.findings[0].disposition_action);

    free(list.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-DISP-ENFORCE002
//cfusa:test REQ-DISP-ENFORCE002
void test_apply_dispositions_mitigate_also_suppresses(void)
{
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-A002", SEV_ERROR);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));
    list.items = malloc(sizeof(cfusa_disposition_t));
    list.count = 1; list.cap = 1;
    memset(&list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(list.items[0].id, "DISP-0002");
    strcpy(list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(list.items[0].action, "mitigate");

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);
    TEST_ASSERT_EQUAL_INT(1, rpt.dispositioned_count);

    free(list.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-DISP-ENFORCE002
//cfusa:test REQ-DISP-ENFORCE002
void test_apply_dispositions_fix_action_does_not_suppress(void)
{
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-L003", SEV_WARNING);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));
    list.items = malloc(sizeof(cfusa_disposition_t));
    list.count = 1; list.cap = 1;
    memset(&list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(list.items[0].id, "DISP-0003");
    strcpy(list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(list.items[0].action, "fix");

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(1, rpt.warning_count); /* unaffected */
    TEST_ASSERT_EQUAL_INT(0, rpt.dispositioned_count);
    TEST_ASSERT_EQUAL_STRING("", rpt.findings[0].disposition_id);

    free(list.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-DISP-ENFORCE002
//cfusa:test REQ-DISP-ENFORCE002
void test_apply_dispositions_rule_only_no_fingerprint_does_not_suppress(void)
{
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-L003", SEV_WARNING);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));
    list.items = malloc(sizeof(cfusa_disposition_t));
    list.count = 1; list.cap = 1;
    memset(&list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(list.items[0].id, "DISP-0004");
    strcpy(list.items[0].rule, "CFUSA-L003");
    /* deliberately no fingerprint set — rule-only entry */
    strcpy(list.items[0].action, "accept");

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(1, rpt.warning_count); /* unaffected: no rule-wide leakage */
    TEST_ASSERT_EQUAL_INT(0, rpt.dispositioned_count);

    free(list.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-DISP-ENFORCE002
//cfusa:test REQ-DISP-ENFORCE002
void test_apply_dispositions_different_fingerprint_same_rule_unaffected(void)
{
    /* Two findings under the same rule, different fingerprints (different
     * messages) — dispositioning one must not affect the other. */
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "CFUSA-A006", "analyze", SEV_WARNING, "f.c", 1, "pointer 'x'");
    cfusa_report_add(&rpt, "CFUSA-A006", "analyze", SEV_WARNING, "f.c", 2, "pointer 'y'");
    TEST_ASSERT_TRUE(strcmp(rpt.findings[0].fingerprint, rpt.findings[1].fingerprint) != 0);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));
    list.items = malloc(sizeof(cfusa_disposition_t));
    list.count = 1; list.cap = 1;
    memset(&list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(list.items[0].id, "DISP-0005");
    strcpy(list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(list.items[0].action, "accept");

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(1, rpt.warning_count); /* only findings[1] still counts */
    TEST_ASSERT_EQUAL_INT(1, rpt.dispositioned_count);
    TEST_ASSERT_TRUE(rpt.findings[0].disposition_id[0] != '\0');
    TEST_ASSERT_TRUE(rpt.findings[1].disposition_id[0] == '\0');

    free(list.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-DISP-ENFORCE002
//cfusa:test REQ-DISP-ENFORCE002
void test_apply_dispositions_empty_list_is_noop(void)
{
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-L003", SEV_ERROR);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(1, rpt.error_count);
    TEST_ASSERT_EQUAL_INT(0, rpt.dispositioned_count);

    cfusa_report_free(&rpt);
}

/* ---- issue #208: findings baseline ---- */

static void write_baseline_json(const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-baseline.json", DE_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) { fputs(content, f); if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed"); }
}

static void rm_baseline_json(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-baseline.json", DE_DIR);
    remove(path);
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_baseline_load_missing_file_is_not_an_error(void)
{
    rm_baseline_json();
    cfusa_disposition_list_t list;
    int ok = cfusa_baseline_load(DE_DIR, &list);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(0, list.count);
    cfusa_dispositions_free(&list);
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_baseline_load_parses_baseline_action_entry(void)
{
    write_baseline_json(
        "{\n  \"baseline\": [\n"
        "    {\"id\":\"BASELINE-0001\",\"rule\":\"CFUSA-L003\","
        "\"fingerprint\":\"sha256:aaaa\",\"action\":\"baseline\"}\n"
        "  ]\n}\n");
    cfusa_disposition_list_t list;
    int ok = cfusa_baseline_load(DE_DIR, &list);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_INT(1, list.count);
    TEST_ASSERT_EQUAL_STRING("BASELINE-0001", list.items[0].id);
    TEST_ASSERT_EQUAL_STRING("sha256:aaaa", list.items[0].fingerprint);
    TEST_ASSERT_EQUAL_STRING("baseline", list.items[0].action);
    cfusa_dispositions_free(&list);
    rm_baseline_json();
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_apply_dispositions_baseline_action_suppresses(void)
{
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-L003", SEV_WARNING);

    cfusa_disposition_list_t list;
    memset(&list, 0, sizeof(list));
    list.items = malloc(sizeof(cfusa_disposition_t));
    list.count = 1; list.cap = 1;
    memset(&list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(list.items[0].id, "BASELINE-0001");
    strcpy(list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(list.items[0].action, "baseline");

    cfusa_report_apply_dispositions(&rpt, &list);

    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    TEST_ASSERT_EQUAL_INT(1, rpt.dispositioned_count);
    TEST_ASSERT_EQUAL_STRING("BASELINE-0001", rpt.findings[0].disposition_id);
    /* distinct from "accept" -- a report reader must be able to tell
     * "predates policy enrollment" apart from "reviewed and accepted". */
    TEST_ASSERT_EQUAL_STRING("baseline", rpt.findings[0].disposition_action);

    free(list.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-BASELINE002
//cfusa:test REQ-BASELINE002
void test_apply_dispositions_idempotent_across_two_lists(void)
{
    /* issue #208: cmd_check.c applies .fusa-dispositions.json, then
     * .fusa-baseline.json, against the SAME report. A finding matching
     * an entry in BOTH lists must only ever be suppressed once -- the
     * second matching call must be a no-op for it, not a second
     * decrement of warning_count/dispositioned_count. */
    cfusa_report_t rpt;
    one_finding(&rpt, "CFUSA-L003", SEV_WARNING);

    cfusa_disposition_list_t disp_list;
    memset(&disp_list, 0, sizeof(disp_list));
    disp_list.items = malloc(sizeof(cfusa_disposition_t));
    disp_list.count = 1; disp_list.cap = 1;
    memset(&disp_list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(disp_list.items[0].id, "DISP-0099");
    strcpy(disp_list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(disp_list.items[0].action, "accept");

    cfusa_disposition_list_t base_list;
    memset(&base_list, 0, sizeof(base_list));
    base_list.items = malloc(sizeof(cfusa_disposition_t));
    base_list.count = 1; base_list.cap = 1;
    memset(&base_list.items[0], 0, sizeof(cfusa_disposition_t));
    strcpy(base_list.items[0].id, "BASELINE-0099");
    strcpy(base_list.items[0].fingerprint, rpt.findings[0].fingerprint);
    strcpy(base_list.items[0].action, "baseline");

    cfusa_report_apply_dispositions(&rpt, &disp_list);
    cfusa_report_apply_dispositions(&rpt, &base_list); /* second call: must no-op */

    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    TEST_ASSERT_EQUAL_INT(1, rpt.dispositioned_count); /* not 2 */
    /* the FIRST list's tag wins -- the second call never overwrites it */
    TEST_ASSERT_EQUAL_STRING("DISP-0099", rpt.findings[0].disposition_id);
    TEST_ASSERT_EQUAL_STRING("accept", rpt.findings[0].disposition_action);

    free(disp_list.items);
    free(base_list.items);
    cfusa_report_free(&rpt);
}

/* ---- end-to-end: cmd_baseline / cmd_check ---- */

static void write_goto_source(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/goto.c", DE_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        fputs("void fn(void) {\n    goto end;\nend:;\n}\n", f);
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
}

static void rm_goto_source(void)
{
    char path[256]; snprintf(path, sizeof(path), "%s/goto.c", DE_DIR); remove(path);
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_cmd_baseline_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    TEST_ASSERT_EQUAL_INT(0, cmd_baseline(2, argv));
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_cmd_baseline_writes_file_and_check_suppresses_it(void)
{
    rm_disp_json();
    rm_baseline_json();
    write_goto_source();

    /* CFUSA-L002 (goto) is a warning, not an error -- use --strict so the
     * gate actually depends on it, mirroring
     * test_lint_exit_code_flips_after_accept_disposition() above. */
    char *before[] = {"cfusa", "--dir", DE_DIR, "--strict", NULL};
    int rc_before = cmd_check(4, before);
    TEST_ASSERT_TRUE(rc_before != 0);

    char *baseline_argv[] = {"cfusa", "--dir", DE_DIR, NULL};
    int baseline_rc = cmd_baseline(3, baseline_argv);
    TEST_ASSERT_EQUAL_INT(0, baseline_rc);

    char basepath[256];
    snprintf(basepath, sizeof(basepath), "%s/.fusa-baseline.json", DE_DIR);
    TEST_ASSERT_TRUE(cfusa_file_exists(basepath));

    char *after[] = {"cfusa", "--dir", DE_DIR, "--strict", NULL};
    int rc_after = cmd_check(4, after);
    TEST_ASSERT_EQUAL_INT(0, rc_after);

    rm_baseline_json();
    rm_goto_source();
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_cmd_baseline_does_not_hide_finding_introduced_after_snapshot(void)
{
    rm_disp_json();
    rm_baseline_json();
    write_goto_source();

    char *baseline_argv[] = {"cfusa", "--dir", DE_DIR, NULL};
    TEST_ASSERT_EQUAL_INT(0, cmd_baseline(3, baseline_argv));

    /* A genuinely different, NOT-yet-baselined finding (distinct rule) --
     * must still gate even though a baseline file now exists. */
    char path[256];
    snprintf(path, sizeof(path), "%s/goto.c", DE_DIR);
    FILE *f = fopen(path, "a");
    TEST_ASSERT_NOT_NULL(f);
    if (f) { fputs("#pragma once\n", f); TEST_ASSERT_EQUAL_INT(0, fclose(f)); }

    char *argv[] = {"cfusa", "--dir", DE_DIR, "--strict", NULL};
    int rc = cmd_check(4, argv);
    TEST_ASSERT_TRUE(rc != 0);

    rm_baseline_json();
    rm_goto_source();
}

//cfusa:req REQ-BASELINE001
//cfusa:test REQ-BASELINE001
void test_cmd_baseline_skips_findings_already_dispositioned(void)
{
    rm_disp_json();
    rm_baseline_json();
    write_goto_source();

    char fp[80];
    get_fingerprint_for_rule(cmd_check, "CFUSA-L002", fp, sizeof(fp));
    TEST_ASSERT_TRUE(fp[0] != '\0');

    char *add_argv[] = {"cfusa", "add", "--dir", DE_DIR,
                         "--rule", "CFUSA-L002", "--fingerprint", fp,
                         "--action", "accept", "--rationale", "reviewed, ok",
                         "--reviewer", "Jane", NULL};
    TEST_ASSERT_EQUAL_INT(0, cmd_disposition(14, add_argv));

    char *baseline_argv[] = {"cfusa", "--dir", DE_DIR, NULL};
    TEST_ASSERT_EQUAL_INT(0, cmd_baseline(3, baseline_argv));

    char basepath[256];
    snprintf(basepath, sizeof(basepath), "%s/.fusa-baseline.json", DE_DIR);
    size_t len = 0;
    char *content = cfusa_read_file(basepath, &len);
    TEST_ASSERT_NOT_NULL(content);
    if (content) {
        /* the already-dispositioned finding's fingerprint must NOT be
         * duplicated into the baseline file. */
        TEST_ASSERT_NULL(strstr(content, fp));
        free(content);
    }

    rm_disp_json();
    rm_baseline_json();
    rm_goto_source();
}

/* ---- end-to-end: cmd_check / cmd_lint / cmd_disposition ---- */

static void write_bad_source(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/bad.c", DE_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        /* A typed (not void*) pointer so this triggers exactly one lint
         * finding (CFUSA-L003) and one analyze finding (CFUSA-A002),
         * not also CFUSA-L008 ("avoid void*") as collateral noise. */
        fputs("void fn(void) {\n    char *p = malloc(64);\n}\n", f);
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
}

/* issue #122 core end-to-end scenario, at cmd_check's level. Uses JSON
 * output rather than the overall exit code: DE_DIR has no .fusa.json/
 * README/LICENSE/CI config/etc, so cmd_check's safety-scaffolding rules
 * (FUSA001-005, HARA001, ...) always also fire in this directory —
 * legitimately unrelated ERRORs/WARNINGs that no CFUSA-A002 disposition
 * should (or does) suppress, which would make an overall exit-code
 * assertion here fragile/misleading. The JSON summary's per-field deltas
 * are the precise, meaningful thing to check instead; the full
 * exit-code-flip guarantee is proven directly against cmd_lint below,
 * where no such collateral findings exist. */
//cfusa:req REQ-DISP-ENFORCE003
//cfusa:test REQ-DISP-ENFORCE003
void test_check_json_tags_and_omits_dispositioned_finding_from_gate(void)
{
    rm_disp_json();
    write_bad_source();

    char fp[80];
    get_fingerprint_for_rule(cmd_check, "CFUSA-A002", fp, sizeof(fp));
    TEST_ASSERT_TRUE(fp[0] != '\0');

    char *add_argv[] = {"cfusa", "add", "--dir", DE_DIR,
                         "--rule", "CFUSA-A002", "--fingerprint", fp,
                         "--action", "accept", "--rationale", "reviewed, ok",
                         "--reviewer", "Jane", NULL};
    int add_rc = cmd_disposition(14, add_argv);
    TEST_ASSERT_EQUAL_INT(0, add_rc);

    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/check_out.json", DE_DIR);
    char *argv[] = {"cfusa", "--dir", DE_DIR, "--format", "json",
                     "--output", outpath, NULL};
    cmd_check(7, argv);

    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[16384] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");

        TEST_ASSERT_NOT_NULL(strstr(buf, "\"dispositioned\": 1"));
        /* The CFUSA-A002 finding is still present (never dropped) and
         * carries the disposition tag. */
        char *a002 = strstr(buf, "\"CFUSA-A002\"");
        TEST_ASSERT_NOT_NULL(a002);
        char *next_finding = strstr(a002 + 1, "\"ruleId\"");
        size_t span = next_finding ? (size_t)(next_finding - a002) : strlen(a002);
        char snippet[512] = "";
        size_t cpy = span < sizeof(snippet) - 1 ? span : sizeof(snippet) - 1;
        memcpy(snippet, a002, cpy); snippet[cpy] = '\0';
        TEST_ASSERT_NOT_NULL(strstr(snippet, "\"dispositionId\": \"DISP-0001\""));
        TEST_ASSERT_NOT_NULL(strstr(snippet, "\"dispositionAction\": \"accept\""));

        remove(outpath);
    }

    rm_disp_json();
    char path[256]; snprintf(path, sizeof(path), "%s/bad.c", DE_DIR); remove(path);
}

/* Same guarantee for cmd_lint independently. */
//cfusa:req REQ-DISP-ENFORCE003
//cfusa:test REQ-DISP-ENFORCE003
void test_lint_exit_code_flips_after_accept_disposition(void)
{
    rm_disp_json();
    write_bad_source();

    char fp[80];
    get_fingerprint_for_rule(cmd_lint, "CFUSA-L003", fp, sizeof(fp));
    TEST_ASSERT_TRUE(fp[0] != '\0');

    /* CFUSA-L003 is a warning, not an error -- use --strict so it gates */
    char *before_strict[] = {"cfusa", "--dir", DE_DIR, "--strict", NULL};
    int rc_before = cmd_lint(4, before_strict);
    TEST_ASSERT_TRUE(rc_before != 0);

    char *add_argv[] = {"cfusa", "add", "--dir", DE_DIR,
                         "--rule", "CFUSA-L003", "--fingerprint", fp,
                         "--action", "mitigate", "--rationale", "reviewed, ok",
                         "--reviewer", "Jane", NULL};
    int add_rc = cmd_disposition(14, add_argv);
    TEST_ASSERT_EQUAL_INT(0, add_rc);

    char *after_strict[] = {"cfusa", "--dir", DE_DIR, "--strict", NULL};
    int rc_after = cmd_lint(4, after_strict);
    TEST_ASSERT_EQUAL_INT(0, rc_after);

    rm_disp_json();
    char path[256]; snprintf(path, sizeof(path), "%s/bad.c", DE_DIR); remove(path);
}

/* issue #153: cmd_lint never set rpt.project_root, so the identical real
 * CFUSA-L003 finding got a different (unrelativized) fingerprint from
 * `cfusa lint` than from `cfusa check` — silently breaking a disposition
 * recorded against one command's fingerprint when the other command runs. */
//cfusa:req REQ-DISP-ENFORCE001
//cfusa:test REQ-DISP-ENFORCE001
void test_check_and_lint_fingerprints_match_for_same_rule(void)
{
    write_bad_source();

    char fp_check[80], fp_lint[80];
    get_fingerprint_for_rule(cmd_check, "CFUSA-L003", fp_check, sizeof(fp_check));
    get_fingerprint_for_rule(cmd_lint,  "CFUSA-L003", fp_lint,  sizeof(fp_lint));

    TEST_ASSERT_TRUE(fp_check[0] != '\0');
    TEST_ASSERT_EQUAL_STRING(fp_check, fp_lint);

    char path[256]; snprintf(path, sizeof(path), "%s/bad.c", DE_DIR); remove(path);
}

/* Same guarantee for cmd_analyze (issue #153). */
//cfusa:req REQ-DISP-ENFORCE001
//cfusa:test REQ-DISP-ENFORCE001
void test_check_and_analyze_fingerprints_match_for_same_rule(void)
{
    write_bad_source();

    char fp_check[80], fp_analyze[80];
    get_fingerprint_for_rule(cmd_check,   "CFUSA-A002", fp_check,   sizeof(fp_check));
    get_fingerprint_for_rule(cmd_analyze, "CFUSA-A002", fp_analyze, sizeof(fp_analyze));

    TEST_ASSERT_TRUE(fp_check[0] != '\0');
    TEST_ASSERT_EQUAL_STRING(fp_check, fp_analyze);

    char path[256]; snprintf(path, sizeof(path), "%s/bad.c", DE_DIR); remove(path);
}

/* cmd_check must never crash / must still succeed when no dispositions
 * file exists at all (the overwhelmingly common case). */
//cfusa:req REQ-DISP-ENFORCE003
//cfusa:test REQ-DISP-ENFORCE003
void test_check_runs_fine_with_no_dispositions_file(void)
{
    rm_disp_json();
    write_bad_source();
    char *argv[] = {"cfusa", "--dir", DE_DIR, NULL};
    int rc = cmd_check(3, argv);
    (void)rc; /* just must not crash */
    char path[256]; snprintf(path, sizeof(path), "%s/bad.c", DE_DIR); remove(path);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_dispositions_load_missing_file_is_not_an_error);
    RUN_TEST(test_dispositions_load_parses_fingerprint_field);
    RUN_TEST(test_dispositions_load_tolerates_whitespace_after_colon);
    RUN_TEST(test_dispositions_load_normalizes_accepted_to_accept);
    RUN_TEST(test_apply_dispositions_accept_suppresses_matching_fingerprint);
    RUN_TEST(test_apply_dispositions_mitigate_also_suppresses);
    RUN_TEST(test_apply_dispositions_fix_action_does_not_suppress);
    RUN_TEST(test_apply_dispositions_rule_only_no_fingerprint_does_not_suppress);
    RUN_TEST(test_apply_dispositions_different_fingerprint_same_rule_unaffected);
    RUN_TEST(test_apply_dispositions_empty_list_is_noop);
    RUN_TEST(test_baseline_load_missing_file_is_not_an_error);
    RUN_TEST(test_baseline_load_parses_baseline_action_entry);
    RUN_TEST(test_apply_dispositions_baseline_action_suppresses);
    RUN_TEST(test_apply_dispositions_idempotent_across_two_lists);
    RUN_TEST(test_cmd_baseline_help_returns_zero);
    RUN_TEST(test_cmd_baseline_writes_file_and_check_suppresses_it);
    RUN_TEST(test_cmd_baseline_does_not_hide_finding_introduced_after_snapshot);
    RUN_TEST(test_cmd_baseline_skips_findings_already_dispositioned);
    RUN_TEST(test_check_json_tags_and_omits_dispositioned_finding_from_gate);
    RUN_TEST(test_lint_exit_code_flips_after_accept_disposition);
    RUN_TEST(test_check_and_lint_fingerprints_match_for_same_rule);
    RUN_TEST(test_check_and_analyze_fingerprints_match_for_same_rule);
    RUN_TEST(test_check_runs_fine_with_no_dispositions_file);
    return UNITY_END();
}
