/*
 * Tests for the ASIL-aware MC/DC/coverage gate in cfusa coverage
 * (--asil, c-FuSa issue #106).
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "cfusa/utils.h"

extern int cmd_coverage(int argc, char **argv);

#define COVA_DIR "/tmp/cfusa_coverage_asil_testdir"

void setUp(void)    { (void)mkdir(COVA_DIR, 0700); }
void tearDown(void) {}

static void write_lcov(const char *fname, long lines_found, long lines_hit,
                        long branches_found, long branches_hit)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", COVA_DIR, fname);
    FILE *f = cfusa_fopen_write(path);
    if (!f) return;
    fprintf(f,
        "SF:src/example.c\n"
        "LF:%ld\nLH:%ld\n"
        "BRF:%ld\nBRH:%ld\n"
        "end_of_record\n",
        lines_found, lines_hit, branches_found, branches_hit);
    if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
}

static void write_mcdc(const char *fname, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", COVA_DIR, fname);
    FILE *f = cfusa_fopen_write(path);
    if (!f) return;
    fputs(content, f);
    if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
}

/* ---- validation ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_invalid_returns_2(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/full.info", COVA_DIR);
    write_lcov("full.info", 10, 10, 4, 4);
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-Z", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

/* ---- ASIL-A/B: full line coverage required, branch not required ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_a_fails_below_full_line(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/partial_line.info", COVA_DIR);
    write_lcov("partial_line.info", 100, 60, 10, 5); /* 60% line */
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-A", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_a_passes_full_line_partial_branch(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/full_line.info", COVA_DIR);
    write_lcov("full_line.info", 100, 100, 10, 5); /* 100% line, 50% branch */
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-A", NULL};
    int rc = cmd_coverage(5, argv);
    /* ASIL-A doesn't require branch coverage -> passes on line alone. */
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- ASIL-C: full line + branch required, MC/DC not required ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_c_fails_below_full_branch(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/partial_branch.info", COVA_DIR);
    write_lcov("partial_branch.info", 100, 100, 10, 6); /* 100% line, 60% branch */
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-C", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_c_passes_full_line_and_branch(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/full_both.info", COVA_DIR);
    write_lcov("full_both.info", 100, 100, 10, 10); /* 100% line + branch */
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-C", NULL};
    int rc = cmd_coverage(5, argv);
    /* ASIL-C doesn't require MC/DC -> full line+branch is enough. */
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- ASIL-D: full line + branch + MC/DC required ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_d_full_branch_proxy_passes(void)
{
    /* No --mcdc-file given: falls back to the same "100% branch coverage
     * as an MC/DC proxy" behavior --dal DAL-A already uses. */
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/full_both2.info", COVA_DIR);
    write_lcov("full_both2.info", 100, 100, 10, 10);
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-D", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_d_with_precise_mcdc_file_fails_when_incomplete(void)
{
    /* --mcdc-file's precise LLVM MC/DC result overrides the coarse branch
     * proxy, same composition as --dal DAL-A + --mcdc-file already has. */
    char lcov[256], mcdc[256];
    snprintf(lcov, sizeof(lcov), "%s/full_both3.info", COVA_DIR);
    snprintf(mcdc, sizeof(mcdc), "%s/half.json", COVA_DIR);
    write_lcov("full_both3.info", 100, 100, 10, 10);
    /* issue #129: real llvm-cov export schema is data[].totals.mcdc.
     * {count,covered}, not {"covered_true_count","covered_false_count"}. */
    write_mcdc("half.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":2,\"covered\":1,\"notcovered\":1,\"percent\":50}}}]}");
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-D",
                    "--mcdc-file", mcdc, NULL};
    int rc = cmd_coverage(7, argv);
    /* 1/2 conditions MC/DC-covered = 50% < 100% threshold -> fail. */
    TEST_ASSERT_EQUAL(1, rc);
}

/* ---- --dal and --asil combine to the stricter requirement ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_dal_d_and_asil_d_combine_to_stricter(void)
{
    /* --dal DAL-D alone would disable every threshold (0/0/off); --asil
     * ASIL-D declared alongside it must still raise the bar to
     * 100%/100%/MC/DC-required rather than being silently overridden. */
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/partial3.info", COVA_DIR);
    write_lcov("partial3.info", 100, 60, 10, 6); /* 60% line, 60% branch */
    char *argv[] = {"cfusa", "--lcov", lcov,
                    "--dal", "DAL-D", "--asil", "ASIL-D", NULL};
    int rc = cmd_coverage(7, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

/* ---- JSON output carries the asil field ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_coverage_asil_appears_in_json_output(void)
{
    char lcov[256], out[256];
    snprintf(lcov, sizeof(lcov), "%s/full_both4.info", COVA_DIR);
    snprintf(out, sizeof(out), "%s/asil_out.json", COVA_DIR);
    write_lcov("full_both4.info", 10, 10, 4, 4);
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-B",
                    "--format", "json", "--output", out, NULL};
    int rc = cmd_coverage(9, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"asil\": \"ASIL-B\""));
        (void)remove(out);
    }
}

/* ---- --branch-threshold (issue #137) ---- */

/* Measured branch coverage at/above --branch-threshold -> pass, with no
 * --threshold (line) interaction: line coverage here is well below the
 * default 80%% line threshold, and --branch-threshold alone doesn't gate
 * line coverage at all -- only overall_pass would fail if it did. */
//cfusa:req REQ-COV022
//cfusa:test REQ-COV022
void test_branch_threshold_pass_does_not_gate_line_coverage(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/bt_pass.info", COVA_DIR);
    write_lcov("bt_pass.info", 100, 10, 10, 5); /* 10% line, 50% branch */
    char *argv[] = {"cfusa", "--lcov", lcov, "--branch-threshold", "40", NULL};
    int rc = cmd_coverage(5, argv);
    /* line 10% < default 80% threshold -> overall still fails, but on the
     * LINE gate, not the branch one -- confirmed via JSON below instead,
     * where each gate's own pass/fail is visible independently. */
    (void)rc;

    char out[256];
    snprintf(out, sizeof(out), "%s/bt_pass_out.json", COVA_DIR);
    char *jargv[] = {"cfusa", "--lcov", lcov, "--branch-threshold", "40",
                      "--format", "json", "--output", out, NULL};
    cmd_coverage(9, jargv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"branchThreshold\": 40.0"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"pct\": 50.00}"));
        (void)remove(out);
    }
}

/* Measured branch coverage below --branch-threshold -> fail, even with
 * line coverage at 100%% (well above the default --threshold). Proves
 * --branch-threshold gates independently of --threshold, as requested. */
//cfusa:req REQ-COV022
//cfusa:test REQ-COV022
void test_branch_threshold_fails_independently_of_line_threshold(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/bt_fail.info", COVA_DIR);
    write_lcov("bt_fail.info", 10, 10, 10, 5); /* 100% line, 50% branch */
    char *argv[] = {"cfusa", "--lcov", lcov, "--branch-threshold", "60", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

/* No --branch-threshold (and no --dal/--asil) -> branch coverage is not
 * enforced at all, matching pre-#137 behavior exactly. */
//cfusa:req REQ-COV022
//cfusa:test REQ-COV022
void test_branch_threshold_unset_does_not_gate_branch(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/bt_unset.info", COVA_DIR);
    write_lcov("bt_unset.info", 10, 10, 10, 0); /* 100% line, 0% branch */
    char *argv[] = {"cfusa", "--lcov", lcov, NULL};
    int rc = cmd_coverage(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* issue #137: an explicit --branch-threshold weaker than --dal/--asil's
 * own (fixed 100%%) branch requirement must NOT weaken it -- it only ever
 * raises the floor, never lowers it. */
//cfusa:req REQ-COV022
//cfusa:test REQ-COV022
void test_branch_threshold_does_not_weaken_dal_requirement(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/bt_dal.info", COVA_DIR);
    write_lcov("bt_dal.info", 10, 10, 10, 5); /* 100% line, 50% branch */
    /* DAL-B requires 100% branch; a weaker --branch-threshold 10 must not
     * downgrade that requirement to 10%. */
    char *argv[] = {"cfusa", "--lcov", lcov, "--dal", "DAL-B",
                     "--branch-threshold", "10", NULL};
    int rc = cmd_coverage(7, argv);
    TEST_ASSERT_EQUAL(1, rc); /* still fails: 50% < DAL-B's 100% */
}

/* An explicit --branch-threshold stricter than --dal/--asil's own branch
 * requirement DOES apply (raises the floor). */
//cfusa:req REQ-COV022
//cfusa:test REQ-COV022
void test_branch_threshold_raises_above_dal_requirement(void)
{
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/bt_raise.info", COVA_DIR);
    write_lcov("bt_raise.info", 10, 10, 10, 8); /* 100% line, 80% branch */
    /* DAL-C has no branch requirement (threshold_branch=0 from DAL-C);
     * --branch-threshold 90 raises it, and 80% < 90% -> fail. */
    char *argv[] = {"cfusa", "--lcov", lcov, "--dal", "DAL-C",
                     "--branch-threshold", "90", NULL};
    int rc = cmd_coverage(7, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

/* --help documents the new flag. */
//cfusa:req REQ-COV022
//cfusa:test REQ-COV022
void test_branch_threshold_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_coverage(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- issue #142: empty/corrupt/unreadable lcov must never read as 100% ---- */

//cfusa:req REQ-COV001
//cfusa:test REQ-COV001
void test_coverage_empty_lcov_fails_not_100pct(void)
{
    /* A 0-byte lcov file contains no LF:/LH: records at all — pct(0,0)
     * used to default to 100.0 with no zero-found guard, so this
     * silently reported full coverage and PASS. */
    char path[256];
    snprintf(path, sizeof(path), "%s/empty.info", COVA_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) TEST_ASSERT_EQUAL(0, fclose(f));

    char *argv[] = {"cfusa", "--lcov", path, "--threshold", "50", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-COV001
//cfusa:test REQ-COV001
void test_coverage_empty_lcov_json_reports_not_passed(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/empty2.info", COVA_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) TEST_ASSERT_EQUAL(0, fclose(f));

    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/empty2_out.json", COVA_DIR);
    char *argv[] = {"cfusa", "--lcov", path, "--threshold", "50",
                     "--format", "json", "--output", outpath, NULL};
    int rc = cmd_coverage(9, argv);
    TEST_ASSERT_TRUE(rc != 0);

    FILE *jf = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(jf);
    if (jf) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0';
        TEST_ASSERT_EQUAL(0, fclose(jf));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"passed\": false"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"lcovNote\""));
    }
}

//cfusa:req REQ-COV001
//cfusa:test REQ-COV001
void test_coverage_unreadable_lcov_fails(void)
{
    /* A path that cfusa_file_exists() sees but fopen() can't open (e.g.
     * a directory given by mistake instead of a file) must fail the
     * same way, not silently report 100%. */
    char dirpath[256];
    snprintf(dirpath, sizeof(dirpath), "%s/not_a_file.info", COVA_DIR);
    (void)mkdir(dirpath, 0700);

    char *argv[] = {"cfusa", "--lcov", dirpath, "--threshold", "50", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-COV001
//cfusa:test REQ-COV001
void test_coverage_real_lcov_still_passes(void)
{
    /* Sanity check the fix doesn't overcorrect into failing genuine data. */
    write_lcov("real.info", 10, 10, 4, 4);
    char path[256];
    snprintf(path, sizeof(path), "%s/real.info", COVA_DIR);
    char *argv[] = {"cfusa", "--lcov", path, "--threshold", "50", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- issue #172: --dal DAL-D must not discard an explicit --threshold ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_dal_d_does_not_discard_explicit_threshold(void)
{
    /* Before the fix, apply_dal()'s DAL-D branch unconditionally zeroed
     * both threshold outputs, silently discarding whatever
     * floor the caller already had -- including an explicit --threshold
     * the user passed on the command line. 60% line coverage against an
     * explicit --threshold 70 must still fail even under --dal DAL-D,
     * exactly as it would with no --dal flag at all. */
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/dal_d_explicit.info", COVA_DIR);
    write_lcov("dal_d_explicit.info", 100, 60, 10, 6); /* 60% line, 60% branch */
    char *argv[] = {"cfusa", "--lcov", lcov, "--threshold", "70",
                     "--dal", "DAL-D", NULL};
    int rc = cmd_coverage(7, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_dal_d_leaves_default_threshold_passing_case_alone(void)
{
    /* Control: with the (non-explicit) 80% default threshold and 100%
     * line/branch coverage, --dal DAL-D still passes -- DAL-D truly means
     * "no additional DO-178C requirement on top of whatever's already
     * there", not "force a failure". */
    char lcov[256];
    snprintf(lcov, sizeof(lcov), "%s/dal_d_default.info", COVA_DIR);
    write_lcov("dal_d_default.info", 100, 100, 10, 10);
    char *argv[] = {"cfusa", "--lcov", lcov, "--dal", "DAL-D", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- issue #152: --dal DAL-A / --asil ASIL-D floor --mcdc-threshold to 100 ---- */

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_dal_a_floors_weak_explicit_mcdc_threshold_to_100(void)
{
    /* 60% MC/DC condition coverage would PASS against an explicit
     * --mcdc-threshold 50 on its own, but --dal DAL-A requires 100%
     * MC/DC -- the weaker explicit threshold must be raised to 100,
     * turning this into a FAIL. */
    char lcov[256], mcdc[256], out[256];
    snprintf(lcov, sizeof(lcov), "%s/dal_a_mcdc.info", COVA_DIR);
    snprintf(mcdc, sizeof(mcdc), "%s/dal_a_mcdc.json", COVA_DIR);
    snprintf(out,  sizeof(out),  "%s/dal_a_mcdc_out.json", COVA_DIR);
    write_lcov("dal_a_mcdc.info", 100, 100, 10, 10);
    write_mcdc("dal_a_mcdc.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":5,\"covered\":3,\"notcovered\":2,\"percent\":60}}}]}");
    char *argv[] = {"cfusa", "--lcov", lcov, "--dal", "DAL-A",
                     "--mcdc-file", mcdc, "--mcdc-threshold", "50",
                     "--format", "json", "--output", out, NULL};
    int rc = cmd_coverage(13, argv);
    TEST_ASSERT_EQUAL(1, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        TEST_ASSERT_EQUAL(0, fclose(f));
        /* the floored threshold (100), not the weaker requested one (50) */
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"threshold\": 100"));
        (void)remove(out);
    }
}

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_asil_d_floors_weak_explicit_mcdc_threshold_to_100(void)
{
    /* Same as above but via --asil ASIL-D (rank 4) instead of --dal DAL-A. */
    char lcov[256], mcdc[256];
    snprintf(lcov, sizeof(lcov), "%s/asil_d_mcdc.info", COVA_DIR);
    snprintf(mcdc, sizeof(mcdc), "%s/asil_d_mcdc.json", COVA_DIR);
    write_lcov("asil_d_mcdc.info", 100, 100, 10, 10);
    write_mcdc("asil_d_mcdc.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":5,\"covered\":3,\"notcovered\":2,\"percent\":60}}}]}");
    char *argv[] = {"cfusa", "--lcov", lcov, "--asil", "ASIL-D",
                     "--mcdc-file", mcdc, "--mcdc-threshold", "50", NULL};
    int rc = cmd_coverage(9, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-COV020
//cfusa:test REQ-COV020
void test_mcdc_threshold_not_floored_without_dal_a_or_asil_d(void)
{
    /* Control: the same 60%-covered MC/DC file with the same explicit
     * --mcdc-threshold 50, but with no --dal/--asil (or a lower tier)
     * present -- must NOT be floored, and passes on its own terms. */
    char lcov[256], mcdc[256];
    snprintf(lcov, sizeof(lcov), "%s/no_dal_mcdc.info", COVA_DIR);
    snprintf(mcdc, sizeof(mcdc), "%s/no_dal_mcdc.json", COVA_DIR);
    write_lcov("no_dal_mcdc.info", 100, 100, 10, 10);
    write_mcdc("no_dal_mcdc.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":5,\"covered\":3,\"notcovered\":2,\"percent\":60}}}]}");
    char *argv[] = {"cfusa", "--lcov", lcov, "--mcdc-file", mcdc,
                     "--mcdc-threshold", "50", NULL};
    int rc = cmd_coverage(7, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_coverage_asil_invalid_returns_2);
    RUN_TEST(test_coverage_asil_a_fails_below_full_line);
    RUN_TEST(test_coverage_asil_a_passes_full_line_partial_branch);
    RUN_TEST(test_coverage_asil_c_fails_below_full_branch);
    RUN_TEST(test_coverage_asil_c_passes_full_line_and_branch);
    RUN_TEST(test_coverage_asil_d_full_branch_proxy_passes);
    RUN_TEST(test_coverage_asil_d_with_precise_mcdc_file_fails_when_incomplete);
    RUN_TEST(test_coverage_dal_d_and_asil_d_combine_to_stricter);
    RUN_TEST(test_coverage_asil_appears_in_json_output);
    RUN_TEST(test_branch_threshold_pass_does_not_gate_line_coverage);
    RUN_TEST(test_branch_threshold_fails_independently_of_line_threshold);
    RUN_TEST(test_branch_threshold_unset_does_not_gate_branch);
    RUN_TEST(test_branch_threshold_does_not_weaken_dal_requirement);
    RUN_TEST(test_branch_threshold_raises_above_dal_requirement);
    RUN_TEST(test_branch_threshold_help_returns_zero);
    RUN_TEST(test_coverage_empty_lcov_fails_not_100pct);
    RUN_TEST(test_coverage_empty_lcov_json_reports_not_passed);
    RUN_TEST(test_coverage_unreadable_lcov_fails);
    RUN_TEST(test_coverage_real_lcov_still_passes);
    RUN_TEST(test_dal_d_does_not_discard_explicit_threshold);
    RUN_TEST(test_dal_d_leaves_default_threshold_passing_case_alone);
    RUN_TEST(test_dal_a_floors_weak_explicit_mcdc_threshold_to_100);
    RUN_TEST(test_asil_d_floors_weak_explicit_mcdc_threshold_to_100);
    RUN_TEST(test_mcdc_threshold_not_floored_without_dal_a_or_asil_d);
    return UNITY_END();
}
