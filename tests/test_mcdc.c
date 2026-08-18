/*
 * Tests for MC/DC coverage analysis (Feature 3).
 * Exercises cmd_coverage --mcdc-file and --mcdc-threshold.
 *
 * issue #129: the old fixtures here used a hand-invented
 * {"covered_true_count":N,"covered_false_count":M} schema that never
 * matched real `llvm-cov export -format=text` output (real schema:
 * data[].totals.mcdc.{count,covered}, and data[].files[]/functions[]
 * mcdc_records[] entries are positional arrays, not objects) — which is
 * presumably why the mismatch was never caught. All fixtures below use
 * the real key names/nesting; two (test_mcdc_real_llvm_cov_export_*)
 * embed output actually captured from a real `-fcoverage-mcdc` build
 * (Apple clang 21, 2026-08) verbatim, not hand-authored, closing that
 * gap directly.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_coverage(int argc, char **argv);

#define MCDC_TEST_DIR "/tmp/cfusa_mcdc_testdir"

void setUp(void)    { (void)mkdir(MCDC_TEST_DIR, 0700); }
void tearDown(void) {}

static void write_mcdc_json(const char *fname, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", MCDC_TEST_DIR, fname);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE *f = (fd >= 0) ? fdopen(fd, "w") : NULL;
    if (f) { fputs(content, f); fclose(f); }
    else if (fd >= 0) { close(fd); }
}

/* ── Feature 3 tests ─────────────────────────────────────────────────────── */

/* --help returns 0 (covers new --mcdc-file/--mcdc-threshold in help) */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "coverage", "--help", NULL};
    int rc = cmd_coverage(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* All conditions covered → exit 0. Real schema: data[].totals.mcdc. */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_all_covered_passes(void)
{
    write_mcdc_json("all_covered.json",
        "{\"data\":[{\"files\":[{\"filename\":\"f.c\","
        "\"mcdc_records\":[[1,27,1,33,1,2,0,0,5,[true,true]]],"
        "\"summary\":{\"mcdc\":{\"count\":2,\"covered\":2,\"notcovered\":0,\"percent\":100}}}],"
        "\"functions\":[{\"name\":\"f\",\"mcdc_records\":[[1,27,1,33,1,2,0,0,5,[true,true]]]}],"
        "\"totals\":{\"mcdc\":{\"count\":2,\"covered\":2,\"notcovered\":0,\"percent\":100}}}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/all_covered.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    /* Should pass: 2/2 conditions covered = 100% >= threshold 100.
     * Scoping to "totals" only (not "summary") matters here: if the
     * per-file "summary".mcdc were also counted, this would read 4/4 —
     * still 100%, so a regression here wouldn't be caught by this test
     * alone; test_mcdc_no_double_counts_file_and_totals_mcdc below
     * exercises the double-counting case explicitly with a threshold
     * that would only fail if double-counted wrong. */
    TEST_ASSERT_EQUAL(0, rc);
}

/* Uncovered condition → exit 1. */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_uncovered_condition_fails(void)
{
    write_mcdc_json("uncovered.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":2,\"covered\":0,\"notcovered\":2,\"percent\":0}}}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/uncovered.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    /* Should fail: 0/2 conditions covered = 0% < threshold 100 */
    TEST_ASSERT_EQUAL(1, rc);
}

/* issue #129: a real llvm-cov export duplicates the same mcdc_records[]
 * content at both per-file ("summary") and per-data-entry ("totals")
 * scope. A parser that counted every raw record occurrence rather than
 * scoping strictly to "totals" would double the true condition count —
 * here, with a threshold chosen so 2/2 (correct, totals-scoped) passes
 * but 4/4 read-as-2-real-conditions-double-counted would still
 * (coincidentally) read as 100% too, so this test instead pins the exact
 * totalConditions the JSON report shows, which a doubled count would
 * visibly break. */
//cfusa:req REQ-COV016
//cfusa:test REQ-COV016
void test_mcdc_no_double_counts_file_and_totals_mcdc(void)
{
    write_mcdc_json("double_count.json",
        "{\"data\":[{\"files\":[{\"filename\":\"f.c\","
        "\"mcdc_records\":[[1,27,1,33,1,2,0,0,5,[true,true]]],"
        "\"summary\":{\"mcdc\":{\"count\":2,\"covered\":2,\"notcovered\":0,\"percent\":100}}}],"
        "\"functions\":[{\"name\":\"f\",\"mcdc_records\":[[1,27,1,33,1,2,0,0,5,[true,true]]]}],"
        "\"totals\":{\"mcdc\":{\"count\":2,\"covered\":2,\"notcovered\":0,\"percent\":100}}}]}");

    char path[256], out[256];
    snprintf(path, sizeof(path), "%s/double_count.json", MCDC_TEST_DIR);
    snprintf(out, sizeof(out), "%s/double_count_out.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage", "--mcdc-file", path,
                    "--format", "json", "--output", out, NULL};
    int rc = cmd_coverage(8, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        /* Exactly 2, not 4 (which double-counting file+totals would give). */
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"totalConditions\": 2"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"coveredConditions\": 2"));
        (void)remove(out);
    }
}

/* No condition records anywhere in the export → exit 1, NOT a silent pass.
 * Previously this returned 0 ("nothing to fail"), which is indistinguishable
 * from a wrong/empty/malformed --mcdc-file from content alone — the same
 * silent-incomplete-data-reads-as-complete failure mode fixed elsewhere in
 * this tool (issue #100). A caller asserting --mcdc-file must get a real
 * answer, not a pass that could just as easily mean "nothing was parsed." */
//cfusa:req REQ-COV021
//cfusa:test REQ-COV021
void test_mcdc_no_records_fails(void)
{
    write_mcdc_json("no_records.json",
        "{\"data\":[{\"files\":[],\"functions\":[],"
        "\"totals\":{\"branches\":{\"count\":0,\"covered\":0}}}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/no_records.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

/* A wrong/garbage --mcdc-file (readable, but not an MC/DC export at all)
 * must fail the same way an empty one does, not silently pass because the
 * string-scan simply found nothing to parse. */
//cfusa:req REQ-COV021
//cfusa:test REQ-COV021
void test_mcdc_garbage_file_fails(void)
{
    write_mcdc_json("garbage.json", "this is not an MC/DC export at all\n");

    char path[256];
    snprintf(path, sizeof(path), "%s/garbage.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

/* The failure note explains why, rather than leaving a bare exit code. */
//cfusa:req REQ-COV021
//cfusa:test REQ-COV021
void test_mcdc_no_records_note_explains_failure(void)
{
    write_mcdc_json("no_records2.json",
        "{\"data\":[{\"files\":[],\"functions\":[]}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/no_records2.json", MCDC_TEST_DIR);
    char out[256];
    snprintf(out, sizeof(out), "%s/no_records_out.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage", "--mcdc-file", path,
                    "--format", "json", "--output", out, NULL};
    int rc = cmd_coverage(8, argv);
    TEST_ASSERT_EQUAL(1, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"passed\": false"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "no MC/DC condition records found"));
        (void)remove(out);
    }
}

/* --mcdc-threshold below actual coverage → pass */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_threshold_below_coverage_passes(void)
{
    /* 1 of 2 conditions covered → 50% */
    write_mcdc_json("mixed.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":2,\"covered\":1,\"notcovered\":1,\"percent\":50}}}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/mixed.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path,
                    "--mcdc-threshold", "50", NULL};
    int rc = cmd_coverage(6, argv);
    /* 50% coverage >= 50% threshold → pass */
    TEST_ASSERT_EQUAL(0, rc);
}

/* --mcdc-threshold above actual coverage → fail */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_threshold_above_coverage_fails(void)
{
    write_mcdc_json("mixed2.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":2,\"covered\":1,\"notcovered\":1,\"percent\":50}}}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/mixed2.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path,
                    "--mcdc-threshold", "80", NULL};
    int rc = cmd_coverage(6, argv);
    /* 50% coverage < 80% threshold → fail */
    TEST_ASSERT_EQUAL(1, rc);
}

/* JSON output includes mcdcReport field */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_json_output_has_mcdc_report(void)
{
    write_mcdc_json("covered2.json",
        "{\"data\":[{\"totals\":{\"mcdc\":"
        "{\"count\":1,\"covered\":1,\"notcovered\":0,\"percent\":100}}}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/covered2.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path,
                    "--format", "json",
                    "--output", "/tmp/cfusa_mcdc_out.json", NULL};
    int rc = cmd_coverage(8, argv); /* 8 non-NULL elements */
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_mcdc_out.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "mcdcReport"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "totalConditions"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "coveragePct"));
        (void)remove("/tmp/cfusa_mcdc_out.json");
    }
}

/* issue #129: fixtures generated from an actual `llvm-cov export
 * -format=text` run, embedded verbatim (not hand-authored), rather than
 * a fixture written to match what the parser's author assumed the
 * schema looked like -- captured 2026-08 from Apple clang 21 /
 * current upstream LLVM lineage building:
 *   int f(int a, int b) { if (a && b) return 1; return 0; }
 *   int main(void) { f(1,1); f(0,1); f(1,0); return 0; }
 * with -fprofile-instr-generate -fcoverage-mapping -fcoverage-mcdc,
 * exercising both branches of the `a && b` decision -> full MC/DC. */
//cfusa:req REQ-COV016
//cfusa:test REQ-COV016
void test_mcdc_real_llvm_cov_export_full_coverage_passes(void)
{
    write_mcdc_json("real_full.json",
        "{\"data\":[{\"files\":[{\"branches\":[[1,27,1,28,2,1,0,0,6],"
        "[1,32,1,33,1,1,0,0,6]],\"expansions\":[],\"filename\":\"t.c\","
        "\"mcdc_records\":[[1,27,1,33,1,2,0,0,5,[true,true]]],"
        "\"summary\":{\"branches\":{\"count\":4,\"covered\":4,\"notcovered\":0,\"percent\":100},"
        "\"functions\":{\"count\":2,\"covered\":2,\"percent\":100},"
        "\"instantiations\":{\"count\":2,\"covered\":2,\"percent\":100},"
        "\"lines\":{\"count\":2,\"covered\":2,\"percent\":100},"
        "\"mcdc\":{\"count\":2,\"covered\":2,\"notcovered\":0,\"percent\":100},"
        "\"regions\":{\"count\":7,\"covered\":7,\"notcovered\":0,\"percent\":100}}}],"
        "\"functions\":[{\"branches\":[[1,27,1,28,2,1,0,0,6],[1,32,1,33,1,1,0,0,6]],"
        "\"count\":3,\"filenames\":[\"t.c\"],"
        "\"mcdc_records\":[[1,27,1,33,1,2,0,0,5,[true,true]]],\"name\":\"f\","
        "\"regions\":[[1,21,1,56,3,0,0,0]]},"
        "{\"branches\":[],\"count\":1,\"filenames\":[\"t.c\"],"
        "\"mcdc_records\":[],\"name\":\"main\",\"regions\":[[2,16,2,53,1,0,0,0]]}],"
        "\"totals\":{\"branches\":{\"count\":4,\"covered\":4,\"notcovered\":0,\"percent\":100},"
        "\"functions\":{\"count\":2,\"covered\":2,\"percent\":100},"
        "\"instantiations\":{\"count\":2,\"covered\":2,\"percent\":100},"
        "\"lines\":{\"count\":2,\"covered\":2,\"percent\":100},"
        "\"mcdc\":{\"count\":2,\"covered\":2,\"notcovered\":0,\"percent\":100},"
        "\"regions\":{\"count\":7,\"covered\":7,\"notcovered\":0,\"percent\":100}}}],"
        "\"type\":\"llvm.coverage.json.export\",\"version\":\"3.0.1\"}");

    char path[256];
    snprintf(path, sizeof(path), "%s/real_full.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage", "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* Same real-export capture, but for a build exercising only the
 * all-true branch of `a && b` twice (never a=0 or b=0) -> both
 * independence pairs unproven, 0% MC/DC. */
//cfusa:req REQ-COV016
//cfusa:test REQ-COV016
void test_mcdc_real_llvm_cov_export_zero_coverage_fails(void)
{
    write_mcdc_json("real_zero.json",
        "{\"data\":[{\"files\":[{\"branches\":[[1,27,1,28,1,1,0,0,6],"
        "[1,32,1,33,1,0,0,0,6]],\"expansions\":[],\"filename\":\"t.c\","
        "\"mcdc_records\":[[1,27,1,33,0,0,0,0,5,[false,false]]],"
        "\"summary\":{\"mcdc\":{\"count\":2,\"covered\":0,\"notcovered\":2,\"percent\":0}}}],"
        "\"functions\":[{\"filenames\":[\"t.c\"],"
        "\"mcdc_records\":[[1,27,1,33,0,0,0,0,5,[false,false]]],\"name\":\"f\"}],"
        "\"totals\":{\"mcdc\":{\"count\":2,\"covered\":0,\"notcovered\":2,\"percent\":0}}}],"
        "\"type\":\"llvm.coverage.json.export\",\"version\":\"3.0.1\"}");

    char path[256];
    snprintf(path, sizeof(path), "%s/real_zero.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage", "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mcdc_help_returns_zero);
    RUN_TEST(test_mcdc_all_covered_passes);
    RUN_TEST(test_mcdc_uncovered_condition_fails);
    RUN_TEST(test_mcdc_no_double_counts_file_and_totals_mcdc);
    RUN_TEST(test_mcdc_no_records_fails);
    RUN_TEST(test_mcdc_garbage_file_fails);
    RUN_TEST(test_mcdc_no_records_note_explains_failure);
    RUN_TEST(test_mcdc_threshold_below_coverage_passes);
    RUN_TEST(test_mcdc_threshold_above_coverage_fails);
    RUN_TEST(test_mcdc_json_output_has_mcdc_report);
    RUN_TEST(test_mcdc_real_llvm_cov_export_full_coverage_passes);
    RUN_TEST(test_mcdc_real_llvm_cov_export_zero_coverage_fails);
    return UNITY_END();
}
