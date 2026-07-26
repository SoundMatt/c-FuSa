/*
 * Tests for MC/DC coverage analysis (Feature 3).
 * Exercises cmd_coverage --mcdc-file and --mcdc-threshold.
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

/* All conditions covered → exit 0 */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_all_covered_passes(void)
{
    /* covered_true_count=3, covered_false_count=2 → covered */
    write_mcdc_json("all_covered.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Foo\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":3,\"covered_false_count\":2}"
        "]}]}]}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/all_covered.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    /* Should pass: 1/1 conditions covered = 100% >= threshold 100 */
    TEST_ASSERT_EQUAL(0, rc);
}

/* Uncovered condition (false_count=0) → exit 1 */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_uncovered_condition_fails(void)
{
    /* covered_true_count=5, covered_false_count=0 → NOT MC/DC covered */
    write_mcdc_json("uncovered.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Bar\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":5,\"covered_false_count\":0}"
        "]}]}]}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/uncovered.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    /* Should fail: 0/1 conditions covered = 0% < threshold 100 */
    TEST_ASSERT_EQUAL(1, rc);
}

/* true_count=0, false_count>0 → NOT MC/DC covered */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_true_count_zero_fails(void)
{
    write_mcdc_json("tc_zero.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Baz\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":0,\"covered_false_count\":4}"
        "]}]}]}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/tc_zero.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

/* No mcdc_records in JSON → exit 0 (no records → pass) */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_no_records_passes(void)
{
    write_mcdc_json("no_records.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Qux\",\"mcdc_records\":[]}"
        "]}]}");

    char path[256];
    snprintf(path, sizeof(path), "%s/no_records.json", MCDC_TEST_DIR);
    char *argv[] = {"cfusa", "coverage",
                    "--mcdc-file", path, NULL};
    int rc = cmd_coverage(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* --mcdc-threshold below actual coverage → pass */
//cfusa:req REQ-COV015
//cfusa:test REQ-COV015
void test_mcdc_threshold_below_coverage_passes(void)
{
    /* 1 covered, 1 uncovered → 50% coverage */
    write_mcdc_json("mixed.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Mixed\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":3,\"covered_false_count\":2},"
        "{\"covered_true_count\":0,\"covered_false_count\":1}"
        "]}]}]}]}");

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
    /* 1 covered, 1 uncovered → 50% coverage */
    write_mcdc_json("mixed2.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Mixed\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":3,\"covered_false_count\":2},"
        "{\"covered_true_count\":0,\"covered_false_count\":1}"
        "]}]}]}]}");

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
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Foo\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":2,\"covered_false_count\":3}"
        "]}]}]}]}");

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
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "mcdcReport"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "totalConditions"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "coveragePct"));
        (void)remove("/tmp/cfusa_mcdc_out.json");
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mcdc_help_returns_zero);
    RUN_TEST(test_mcdc_all_covered_passes);
    RUN_TEST(test_mcdc_uncovered_condition_fails);
    RUN_TEST(test_mcdc_true_count_zero_fails);
    RUN_TEST(test_mcdc_no_records_passes);
    RUN_TEST(test_mcdc_threshold_below_coverage_passes);
    RUN_TEST(test_mcdc_threshold_above_coverage_fails);
    RUN_TEST(test_mcdc_json_output_has_mcdc_report);
    return UNITY_END();
}
