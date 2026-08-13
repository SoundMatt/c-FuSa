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
    fclose(f);
}

static void write_mcdc(const char *fname, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", COVA_DIR, fname);
    FILE *f = cfusa_fopen_write(path);
    if (!f) return;
    fputs(content, f);
    fclose(f);
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
    write_mcdc("half.json",
        "{\"data\":[{\"functions\":["
        "{\"name\":\"Foo\",\"mcdc_records\":[{\"conditions\":["
        "{\"covered_true_count\":3,\"covered_false_count\":2},"
        "{\"covered_true_count\":0,\"covered_false_count\":1}"
        "]}]}]}]}");
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
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"asil\": \"ASIL-B\""));
        (void)remove(out);
    }
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
    return UNITY_END();
}
