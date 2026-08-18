/*
 * Tests for `cfusa explain <RULE-ID>` (issue #212).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"

extern int cmd_explain(int argc, char **argv);

void setUp(void)   {}
void tearDown(void) {}

/* Runs cmd_explain(argc, argv), capturing stdout into `buf` (NUL-
 * terminated). Mirrors the redirect pattern used throughout
 * tests/test_commands2.c. */
static int run_capture(int argc, char **argv, char *buf, size_t bufcap)
{
    char capture_path[] = "/tmp/cfusa_explain_test_stdout.XXXXXX";
    int fd = mkstemp(capture_path);
    TEST_ASSERT_TRUE(fd >= 0);
    if (fd >= 0) close(fd);

    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(capture_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    int rc = cmd_explain(argc, argv);

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    close(saved_fd);

    buf[0] = '\0';
    FILE *f = fopen(capture_path, "r");
    if (f) {
        size_t n = fread(buf, 1, bufcap - 1, f);
        buf[n] = '\0';
        fclose(f);
    }
    remove(capture_path);
    return rc;
}

//cfusa:req REQ-EXPLAIN001
//cfusa:test REQ-EXPLAIN001
void test_explain_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    char buf[4096];
    int rc = run_capture(2, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(strstr(buf, "Usage: cfusa explain"));
}

//cfusa:req REQ-EXPLAIN002
//cfusa:test REQ-EXPLAIN002
void test_explain_missing_arg_returns_2(void)
{
    char *argv[] = {"cfusa", NULL};
    char buf[256];
    int rc = run_capture(1, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(2, rc);
}

//cfusa:req REQ-EXPLAIN002
//cfusa:test REQ-EXPLAIN002
void test_explain_unknown_rule_returns_1(void)
{
    char *argv[] = {"cfusa", "CFUSA-NOPE999", NULL};
    char buf[256];
    int rc = run_capture(2, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(1, rc);
}

//cfusa:req REQ-EXPLAIN001
//cfusa:test REQ-EXPLAIN001
void test_explain_known_rule_prints_description_standard_and_fix(void)
{
    char *argv[] = {"cfusa", "CFUSA-CY006", NULL};
    char buf[4096];
    int rc = run_capture(2, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-CY006"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "cert-c"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "MEM30-C"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "Fix:"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "Null the pointer immediately after free"));
}

/* issue #212's whole point: a human at a shell prompt shouldn't need the
 * exact "CFUSA-" prefix or casing. */
//cfusa:req REQ-EXPLAIN003
//cfusa:test REQ-EXPLAIN003
void test_explain_case_and_prefix_insensitive_lookup(void)
{
    char *argv[] = {"cfusa", "cy006", NULL};
    char buf[4096];
    int rc = run_capture(2, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-CY006"));
}

//cfusa:req REQ-EXPLAIN001
//cfusa:test REQ-EXPLAIN001
void test_explain_rule_without_fix_guidance_says_so(void)
{
    /* COMP001 (cyclomatic complexity) has no FIXES[] entry -- it needs
     * judgment, not a mechanical fix (cmd_fix.c's own doc comment on
     * L001 makes the same point). */
    char *argv[] = {"cfusa", "COMP001", NULL};
    char buf[4096];
    int rc = run_capture(2, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(strstr(buf, "COMP001"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "No automated remediation guidance"));
}

//cfusa:req REQ-EXPLAIN001
//cfusa:test REQ-EXPLAIN001
void test_explain_list_prints_every_category(void)
{
    char *argv[] = {"cfusa", "--list", NULL};
    char buf[16384];
    int rc = run_capture(2, argv, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-L001"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-A001"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-CY001"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "lint:"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "cyber:"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_explain_help_returns_zero);
    RUN_TEST(test_explain_missing_arg_returns_2);
    RUN_TEST(test_explain_unknown_rule_returns_1);
    RUN_TEST(test_explain_known_rule_prints_description_standard_and_fix);
    RUN_TEST(test_explain_case_and_prefix_insensitive_lookup);
    RUN_TEST(test_explain_rule_without_fix_guidance_says_so);
    RUN_TEST(test_explain_list_prints_every_category);
    return UNITY_END();
}
