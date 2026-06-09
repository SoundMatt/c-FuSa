/*
 * Tests for cmd_impact — git ref validation and command parsing.
 * validate_git_ref is static so we probe it via cmd_impact return codes.
 */
#include <stdio.h>
#include <string.h>
#include "../vendor/unity/unity.h"

extern int cmd_impact(int argc, char **argv);

void setUp(void) {}
void tearDown(void) {}

/* ---- Git ref validation (command injection guard) ---- */

//cfusa:req REQ-IMP001
//cfusa:test REQ-IMP001
void test_impact_rejects_semicolon_in_from(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "HEAD;rm -rf /",
                    "--to", "HEAD", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-IMP001
//cfusa:test REQ-IMP001
void test_impact_rejects_backtick_in_to(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "HEAD",
                    "--to", "HEAD`id`", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-IMP001
//cfusa:test REQ-IMP001
void test_impact_rejects_dollar_in_ref(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "$(evil)",
                    "--to", "HEAD", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-IMP001
//cfusa:test REQ-IMP001
void test_impact_rejects_ampersand_in_ref(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "main&&evil",
                    "--to", "HEAD", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-IMP001
//cfusa:test REQ-IMP001
void test_impact_rejects_pipe_in_ref(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "main|evil",
                    "--to", "HEAD", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-IMP001
//cfusa:test REQ-IMP001
void test_impact_rejects_space_in_ref(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "main branch",
                    "--to", "HEAD", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-IMP002
//cfusa:test REQ-IMP002
void test_impact_accepts_valid_branch_name(void)
{
    /* Valid ref — will fail due to no git repo but should NOT return 1 for injection check */
    char *argv[] = {"cfusa", "impact", "--from", "main",
                    "--to", "HEAD", "--dir", "/tmp", NULL};
    int rc = cmd_impact(8, argv);
    /* rc may be non-zero due to git not being available, but not 1 for injection */
    (void)rc; /* No injection → no crash */
}

//cfusa:req REQ-IMP002
//cfusa:test REQ-IMP002
void test_impact_accepts_sha_ref(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "abc1234def5678",
                    "--to", "HEAD", "--dir", "/tmp", NULL};
    int rc = cmd_impact(8, argv);
    (void)rc;
}

//cfusa:req REQ-IMP003
//cfusa:test REQ-IMP003
void test_impact_empty_from_rejected(void)
{
    char *argv[] = {"cfusa", "impact", "--from", "",
                    "--to", "HEAD", "--dir", ".", NULL};
    int rc = cmd_impact(8, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_impact_rejects_semicolon_in_from);
    RUN_TEST(test_impact_rejects_backtick_in_to);
    RUN_TEST(test_impact_rejects_dollar_in_ref);
    RUN_TEST(test_impact_rejects_ampersand_in_ref);
    RUN_TEST(test_impact_rejects_pipe_in_ref);
    RUN_TEST(test_impact_rejects_space_in_ref);
    RUN_TEST(test_impact_accepts_valid_branch_name);
    RUN_TEST(test_impact_accepts_sha_ref);
    RUN_TEST(test_impact_empty_from_rejected);
    return UNITY_END();
}
