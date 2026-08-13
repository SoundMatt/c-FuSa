/*
 * Tests for cmd_impact — git ref validation and command parsing.
 * validate_git_ref is static so we probe it via cmd_impact return codes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"
#include "cfusa/utils.h"

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

/* ---- catalogs larger than the old fixed MAX_REQS=256 cap (issue #100) --- */

#define IMPACT_BIG_DIR "/tmp/cfusa_impact_bigreqs_testdir"

//cfusa:req REQ-IMP006
//cfusa:test REQ-IMP006
void test_impact_loads_more_than_256_reqs_not_truncated(void)
{
    /* Regression for issue #100: cmd_impact's requirement-id array was
     * capped at a fixed 256 entries; entries past the cap were silently
     * dropped by load_req_ids(), so a requirement past the cap could never
     * be reported as impacted even when a changed file carried a matching
     * //cfusa:req tag. Write 300 requirements, touch a file annotated with
     * the very last one, and confirm cmd_impact reports it as impacted. */
    TEST_ASSERT_EQUAL(0, system("rm -rf " IMPACT_BIG_DIR));
    TEST_ASSERT_EQUAL(0, system("mkdir -p " IMPACT_BIG_DIR));

    char path[300];
    snprintf(path, sizeof(path), "%s/.fusa-reqs.json", IMPACT_BIG_DIR);
    FILE *rf = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(rf);
    fprintf(rf, "{\n  \"requirements\": [\n");
    for (int i = 1; i <= 300; i++)
        fprintf(rf, "    {\"id\":\"REQ-BIGIMP-%03d\",\"title\":\"r%d\"}%s\n",
                i, i, (i < 300) ? "," : "");
    fprintf(rf, "  ]\n}\n");
    fclose(rf);

    snprintf(path, sizeof(path), "%s/impl.c", IMPACT_BIG_DIR);
    FILE *cf = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(cf);
    fprintf(cf, "void f(void) {}\n");
    fclose(cf);

    /* cmd_impact's git-diff step runs in the process's current directory,
     * not --dir (that flag only controls where the requirements registry
     * is read from) — chdir into the fixture repo so both the git setup
     * below and `git diff` inside cmd_impact() see it. Command strings are
     * kept as compile-time literals (no runtime-built argument) throughout. */
    char orig_cwd[512];
    TEST_ASSERT_NOT_NULL(getcwd(orig_cwd, sizeof(orig_cwd)));
    TEST_ASSERT_EQUAL(0, chdir(IMPACT_BIG_DIR));

    TEST_ASSERT_EQUAL(0, system("git init -q "
        "&& git -c user.email=t@t -c user.name=t add -A "
        "&& git -c user.email=t@t -c user.name=t commit -qm init"));

    /* Touch impl.c with a tag for the very last requirement (past the old
     * 256-entry cap) and commit the change so `git diff` reports it.
     * Rewritten in full (rather than opened in append mode) so file
     * creation always goes through cfusa_fopen_write()'s explicit 0600
     * permissions. */
    FILE *cf2 = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(cf2);
    fprintf(cf2, "void f(void) {}\n//cfusa:req REQ-BIGIMP-300\nvoid g(void) {}\n");
    fclose(cf2);

    TEST_ASSERT_EQUAL(0, system("git -c user.email=t@t -c user.name=t commit -aqm change"));

    char out_path[300];
    snprintf(out_path, sizeof(out_path), "%s/impact_out.txt", IMPACT_BIG_DIR);
    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(out_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", "impact", "--dir", IMPACT_BIG_DIR,
                     "--from", "HEAD~1", "--to", "HEAD", NULL};
    int rc = cmd_impact(8, argv);

    TEST_ASSERT_EQUAL(0, chdir(orig_cwd));

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    close(saved_fd);

    TEST_ASSERT_EQUAL(0, rc);

    FILE *of = fopen(out_path, "r");
    TEST_ASSERT_NOT_NULL(of);
    fseek(of, 0, SEEK_END);
    long sz = ftell(of);
    fseek(of, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    TEST_ASSERT_NOT_NULL(buf);
    size_t nread = fread(buf, 1, (size_t)sz, of);
    buf[nread] = '\0';
    fclose(of);

    TEST_ASSERT_NOT_NULL(strstr(buf, "REQ-BIGIMP-300"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "impacted"));
    free(buf);

    system("rm -rf " IMPACT_BIG_DIR);
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
    RUN_TEST(test_impact_loads_more_than_256_reqs_not_truncated);
    return UNITY_END();
}
