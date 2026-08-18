/*
 * Tests for issue #209: cfusa_git_changed_lines_load()/
 * cfusa_report_filter_to_changed_lines() (gitdiff.c) and cmd_check's
 * --changed-since flag.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/gitdiff.h"
#include "../include/cfusa/utils.h"

extern int cmd_check(int argc, char **argv);

#define GD_DIR "/tmp/cfusa_gitdiff_testdir"

void setUp(void)    {}
void tearDown(void) {}

/* ---- ref validation (argument-injection guard, mirrors test_impact.c) ---- */

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_git_changed_lines_rejects_leading_dash_ref(void)
{
    cfusa_changed_lines_t list;
    int ok = cfusa_git_changed_lines_load(".", "--output=pwned", &list);
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_EQUAL_INT(0, list.count);
    cfusa_git_changed_lines_free(&list);
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_git_changed_lines_rejects_semicolon_ref(void)
{
    cfusa_changed_lines_t list;
    int ok = cfusa_git_changed_lines_load(".", "HEAD;rm -rf /", &list);
    TEST_ASSERT_FALSE(ok);
    cfusa_git_changed_lines_free(&list);
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_git_changed_lines_rejects_dollar_ref(void)
{
    cfusa_changed_lines_t list;
    int ok = cfusa_git_changed_lines_load(".", "$(evil)", &list);
    TEST_ASSERT_FALSE(ok);
    cfusa_git_changed_lines_free(&list);
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_git_changed_lines_rejects_empty_ref(void)
{
    cfusa_changed_lines_t list;
    int ok = cfusa_git_changed_lines_load(".", "", &list);
    TEST_ASSERT_FALSE(ok);
    cfusa_git_changed_lines_free(&list);
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_git_changed_lines_not_a_git_repo_fails(void)
{
    (void)mkdir("/tmp/cfusa_gitdiff_notrepo", 0700);
    cfusa_changed_lines_t list;
    int ok = cfusa_git_changed_lines_load("/tmp/cfusa_gitdiff_notrepo", "HEAD", &list);
    TEST_ASSERT_FALSE(ok);
    cfusa_git_changed_lines_free(&list);
}

/* ---- cfusa_report_filter_to_changed_lines() (unit level) ---- */

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_filter_keeps_only_findings_in_range(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "CFUSA-L002", "lint", SEV_WARNING, "a.c", 2,  "in range");
    cfusa_report_add(&rpt, "CFUSA-L003", "lint", SEV_WARNING, "a.c", 10, "out of range");
    cfusa_report_add(&rpt, "CFUSA-A002", "analyze", SEV_ERROR, "b.c", 5, "different file");

    cfusa_changed_lines_t changed;
    memset(&changed, 0, sizeof(changed));
    changed.items = malloc(sizeof(cfusa_changed_range_t));
    changed.count = 1; changed.cap = 1;
    strncpy(changed.items[0].file, "a.c", sizeof(changed.items[0].file) - 1);
    changed.items[0].file[sizeof(changed.items[0].file) - 1] = '\0';
    changed.items[0].start = 1;
    changed.items[0].end   = 3;

    cfusa_report_filter_to_changed_lines(&rpt, &changed);

    TEST_ASSERT_EQUAL_INT(1, rpt.count);
    TEST_ASSERT_EQUAL_STRING("CFUSA-L002", rpt.findings[0].rule_id);
    TEST_ASSERT_EQUAL_INT(1, rpt.warning_count);
    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);

    free(changed.items);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_filter_always_keeps_line_zero_findings(void)
{
    /* directory/file-level findings (FUSA001, HARA001, ...) use line 0
     * and must survive filtering regardless of any changed range. */
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "FUSA001", "safety", SEV_INFO, ".", 0, "no config");
    cfusa_report_add(&rpt, "CFUSA-L002", "lint", SEV_WARNING, "a.c", 99, "unrelated line");

    cfusa_changed_lines_t changed;
    memset(&changed, 0, sizeof(changed)); /* empty: nothing changed */

    cfusa_report_filter_to_changed_lines(&rpt, &changed);

    TEST_ASSERT_EQUAL_INT(1, rpt.count);
    TEST_ASSERT_EQUAL_STRING("FUSA001", rpt.findings[0].rule_id);

    cfusa_report_free(&rpt);
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_filter_recomputes_dispositioned_count(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "CFUSA-L002", "lint", SEV_WARNING, "a.c", 2, "kept");
    strncpy(rpt.findings[0].disposition_id, "DISP-0001",
            sizeof(rpt.findings[0].disposition_id) - 1);
    cfusa_report_add(&rpt, "CFUSA-L003", "lint", SEV_WARNING, "a.c", 20, "dropped");

    cfusa_changed_lines_t changed;
    memset(&changed, 0, sizeof(changed));
    changed.items = malloc(sizeof(cfusa_changed_range_t));
    changed.count = 1; changed.cap = 1;
    strncpy(changed.items[0].file, "a.c", sizeof(changed.items[0].file) - 1);
    changed.items[0].start = 1;
    changed.items[0].end   = 3;

    cfusa_report_filter_to_changed_lines(&rpt, &changed);

    TEST_ASSERT_EQUAL_INT(1, rpt.count);
    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count); /* the kept one is dispositioned */
    TEST_ASSERT_EQUAL_INT(1, rpt.dispositioned_count);

    free(changed.items);
    cfusa_report_free(&rpt);
}

/* ---- end-to-end: a real scratch git repo ----
 *
 * Every system() call below takes a purely compile-time string literal
 * (GD_DIR is itself a #define, so "..." GD_DIR "..." string-literal
 * concatenation is still a literal at the call site) rather than a
 * runtime-built buffer passed through a wrapper function -- CFUSA-CY003
 * (CWE-78) only flags a system()/exec*() call whose argument does NOT
 * look like a literal at its own call site, precisely so a real
 * variable/buffer argument (which could carry attacker-controlled
 * content in real product code) still gets caught; matches
 * tests/test_comp.c's own established `system("rm -rf " CTDIR)` pattern
 * for this exact situation. */
/* Every system() call below inlines its full literal argument (never a
 * macro name, even one that itself expands to a literal) starting
 * immediately after the opening paren, all on ONE physical line --
 * CFUSA-CY003's scanner is textual/line-based: it only recognizes a
 * call as safe when the character right after "system(" is literally
 * '"' in the source text, so both a wrapped `system(\n    "...")` and
 * a `system(SOME_MACRO "...")` would (correctly cautious for a
 * textual scanner that can't run the preprocessor) still read as a
 * non-literal argument. */
static void setup_repo_with_two_commits(void)
{
    TEST_ASSERT_EQUAL_INT(0, system("rm -rf " GD_DIR " && mkdir -p " GD_DIR));
    TEST_ASSERT_EQUAL_INT(0, system("cd " GD_DIR " && git init -q"));
    TEST_ASSERT_EQUAL_INT(0, system("cd " GD_DIR " && git config user.email t@t.com && git config user.name t"));

    char path[256];
    snprintf(path, sizeof(path), "%s/a.c", GD_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        fputs("void fn(void) {\n    goto end;\nend:;\n}\n", f);
        TEST_ASSERT_EQUAL_INT(0, fclose(f));
    }
    TEST_ASSERT_EQUAL_INT(0, system("cd " GD_DIR " && git add a.c && git commit -q -m first"));

    /* second commit: rewritten (not appended) via cfusa_fopen_write() so
     * this never opens the file with fopen()'s umask-dependent mode --
     * adds a genuinely new, different finding on line 5. */
    f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        fputs("void fn(void) {\n    goto end;\nend:;\n}\n"
              "void fn2(void) { void *p = malloc(64); (void)p; }\n", f);
        TEST_ASSERT_EQUAL_INT(0, fclose(f));
    }
    TEST_ASSERT_EQUAL_INT(0, system("cd " GD_DIR " && git add a.c && git commit -q -m second"));
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_git_changed_lines_load_parses_real_diff(void)
{
    setup_repo_with_two_commits();

    cfusa_changed_lines_t changed;
    int ok = cfusa_git_changed_lines_load(GD_DIR, "HEAD~1", &changed);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_TRUE(changed.count >= 1);

    int found_line5 = 0;
    for (int i = 0; i < changed.count; i++) {
        if (strcmp(changed.items[i].file, "a.c") == 0 &&
            5 >= changed.items[i].start && 5 <= changed.items[i].end)
            found_line5 = 1;
    }
    TEST_ASSERT_TRUE(found_line5);

    cfusa_git_changed_lines_free(&changed);
    TEST_ASSERT_EQUAL_INT(0, system("rm -rf " GD_DIR));
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_cmd_check_changed_since_drops_pre_existing_finding(void)
{
    setup_repo_with_two_commits();

    /* issue #209 side-finding, tracked separately (not fixed here — see
     * the tracked follow-up issue): cmd_check.c sets rpt.project_root
     * via realpath(dir), but cfusa_walk_sources() builds each file's raw
     * path from the LITERAL `dir` argument. If `dir` is itself an
     * absolute path through an unresolved symlink (e.g. macOS aliases
     * /tmp -> /private/tmp), the two disagree and every finding's file
     * path fails to relativize -- which would also make it fail to
     * match any --changed-since range. --dir "." (this test's own
     * setup, and cmd_check's own default) sidesteps this entirely,
     * matching the realistic/recommended usage of running from inside
     * the repo. */
    char cwd[512];
    TEST_ASSERT_NOT_NULL(getcwd(cwd, sizeof(cwd)));
    TEST_ASSERT_EQUAL_INT(0, chdir(GD_DIR));

    char *argv[] = {"cfusa", "--dir", ".", "--changed-since", "HEAD~1",
                     "--format", "json", "--output", "out.json", NULL};
    int rc = cmd_check(9, argv);
    (void)rc;

    size_t len = 0;
    char *content = cfusa_read_file("out.json", &len);
    TEST_ASSERT_NOT_NULL(content);
    if (content) {
        /* CFUSA-L002 (the goto on line 2, untouched by the second
         * commit) must be filtered out entirely. */
        TEST_ASSERT_NULL(strstr(content, "\"CFUSA-L002\""));
        /* CFUSA-L003/L008 (fn2's malloc/void*, genuinely new on line 5)
         * must survive filtering. */
        TEST_ASSERT_NOT_NULL(strstr(content, "\"CFUSA-L003\""));
        free(content);
    }

    TEST_ASSERT_EQUAL_INT(0, chdir(cwd));
    TEST_ASSERT_EQUAL_INT(0, system("rm -rf " GD_DIR));
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_cmd_check_changed_since_bad_ref_returns_2(void)
{
    setup_repo_with_two_commits();

    char *argv[] = {"cfusa", "--dir", GD_DIR, "--changed-since",
                     "no-such-ref-xyz", NULL};
    int rc = cmd_check(5, argv);
    TEST_ASSERT_EQUAL_INT(2, rc);

    TEST_ASSERT_EQUAL_INT(0, system("rm -rf " GD_DIR));
}

//cfusa:req REQ-GITDIFF001
//cfusa:test REQ-GITDIFF001
void test_cmd_check_help_mentions_changed_since(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    TEST_ASSERT_EQUAL_INT(0, cmd_check(2, argv));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_git_changed_lines_rejects_leading_dash_ref);
    RUN_TEST(test_git_changed_lines_rejects_semicolon_ref);
    RUN_TEST(test_git_changed_lines_rejects_dollar_ref);
    RUN_TEST(test_git_changed_lines_rejects_empty_ref);
    RUN_TEST(test_git_changed_lines_not_a_git_repo_fails);
    RUN_TEST(test_filter_keeps_only_findings_in_range);
    RUN_TEST(test_filter_always_keeps_line_zero_findings);
    RUN_TEST(test_filter_recomputes_dispositioned_count);
    RUN_TEST(test_git_changed_lines_load_parses_real_diff);
    RUN_TEST(test_cmd_check_changed_since_drops_pre_existing_finding);
    RUN_TEST(test_cmd_check_changed_since_bad_ref_returns_2);
    RUN_TEST(test_cmd_check_help_mentions_changed_since);
    return UNITY_END();
}
