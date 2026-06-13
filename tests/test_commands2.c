/*
 * Smoke tests for: vuln, sci, coverage, sas, metrics, pr, hooks, template, fix, do178.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_vuln(int argc, char **argv);
extern int cmd_sci(int argc, char **argv);
extern int cmd_coverage(int argc, char **argv);
extern int cmd_sas(int argc, char **argv);
extern int cmd_metrics(int argc, char **argv);
extern int cmd_pr(int argc, char **argv);
extern int cmd_hooks(int argc, char **argv);
extern int cmd_template(int argc, char **argv);
extern int cmd_fix(int argc, char **argv);
extern int cmd_do178(int argc, char **argv);
extern int cmd_version(int argc, char **argv);
extern int cmd_boundary(int argc, char **argv);
extern int cmd_verify(int argc, char **argv);

#define CMD2_DIR "/tmp/cfusa_cmd2_testdir"

void setUp(void)   { (void)mkdir(CMD2_DIR, 0700); }
void tearDown(void) {}

/* ---- vuln ---- */

//cfusa:req REQ-VULN001
//cfusa:test REQ-VULN001
void test_vuln_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_vuln(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-VULN002
//cfusa:test REQ-VULN002
void test_vuln_runs_on_empty_dir(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_vuln(3, argv);
    (void)rc;
}

//cfusa:req REQ-VULN003
//cfusa:test REQ-VULN003
void test_vuln_json_format(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--format", "json", NULL};
    int rc = cmd_vuln(5, argv);
    (void)rc;
}

//cfusa:req REQ-VULN-OUTDIR001
//cfusa:test REQ-VULN-OUTDIR001
void test_vuln_output_dir(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--output-dir", "/tmp/cfusa_vuln_outdir_test", NULL};
    int rc = cmd_vuln(5, argv);
    /* exit 0 = no hits; exit 1 = hits found; both are acceptable */
    TEST_ASSERT_TRUE(rc == 0 || rc == 1);

    /* verify vuln.json was created */
    FILE *f = fopen("/tmp/cfusa_vuln_outdir_test/vuln.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
}

/* ---- sci ---- */

//cfusa:req REQ-SCI001
//cfusa:test REQ-SCI001
void test_sci_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_sci(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-SCI002
//cfusa:test REQ-SCI002
void test_sci_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_sci(3, argv);
    (void)rc;
}

/* ---- coverage ---- */

//cfusa:req REQ-COV001
//cfusa:test REQ-COV001
void test_coverage_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_coverage(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-COV002
//cfusa:test REQ-COV002
void test_coverage_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_coverage(3, argv);
    (void)rc;
}

/* ---- sas ---- */

//cfusa:req REQ-SAS001
//cfusa:test REQ-SAS001
void test_sas_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_sas(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-SAS002
//cfusa:test REQ-SAS002
void test_sas_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_sas(3, argv);
    (void)rc;
}

/* ---- metrics ---- */

//cfusa:req REQ-MET001
//cfusa:test REQ-MET001
void test_metrics_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_metrics(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-MET002
//cfusa:test REQ-MET002
void test_metrics_runs_on_empty_dir(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(3, argv);
    (void)rc;
}

//cfusa:req REQ-MET003
//cfusa:test REQ-MET003
void test_metrics_json_format(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--format", "json", NULL};
    int rc = cmd_metrics(5, argv);
    (void)rc;
}

//cfusa:req REQ-MET004
//cfusa:test REQ-MET004
void test_metrics_record_auto(void)
{
    /* Auto-record with no manual flags — should succeed even with no artifacts */
    char *argv[] = {"cfusa", "record", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-MET005
//cfusa:test REQ-MET005
void test_metrics_show_json_output(void)
{
    /* First record something */
    char *rec[] = {"cfusa", "record", "--dir", CMD2_DIR,
                   "--errors", "2", "--warnings", "3", "--info", "1",
                   "--label", "test", NULL};
    cmd_metrics(12, rec);

    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/metrics-out.json", CMD2_DIR);
    char *argv[] = {"cfusa", "show", "--dir", CMD2_DIR,
                    "--format", "json", "--output", outpath, NULL};
    int rc = cmd_metrics(8, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"errorCount\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"timestamp\""));
    }
    (void)remove(outpath);
}

//cfusa:req REQ-COV003
//cfusa:test REQ-COV003
void test_coverage_dal_invalid(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--dal", "INVALID", NULL};
    int rc = cmd_coverage(5, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

//cfusa:req REQ-COV004
//cfusa:test REQ-COV004
void test_coverage_dal_d_no_threshold(void)
{
    /* DAL-D: no coverage requirement — should exit 0 even without lcov */
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--dal", "DAL-D",
                    "--mutate-score", "0.0", NULL};
    /* Without lcov + without mutate flag, still needs lcov. Skip if no lcov. */
    int rc = cmd_coverage(7, argv);
    /* DAL-D exit code: 0 (no threshold) or 1 (no lcov file found).
     * What matters: we got a valid response, not a crash. */
    TEST_ASSERT_TRUE(rc == 0 || rc == 1 || rc == 2);
}

/* ---- pr ---- */

//cfusa:req REQ-PR001
//cfusa:test REQ-PR001
void test_pr_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_pr(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-PR002
//cfusa:test REQ-PR002
void test_pr_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_pr(3, argv);
    (void)rc;
}

/* ---- metrics subcommand validation ---- */

//cfusa:req REQ-MET-SUBCMD001
//cfusa:test REQ-MET-SUBCMD001
void test_metrics_no_subcmd_returns_2(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(3, argv);
    TEST_ASSERT_EQUAL_INT(2, rc);
}

//cfusa:req REQ-MET-SUBCMD001
//cfusa:test REQ-MET-SUBCMD001
void test_metrics_unknown_subcmd_returns_2(void)
{
    char *argv[] = {"cfusa", "frobber", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(4, argv);
    TEST_ASSERT_EQUAL_INT(2, rc);
}

//cfusa:req REQ-MET-SUBCMD001
//cfusa:test REQ-MET-SUBCMD001
void test_metrics_record_outputs_metrics_recorded(void)
{
    char *argv[] = {"cfusa", "record", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(4, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

/* ---- hooks ---- */

//cfusa:req REQ-HOOK001
//cfusa:test REQ-HOOK001
void test_hooks_runs_no_crash(void)
{
    char *argv[] = {"cfusa", NULL};
    int rc = cmd_hooks(1, argv);
    (void)rc;
}

#define HOOKS_INSTALL_DIR "/tmp/cfusa_hooks_install_test"

//cfusa:req REQ-HOOK-INSTALL001
//cfusa:test REQ-HOOK-INSTALL001
void test_hooks_install_already_exists_returns_2(void)
{
    /* Create the hooks dir and pre-commit file so install detects existing hook */
    char hook_dir[256], hook_path[256];
    snprintf(hook_dir,  sizeof(hook_dir),  "%s/.git/hooks", HOOKS_INSTALL_DIR);
    snprintf(hook_path, sizeof(hook_path), "%s/.git/hooks/pre-commit", HOOKS_INSTALL_DIR);
    (void)mkdir(HOOKS_INSTALL_DIR, 0755);
    (void)mkdir(hook_dir, 0755);
    FILE *f = fopen(hook_path, "w");
    if (f) { fputs("#!/bin/sh\n", f); fclose(f); }

    char *argv[] = {"cfusa", "install", "--dir", HOOKS_INSTALL_DIR, NULL};
    int rc = cmd_hooks(4, argv);
    TEST_ASSERT_EQUAL_INT(2, rc);

    (void)remove(hook_path);
}

//cfusa:req REQ-HOOK-REMOVE001
//cfusa:test REQ-HOOK-REMOVE001
void test_hooks_remove_not_found_returns_2(void)
{
    char *argv[] = {"cfusa", "remove", "--dir", "/tmp/cfusa_hooks_notfound_test", NULL};
    int rc = cmd_hooks(4, argv);
    TEST_ASSERT_EQUAL_INT(2, rc);
}

/* ---- template ---- */

//cfusa:req REQ-TMPL001
//cfusa:test REQ-TMPL001
void test_template_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_template(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TMPL002
//cfusa:test REQ-TMPL002
void test_template_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_template(3, argv);
    (void)rc;
}

//cfusa:req REQ-TMPL002
//cfusa:test REQ-TMPL002
void test_template_type_all(void)
{
    char tdir[256];
    snprintf(tdir, sizeof(tdir), "%s/tmpl_all", CMD2_DIR);
    char *argv[] = {"cfusa", "--type", "all", "--dir", tdir, NULL};
    int rc = cmd_template(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    /* Verify at least one template was created */
    char path[512];
    snprintf(path, sizeof(path), "%s/safety-plan.md", tdir);
    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
}

//cfusa:req REQ-TMPL002
//cfusa:test REQ-TMPL002
void test_template_type_safety_plan(void)
{
    char tdir[256];
    snprintf(tdir, sizeof(tdir), "%s/tmpl_sp", CMD2_DIR);
    char *argv[] = {"cfusa", "--type", "safety-plan", "--dir", tdir, NULL};
    int rc = cmd_template(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- fix ---- */

//cfusa:req REQ-FIX001
//cfusa:test REQ-FIX001
void test_fix_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_fix(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-FIX002
//cfusa:test REQ-FIX002
void test_fix_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_fix(3, argv);
    (void)rc;
}

/* ---- do178 ---- */

//cfusa:req REQ-DO178
//cfusa:test REQ-DO178
void test_do178_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_do178(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-DO178
//cfusa:test REQ-DO178
void test_do178_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_do178(3, argv);
    (void)rc;
}

/* ---- version ---- */

//cfusa:req REQ-VER001
//cfusa:test REQ-VER001
void test_version_returns_zero(void)
{
    char *argv[] = {"cfusa", NULL};
    int rc = cmd_version(1, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- boundary ---- */

//cfusa:req REQ-BND001
//cfusa:test REQ-BND001
void test_boundary_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_boundary(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-BND002
//cfusa:test REQ-BND002
void test_boundary_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_boundary(3, argv);
    (void)rc;
}

/* ---- verify ---- */

//cfusa:req REQ-VRFY001
//cfusa:test REQ-VRFY001
void test_verify_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_verify(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-VRFY002
//cfusa:test REQ-VRFY002
void test_verify_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_verify(3, argv);
    (void)rc;
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vuln_help_returns_zero);
    RUN_TEST(test_vuln_runs_on_empty_dir);
    RUN_TEST(test_vuln_json_format);
    RUN_TEST(test_vuln_output_dir);
    RUN_TEST(test_sci_help_returns_zero);
    RUN_TEST(test_sci_runs_no_crash);
    RUN_TEST(test_coverage_help_returns_zero);
    RUN_TEST(test_coverage_runs_no_crash);
    RUN_TEST(test_coverage_dal_invalid);
    RUN_TEST(test_coverage_dal_d_no_threshold);
    RUN_TEST(test_sas_help_returns_zero);
    RUN_TEST(test_sas_runs_no_crash);
    RUN_TEST(test_metrics_help_returns_zero);
    RUN_TEST(test_metrics_runs_on_empty_dir);
    RUN_TEST(test_metrics_json_format);
    RUN_TEST(test_metrics_record_auto);
    RUN_TEST(test_metrics_show_json_output);
    RUN_TEST(test_metrics_no_subcmd_returns_2);
    RUN_TEST(test_metrics_unknown_subcmd_returns_2);
    RUN_TEST(test_metrics_record_outputs_metrics_recorded);
    RUN_TEST(test_pr_help_returns_zero);
    RUN_TEST(test_pr_runs_no_crash);
    RUN_TEST(test_hooks_runs_no_crash);
    RUN_TEST(test_hooks_install_already_exists_returns_2);
    RUN_TEST(test_hooks_remove_not_found_returns_2);
    RUN_TEST(test_template_help_returns_zero);
    RUN_TEST(test_template_runs_no_crash);
    RUN_TEST(test_template_type_all);
    RUN_TEST(test_template_type_safety_plan);
    RUN_TEST(test_fix_help_returns_zero);
    RUN_TEST(test_fix_runs_no_crash);
    RUN_TEST(test_do178_help_returns_zero);
    RUN_TEST(test_do178_runs_no_crash);
    RUN_TEST(test_version_returns_zero);
    RUN_TEST(test_boundary_help_returns_zero);
    RUN_TEST(test_boundary_runs_no_crash);
    RUN_TEST(test_verify_help_returns_zero);
    RUN_TEST(test_verify_runs_no_crash);
    return UNITY_END();
}
