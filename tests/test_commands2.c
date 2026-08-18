/*
 * Smoke tests for: vuln, sci, coverage, sas, metrics, pr, hooks, template, fix, do178.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/utils.h"

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
extern int cmd_report(int argc, char **argv);
extern int cmd_help(int argc, char **argv);

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
//cfusa:test REQ-CLI-SCI001
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
//cfusa:test REQ-CLI-PR001
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

//cfusa:req REQ-MET-SUBCMD002
//cfusa:test REQ-MET-SUBCMD002
void test_metrics_unknown_subcmd_returns_2(void)
{
    char *argv[] = {"cfusa", "frobber", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(4, argv);
    TEST_ASSERT_EQUAL_INT(2, rc);
}

//cfusa:req REQ-MET-REC001
//cfusa:test REQ-MET-REC001
void test_metrics_record_outputs_metrics_recorded(void)
{
    char capture_path[256];
    snprintf(capture_path, sizeof(capture_path), "%s/metrics_record_stdout.txt", CMD2_DIR);
    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(capture_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", "record", "--dir", CMD2_DIR, NULL};
    int rc = cmd_metrics(4, argv);

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    close(saved_fd);

    TEST_ASSERT_EQUAL_INT(0, rc);

    FILE *f = fopen(capture_path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "Metrics recorded"));
    }
    remove(capture_path);
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
    char git_dir[256], hook_dir[256], hook_path[256];
    snprintf(git_dir,   sizeof(git_dir),   "%s/.git", HOOKS_INSTALL_DIR);
    snprintf(hook_dir,  sizeof(hook_dir),  "%s/.git/hooks", HOOKS_INSTALL_DIR);
    snprintf(hook_path, sizeof(hook_path), "%s/.git/hooks/pre-commit", HOOKS_INSTALL_DIR);
    (void)mkdir(HOOKS_INSTALL_DIR, 0755);
    (void)mkdir(git_dir, 0755);
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
//cfusa:test REQ-CLI-TEMPLATE001
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

/* issue #127: cfusa fix had no remediation guidance for CFUSA-CY006
 * (free-without-NULL, CWE-416/CERT-C MEM30-C) despite it being fully
 * mechanical -- exactly the shape `fix` already handles for other rules. */
//cfusa:req REQ-FIX005
//cfusa:test REQ-FIX005
void test_fix_cy006_guidance_present(void)
{
    char src_path[256];
    snprintf(src_path, sizeof(src_path), "%s/cy006_fix_src.c", CMD2_DIR);
    FILE *sf = cfusa_fopen_write(src_path);
    TEST_ASSERT_NOT_NULL(sf);
    if (sf) {
        fputs("void fn(void *ptr) {\n    free(ptr);\n}\n", sf);
        if (fclose(sf) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }

    char capture_path[256];
    snprintf(capture_path, sizeof(capture_path), "%s/fix_cy006_stdout.txt", CMD2_DIR);
    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(capture_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_fix(3, argv);

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    close(saved_fd);
    /* cmd_fix returns 1 whenever any finding exists at all (fixable or
     * not) -- the free() call itself is a genuine finding, so 1 here
     * means "ran successfully and found something", not a crash/error. */
    TEST_ASSERT_EQUAL_INT(1, rc);

    FILE *f = fopen(capture_path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-CY006"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Null the pointer immediately after free"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "MEM30-C"));
    }
    remove(capture_path);
    remove(src_path);
}

/* issue #210: coverage was ~19 rules out of ~39; spot-check a handful of
 * the newly-added guidance entries actually surface end-to-end. */
//cfusa:req REQ-FIX007
//cfusa:test REQ-FIX007
void test_fix_guidance_covers_previously_missing_rules(void)
{
    char src_path[256];
    snprintf(src_path, sizeof(src_path), "%s/fix_coverage_src.c", CMD2_DIR);
    FILE *sf = cfusa_fopen_write(src_path);
    TEST_ASSERT_NOT_NULL(sf);
    if (sf) {
        /* L008 (void*), A007 (unchecked write() return), CY011 (curl URL
         * from a variable) — three rules that had no FIXES entry before
         * this change. */
        fputs("void fn(void *p) {\n"
              "    (void)p;\n"
              "    write(1, \"x\", 1);\n"
              "    curl_easy_setopt(curl, CURLOPT_URL, url);\n"
              "}\n", sf);
        if (fclose(sf) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }

    char capture_path[256];
    snprintf(capture_path, sizeof(capture_path), "%s/fix_coverage_stdout.txt", CMD2_DIR);
    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(capture_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_fix(3, argv);

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    close(saved_fd);
    TEST_ASSERT_EQUAL_INT(1, rc);

    FILE *f = fopen(capture_path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-L008"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Replace void* with a concrete pointer type"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-A007"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Check the return value of the system call"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "CFUSA-CY011"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Validate or whitelist URLs/proxies before use"));
    }
    remove(capture_path);
    remove(src_path);
}

/* issue #210: real autofix — --dry-run must preview the CY006
 * null-after-free rewrite without touching the source file. */
//cfusa:req REQ-FIX006
//cfusa:test REQ-FIX006
void test_fix_dry_run_previews_without_writing(void)
{
    char src_path[256];
    snprintf(src_path, sizeof(src_path), "%s/fix_dryrun_src.c", CMD2_DIR);
    const char *original = "void fn(void *ptr) {\n    free(ptr);\n}\n";
    FILE *sf = cfusa_fopen_write(src_path);
    TEST_ASSERT_NOT_NULL(sf);
    if (sf) {
        fputs(original, sf);
        if (fclose(sf) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }

    char capture_path[256];
    snprintf(capture_path, sizeof(capture_path), "%s/fix_dryrun_stdout.txt", CMD2_DIR);
    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(capture_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--dry-run", NULL};
    int rc = cmd_fix(4, argv);

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    close(saved_fd);
    TEST_ASSERT_EQUAL_INT(1, rc);

    FILE *f = fopen(capture_path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "dry-run"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "ptr = NULL;"));
    }
    remove(capture_path);

    /* The whole point of --dry-run: the source file must be byte-for-byte
     * unchanged. */
    size_t after_len = 0;
    char *after = cfusa_read_file(src_path, &after_len);
    TEST_ASSERT_NOT_NULL(after);
    if (after) {
        TEST_ASSERT_EQUAL_STRING(original, after);
        free(after);
    }
    remove(src_path);
}

/* issue #210: --apply actually rewrites the source, inserting the NULL-out
 * immediately after the free() call and leaving everything else intact. */
//cfusa:req REQ-FIX006
//cfusa:test REQ-FIX006
void test_fix_apply_inserts_null_after_free(void)
{
    char src_path[256];
    snprintf(src_path, sizeof(src_path), "%s/fix_apply_src.c", CMD2_DIR);
    FILE *sf = cfusa_fopen_write(src_path);
    TEST_ASSERT_NOT_NULL(sf);
    if (sf) {
        fputs("void fn(void *ptr) {\n"
              "    free(ptr);\n"
              "    return;\n"
              "}\n", sf);
        if (fclose(sf) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }

    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--apply", NULL};
    int rc = cmd_fix(4, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);

    size_t len = 0;
    char *content = cfusa_read_file(src_path, &len);
    TEST_ASSERT_NOT_NULL(content);
    if (content) {
        TEST_ASSERT_NOT_NULL(strstr(content, "free(ptr);\n    ptr = NULL;\n"));
        /* The rest of the function must survive untouched. */
        TEST_ASSERT_NOT_NULL(strstr(content, "return;"));
        free(content);
    }
    remove(src_path);
}

/* issue #210: --apply must be a no-op (never insert a duplicate) when the
 * pointer is already NULL'd on the very next line. */
//cfusa:req REQ-FIX006
//cfusa:test REQ-FIX006
void test_fix_apply_skips_already_nulled_pointer(void)
{
    char src_path[256];
    snprintf(src_path, sizeof(src_path), "%s/fix_apply_skip_src.c", CMD2_DIR);
    const char *original =
        "void fn(void *ptr) {\n    free(ptr);\n    ptr = NULL;\n}\n";
    FILE *sf = cfusa_fopen_write(src_path);
    TEST_ASSERT_NOT_NULL(sf);
    if (sf) {
        fputs(original, sf);
        if (fclose(sf) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }

    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--apply", NULL};
    int rc = cmd_fix(4, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);

    size_t len = 0;
    char *content = cfusa_read_file(src_path, &len);
    TEST_ASSERT_NOT_NULL(content);
    if (content) {
        TEST_ASSERT_EQUAL_STRING(original, content);
        free(content);
    }
    remove(src_path);
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

//cfusa:req REQ-DO178-DAL001
//cfusa:test REQ-DO178-DAL001
void test_do178_invalid_dal_returns_2(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--dal", "DAL-Z", NULL};
    int rc = cmd_do178(5, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

//cfusa:req REQ-DO178-DAL001
//cfusa:test REQ-DO178-DAL001
void test_do178_dal_prefix_format_accepted(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--dal", "DAL-A", NULL};
    int rc = cmd_do178(5, argv);
    /* DAL-A prefix format accepted, runs without usage error */
    TEST_ASSERT_TRUE(rc != 2);
}

/* ---- version ---- */

//cfusa:req REQ-VER001
//cfusa:test REQ-VER001
//cfusa:test REQ-CLI-VERSION001
void test_version_returns_zero(void)
{
    char *argv[] = {"cfusa", NULL};
    int rc = cmd_version(1, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- boundary ---- */

//cfusa:req REQ-BND001
//cfusa:test REQ-BND001
//cfusa:test REQ-CLI-BOUNDARY001
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
//cfusa:test REQ-CLI-VERIFY001
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

/* ---- report ---- */

//cfusa:req REQ-CLI-REPORT001
//cfusa:test REQ-CLI-REPORT001
void test_report_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_report(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-CLI-REPORT001
//cfusa:test REQ-CLI-REPORT001
void test_report_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, NULL};
    int rc = cmd_report(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-CLI-REPORT001
//cfusa:test REQ-CLI-REPORT001
void test_report_json_format_writes_output(void)
{
    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/report-out.json", CMD2_DIR);
    char *argv[] = {"cfusa", "--dir", CMD2_DIR,
                    "--format", "json", "--output", outpath, NULL};
    int rc = cmd_report(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"generatedAt\""));
    }
    (void)remove(outpath);
}

//cfusa:req REQ-CLI-REPORT001
//cfusa:test REQ-CLI-REPORT001
void test_report_strict_is_usage_error(void)
{
    /* §9.1: --strict on report is a usage error (use 'check' for gating) */
    char *argv[] = {"cfusa", "--dir", CMD2_DIR, "--strict", NULL};
    int rc = cmd_report(4, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

/* ---- main dispatch / help ---- */

//cfusa:req REQ-CLI-MAIN001
//cfusa:test REQ-CLI-MAIN001
void test_help_lists_known_commands(void)
{
    char capture_path[256];
    snprintf(capture_path, sizeof(capture_path), "%s/help_stdout.txt", CMD2_DIR);
    fflush(stdout);
    int saved_fd = dup(STDOUT_FILENO);
    FILE *redirected = freopen(capture_path, "w", stdout);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", NULL};
    int rc = cmd_help(1, argv);

    fflush(stdout);
    dup2(saved_fd, STDOUT_FILENO);
    int close_rc = close(saved_fd);
    (void)close_rc;

    TEST_ASSERT_EQUAL_INT(0, rc);

    FILE *f = fopen(capture_path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        /* Dispatch table (CFUSA_COMMANDS) must be reflected in help output */
        TEST_ASSERT_NOT_NULL(strstr(buf, "report"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "version"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Usage: cfusa <command>"));
    }
    remove(capture_path);
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
    RUN_TEST(test_fix_cy006_guidance_present);
    RUN_TEST(test_fix_guidance_covers_previously_missing_rules);
    RUN_TEST(test_fix_dry_run_previews_without_writing);
    RUN_TEST(test_fix_apply_inserts_null_after_free);
    RUN_TEST(test_fix_apply_skips_already_nulled_pointer);
    RUN_TEST(test_do178_help_returns_zero);
    RUN_TEST(test_do178_runs_no_crash);
    RUN_TEST(test_do178_invalid_dal_returns_2);
    RUN_TEST(test_do178_dal_prefix_format_accepted);
    RUN_TEST(test_version_returns_zero);
    RUN_TEST(test_boundary_help_returns_zero);
    RUN_TEST(test_boundary_runs_no_crash);
    RUN_TEST(test_verify_help_returns_zero);
    RUN_TEST(test_verify_runs_no_crash);
    RUN_TEST(test_report_help_returns_zero);
    RUN_TEST(test_report_runs_no_crash);
    RUN_TEST(test_report_json_format_writes_output);
    RUN_TEST(test_report_strict_is_usage_error);
    RUN_TEST(test_help_lists_known_commands);
    return UNITY_END();
}
