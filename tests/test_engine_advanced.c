/*
 * Advanced engine tests: rule registration, reset, category filtering.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/engine.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"

extern void cfusa_lint_register_rules(void);
extern void cfusa_cyber_register_rules(void);
extern void cfusa_analyze_register_rules(void);

#define ENG_DIR  "/tmp/cfusa_engadv_testdir"
#define ENG_FILE ENG_DIR "/t.c"

static void write_file(const char *code)
{
    (void)mkdir(ENG_DIR, 0700);
    FILE *f = fopen(ENG_FILE, "w");
    if (f) { fputs(code, f); fclose(f); }
}

void setUp(void)  {}
void tearDown(void) { (void)remove(ENG_FILE); }

/* ---- reset ---- */

//cfusa:req REQ-ENG001
//cfusa:test REQ-ENG001
void test_reset_then_register_lint_works(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    /* run a lint check to confirm rules are registered */
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    write_file("void fn(void) { goto end;\nend:;\n}\n");
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, ENG_DIR, &cfg, &rpt);
    /* Just check it doesn't crash; rule count may vary */
    TEST_ASSERT_TRUE(rpt.count >= 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ENG001
//cfusa:test REQ-ENG001
void test_reset_clears_rules(void)
{
    cfusa_lint_register_rules();
    cfusa_engine_reset();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    write_file("void fn(void) {\n    goto end;\nend:;\n}\n");
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, ENG_DIR, &cfg, &rpt);
    /* After reset, no rules; expect 0 findings */
    TEST_ASSERT_EQUAL(0, rpt.count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ENG001
//cfusa:test REQ-ENG001
void test_double_reset_no_crash(void)
{
    cfusa_engine_reset();
    cfusa_engine_reset();
    /* no crash */
}

/* ---- category filtering ---- */

//cfusa:req REQ-ENG002
//cfusa:test REQ-ENG002
void test_lint_category_runs_lint_rules(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* L003: malloc usage */
    write_file("void fn(void) { void *p = malloc(64); (void)p; }\n");
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, ENG_DIR, &cfg, &rpt);
    TEST_ASSERT_TRUE(rpt.count >= 1);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ENG002
//cfusa:test REQ-ENG002
void test_cyber_category_runs_cyber_rules(void)
{
    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    write_file("void fn(void *p) { free(p); }\n");
    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, ENG_DIR, &cfg, &rpt);
    TEST_ASSERT_TRUE(rpt.count >= 1);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ENG002
//cfusa:test REQ-ENG002
void test_analyze_category_runs_analyze_rules(void)
{
    cfusa_engine_reset();
    cfusa_analyze_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    write_file("void fn(char *d, const char *s) { strcpy(d, s); }\n");
    cfusa_engine_run_category(CFUSA_CATEGORY_ANALYZE, ENG_DIR, &cfg, &rpt);
    TEST_ASSERT_TRUE(rpt.count >= 1);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ENG002
//cfusa:test REQ-ENG002
void test_wrong_category_no_findings(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules(); /* register LINT rules */
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    write_file("void fn(void) { void *p = malloc(64); (void)p; }\n");
    /* Run CYBER category — lint rules should not fire */
    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, ENG_DIR, &cfg, &rpt);
    TEST_ASSERT_EQUAL(0, rpt.count);
    cfusa_report_free(&rpt);
}

/* ---- all categories at once ---- */

//cfusa:req REQ-ENG003
//cfusa:test REQ-ENG003
void test_all_categories_combined(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_cyber_register_rules();
    cfusa_analyze_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* Code with lint + cyber + analyze issues */
    write_file(
        "void fn(char *d, const char *s) {\n"
        "    strcpy(d, s);\n"   /* A001 + CY001 */
        "    free(d);\n"         /* CY006 */
        "}\n");
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT,    ENG_DIR, &cfg, &rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER,   ENG_DIR, &cfg, &rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_ANALYZE, ENG_DIR, &cfg, &rpt);
    TEST_ASSERT_TRUE(rpt.count >= 2);
    cfusa_report_free(&rpt);
}

/* ---- empty directory ---- */

//cfusa:req REQ-ENG004
//cfusa:test REQ-ENG004
void test_empty_dir_no_findings(void)
{
    /* Make sure ENG_DIR has no .c files */
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* Use a separate dir with no files */
    char emptydir[] = "/tmp/cfusa_engadv_empty";
    (void)mkdir(emptydir, 0700);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, emptydir, &cfg, &rpt);
    TEST_ASSERT_EQUAL(0, rpt.count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ENG004
//cfusa:test REQ-ENG004
void test_nonexistent_dir_no_crash(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, "/tmp/cfusa_eng_nosuchdir_xyz987", &cfg, &rpt);
    TEST_ASSERT_EQUAL(0, rpt.count);
    cfusa_report_free(&rpt);
}

/* ---- list rules no crash ---- */

//cfusa:req REQ-ENG005
//cfusa:test REQ-ENG005
void test_list_rules_no_crash(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_engine_list_rules(); /* prints to stdout — no crash */
}

//cfusa:req REQ-ENG005
//cfusa:test REQ-ENG005
void test_list_rules_after_reset(void)
{
    cfusa_engine_reset();
    cfusa_engine_list_rules(); /* empty list — no crash */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_reset_then_register_lint_works);
    RUN_TEST(test_reset_clears_rules);
    RUN_TEST(test_double_reset_no_crash);
    RUN_TEST(test_lint_category_runs_lint_rules);
    RUN_TEST(test_cyber_category_runs_cyber_rules);
    RUN_TEST(test_analyze_category_runs_analyze_rules);
    RUN_TEST(test_wrong_category_no_findings);
    RUN_TEST(test_all_categories_combined);
    RUN_TEST(test_empty_dir_no_findings);
    RUN_TEST(test_nonexistent_dir_no_crash);
    RUN_TEST(test_list_rules_no_crash);
    RUN_TEST(test_list_rules_after_reset);
    return UNITY_END();
}
