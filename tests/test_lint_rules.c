/*
 * Tests for MISRA-C lint rules L001-L010.
 * Uses a temp-file approach: write a snippet, scan it, check findings.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_lint_register_rules(void);

#define LINT_TEST_DIR "/tmp/cfusa_lint_testdir"
#define LINT_TEST_FILE LINT_TEST_DIR "/t.c"

static void run_lint_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfg.max_function_lines = 5;

    (void)mkdir(LINT_TEST_DIR, 0700);
    FILE *f = fopen(LINT_TEST_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, LINT_TEST_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *rule_id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, rule_id) == 0)
            n++;
    return n;
}

void setUp(void) {}
void tearDown(void) { (void)remove(LINT_TEST_FILE); }

/* ---- L001: Function length ---- */
//cfusa:req REQ-LINT001
//cfusa:test REQ-LINT001
void test_l001_long_function_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void big_fn(void) {\n"
        "  int a=1;\n  int b=2;\n  int c=3;\n  int d=4;\n"
        "  int e=5;\n  int g=7;\n}\n",
        &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L001"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT002
//cfusa:test REQ-LINT002
void test_l001_short_function_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void short_fn(void) {\n  return;\n}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L001"));
    cfusa_report_free(&rpt);
}

/* ---- L002: goto ---- */
//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_goto_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) {\n  goto end;\nend:;\n}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L002"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT004
//cfusa:test REQ-LINT004
void test_l002_goto_in_string_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) {\n  const char *s=\"goto end\";\n}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L002"));
    cfusa_report_free(&rpt);
}

/* ---- L003: Dynamic memory ---- */
//cfusa:req REQ-LINT005
//cfusa:test REQ-LINT005
void test_l003_malloc_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) {\n  void *p = malloc(10);\n  free(p);\n}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L003"));
    cfusa_report_free(&rpt);
}

void test_l003_no_malloc_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) {\n  int x = 42;\n}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L003"));
    cfusa_report_free(&rpt);
}

/* ---- L005: #undef ---- */
//cfusa:req REQ-LINT008
//cfusa:test REQ-LINT008
void test_l005_undef_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define FOO 1\n#undef FOO\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L005"));
    cfusa_report_free(&rpt);
}

/* ---- L006: setjmp/longjmp ---- */
//cfusa:req REQ-LINT009
//cfusa:test REQ-LINT009
void test_l006_setjmp_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#include <setjmp.h>\nvoid fn(void) { jmp_buf b; setjmp(b); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L006"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT010
//cfusa:test REQ-LINT010
void test_l006_setjmp_in_string_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { const char *s = \"setjmp(b)\"; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L006"));
    cfusa_report_free(&rpt);
}

/* ---- L007: Mutable static ---- */
//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_mutable_static_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static int g_counter;\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L007"));
    cfusa_report_free(&rpt);
}

void test_l007_const_static_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static const int MAX = 10;\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L007"));
    cfusa_report_free(&rpt);
}

/* ---- L008: void* ---- */
//cfusa:req REQ-LINT012
//cfusa:test REQ-LINT012
void test_l008_void_ptr_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *ctx) { (void)ctx; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L008"));
    cfusa_report_free(&rpt);
}

/* ---- L009: #pragma ---- */
//cfusa:req REQ-LINT013
//cfusa:test REQ-LINT013
void test_l009_pragma_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#pragma once\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L009"));
    cfusa_report_free(&rpt);
}

/* ---- L010: errno ---- */
//cfusa:req REQ-LINT014
//cfusa:test REQ-LINT014
void test_l010_errno_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#include <errno.h>\nvoid fn(void) { if (errno!=0) {} }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L010"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_l001_long_function_fires);
    RUN_TEST(test_l001_short_function_silent);
    RUN_TEST(test_l002_goto_fires);
    RUN_TEST(test_l002_goto_in_string_silent);
    RUN_TEST(test_l003_malloc_fires);
    RUN_TEST(test_l003_no_malloc_silent);
    RUN_TEST(test_l005_undef_fires);
    RUN_TEST(test_l006_setjmp_fires);
    RUN_TEST(test_l006_setjmp_in_string_silent);
    RUN_TEST(test_l007_mutable_static_fires);
    RUN_TEST(test_l007_const_static_silent);
    RUN_TEST(test_l008_void_ptr_fires);
    RUN_TEST(test_l009_pragma_fires);
    RUN_TEST(test_l010_errno_fires);
    return UNITY_END();
}
