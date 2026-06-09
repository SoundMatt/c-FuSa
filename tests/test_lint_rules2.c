/*
 * Second batch of lint rule tests: additional positive/negative cases for L001-L010.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_lint_register_rules(void);

#define L2_DIR  "/tmp/cfusa_lint2_testdir"
#define L2_FILE L2_DIR "/t.c"

static void run_lint_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfg.max_function_lines = 5;

    (void)mkdir(L2_DIR, 0700);
    FILE *f = fopen(L2_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, L2_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void)  {}
void tearDown(void) { (void)remove(L2_FILE); }

/* ---- L001: function length edge cases ---- */

//cfusa:req REQ-LINT001
//cfusa:test REQ-LINT001
void test_l001_exactly_at_limit_silent(void)
{
    /* 5 lines: fn opening + 3 stmts + closing = 5 exactly (should not fire) */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(void) {\n"
        "    int a = 1;\n"
        "    int b = 2;\n"
        "    (void)(a+b);\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L001"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT001
//cfusa:test REQ-LINT001
void test_l001_two_functions_both_long_fire(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* Each function has 8 body lines — length 8 > max 5, so both fire */
    run_lint_on(
        "void fn1(void) {\n"
        "    int a=1;\n"
        "    int b=2;\n"
        "    int c=3;\n"
        "    int d=4;\n"
        "    int e=5;\n"
        "    int f=6;\n"
        "    int g=7;\n"
        "}\n"
        "void fn2(void) {\n"
        "    int a=1;\n"
        "    int b=2;\n"
        "    int c=3;\n"
        "    int d=4;\n"
        "    int e=5;\n"
        "    int f=6;\n"
        "    int g=7;\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L001") >= 2);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT001
//cfusa:test REQ-LINT001
void test_l001_empty_function_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) {}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L001"));
    cfusa_report_free(&rpt);
}

/* ---- L002: goto edge cases ---- */

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_bare_goto_fires(void)
{
    /* L002 requires 'goto' at the start of a line (after whitespace trim) */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) {\n    goto end;\nend:;\n}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_goto_in_string_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("const char *s = \"goto label\";\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L002"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_goto_keyword_multiple_fires(void)
{
    /* goto must appear at line start for L002 to fire */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(void) {\n"
        "    goto a;\n"
        "    goto b;\n"
        "a:; b:;\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L002") >= 2);
    cfusa_report_free(&rpt);
}

/* ---- L003: dynamic memory additional cases ---- */

//cfusa:req REQ-LINT005
//cfusa:test REQ-LINT005
void test_l003_malloc_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { void *p = malloc(64); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT005
//cfusa:test REQ-LINT005
void test_l003_calloc_alone_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(size_t n) { int *p = (int*)calloc(n, sizeof(int)); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT005
//cfusa:test REQ-LINT005
void test_l003_realloc_fires_once(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *p) { p = realloc(p, 100); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L004: recursion detection ---- */

//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_direct_recursion_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "int factorial(int n) {\n"
        "    if (n <= 1) return 1;\n"
        "    return n * factorial(n - 1);\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L004") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_no_recursion_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "int add(int a, int b) { return a + b; }\n"
        "int sub(int a, int b) { return a - b; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L004"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_forward_decl_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "extern int helper(int x);\n"
        "int fn(int x) { return helper(x); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L004"));
    cfusa_report_free(&rpt);
}

/* ---- L005: #undef cases ---- */

//cfusa:req REQ-LINT008
//cfusa:test REQ-LINT008
void test_l005_single_undef_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define LIMIT 100\n#undef LIMIT\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L005") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT008
//cfusa:test REQ-LINT008
void test_l005_no_undef_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define LIMIT 100\nint x = LIMIT;\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L005"));
    cfusa_report_free(&rpt);
}

/* ---- L006: setjmp/longjmp ---- */

//cfusa:req REQ-LINT009
//cfusa:test REQ-LINT009
void test_l006_setjmp_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#include <setjmp.h>\njmp_buf b;\nvoid fn(void) { setjmp(b); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L006") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT009
//cfusa:test REQ-LINT009
void test_l006_no_setjmp_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int x = 1; (void)x; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L006"));
    cfusa_report_free(&rpt);
}

/* ---- L007: mutable static ---- */

//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_static_global_int_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static int counter = 0;\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_static_const_ptr_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static const int *TABLE = 0;\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L007"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_static_struct_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static struct { int x; } state;\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L007") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L008: void pointer ---- */

//cfusa:req REQ-LINT012
//cfusa:test REQ-LINT012
void test_l008_void_ptr_param_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *p) { (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L008") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT012
//cfusa:test REQ-LINT012
void test_l008_typed_ptr_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(int *p) { (void)p; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L008"));
    cfusa_report_free(&rpt);
}

/* ---- L009: pragma ---- */

//cfusa:req REQ-LINT013
//cfusa:test REQ-LINT013
void test_l009_pragma_optimize_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#pragma optimize(\"gt\", on)\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L009") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT013
//cfusa:test REQ-LINT013
void test_l009_pragma_once_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#pragma once\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L009") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L010: errno edge cases ---- */

//cfusa:req REQ-LINT014
//cfusa:test REQ-LINT014
void test_l010_errno_no_include_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int e = errno; (void)e; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L010") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT014
//cfusa:test REQ-LINT014
void test_l010_no_errno_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int x = 42; (void)x; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L010"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT014
//cfusa:test REQ-LINT014
void test_l010_errno_direct_fires(void)
{
    /* L010 fires on the string "errno" outside a comment or <errno.h> include */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { if (errno != 0) return; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L010") > 0);
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_l001_exactly_at_limit_silent);
    RUN_TEST(test_l001_two_functions_both_long_fire);
    RUN_TEST(test_l001_empty_function_silent);
    RUN_TEST(test_l002_bare_goto_fires);
    RUN_TEST(test_l002_goto_in_string_silent);
    RUN_TEST(test_l002_goto_keyword_multiple_fires);
    RUN_TEST(test_l003_malloc_fires);
    RUN_TEST(test_l003_calloc_alone_fires);
    RUN_TEST(test_l003_realloc_fires_once);
    RUN_TEST(test_l004_direct_recursion_fires);
    RUN_TEST(test_l004_no_recursion_silent);
    RUN_TEST(test_l004_forward_decl_silent);
    RUN_TEST(test_l005_single_undef_fires);
    RUN_TEST(test_l005_no_undef_silent);
    RUN_TEST(test_l006_setjmp_fires);
    RUN_TEST(test_l006_no_setjmp_silent);
    RUN_TEST(test_l007_static_global_int_fires);
    RUN_TEST(test_l007_static_const_ptr_silent);
    RUN_TEST(test_l007_static_struct_fires);
    RUN_TEST(test_l008_void_ptr_param_fires);
    RUN_TEST(test_l008_typed_ptr_silent);
    RUN_TEST(test_l009_pragma_optimize_fires);
    RUN_TEST(test_l009_pragma_once_fires);
    RUN_TEST(test_l010_errno_no_include_fires);
    RUN_TEST(test_l010_no_errno_silent);
    RUN_TEST(test_l010_errno_direct_fires);
    return UNITY_END();
}
