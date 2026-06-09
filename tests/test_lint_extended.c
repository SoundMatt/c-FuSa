/*
 * Extended edge-case tests for lint rules L002-L010.
 * Complements test_lint_rules.c with additional positive and negative cases.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_lint_register_rules(void);

#define LEXT_DIR  "/tmp/cfusa_lext_testdir"
#define LEXT_FILE LEXT_DIR "/t.c"

static void run_lint_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfg.max_function_lines = 5;

    (void)mkdir(LEXT_DIR, 0700);
    FILE *f = fopen(LEXT_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, LEXT_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void)  {}
void tearDown(void) { (void)remove(LEXT_FILE); }

/* ---- L002: goto edge cases ---- */

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_goto_in_comment_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("// goto label\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L002"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_gotolabel_word_boundary(void)
{
    /* "goto_label" should not trigger L002 */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int goto_label=1; (void)goto_label; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L002"));
    cfusa_report_free(&rpt);
}

/* ---- L003: dynamic memory edge cases ---- */

//cfusa:req REQ-LINT005
//cfusa:test REQ-LINT005
void test_l003_calloc_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { void *p = calloc(10, 4); free(p); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT005
//cfusa:test REQ-LINT005
void test_l003_realloc_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *p) { p = realloc(p, 20); free(p); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT006
//cfusa:test REQ-LINT006
void test_l003_free_alone_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *p) { free(p); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L005: #undef edge cases ---- */

//cfusa:req REQ-LINT008
//cfusa:test REQ-LINT008
void test_l005_multiple_undefs_fire(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define A 1\n#undef A\n#define B 2\n#undef B\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L005") >= 2);
    cfusa_report_free(&rpt);
}

/* ---- L006: setjmp/longjmp ---- */

//cfusa:req REQ-LINT009
//cfusa:test REQ-LINT009
void test_l006_longjmp_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#include <setjmp.h>\njmp_buf b;\nvoid fn(void) { longjmp(b, 1); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L006") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L007: mutable static edge cases ---- */

//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_static_int_array_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static int buf[64];\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_static_const_char_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("static const char *VERSION = \"0.1\";\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L007"));
    cfusa_report_free(&rpt);
}

/* ---- L008: void* edge cases ---- */

//cfusa:req REQ-LINT012
//cfusa:test REQ-LINT012
void test_l008_void_ptr_return_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void *fn(void) { return 0; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L008") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L009: pragma edge cases ---- */

//cfusa:req REQ-LINT013
//cfusa:test REQ-LINT013
void test_l009_pragma_comment_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* comment saying #pragma is not a real pragma */
    run_lint_on("/* use #pragma pack with care */\nvoid fn(void){}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L009"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT013
//cfusa:test REQ-LINT013
void test_l009_pragma_pack_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#pragma pack(1)\nstruct S { char x; };\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L009") > 0);
    cfusa_report_free(&rpt);
}

/* ---- L010: errno edge cases ---- */

//cfusa:req REQ-LINT014
//cfusa:test REQ-LINT014
void test_l010_errno_include_silent(void)
{
    /* L010 is silenced by the errno.h include line itself */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#include <errno.h>\nvoid fn(void) { (void)errno; }\n", &rpt);
    /* The include line suppresses; the usage line fires — net is 1 not 2 */
    TEST_ASSERT_EQUAL(1, count_rule(&rpt,"CFUSA-L010"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_l002_goto_in_comment_silent);
    RUN_TEST(test_l002_gotolabel_word_boundary);
    RUN_TEST(test_l003_calloc_fires);
    RUN_TEST(test_l003_realloc_fires);
    RUN_TEST(test_l003_free_alone_fires);
    RUN_TEST(test_l005_multiple_undefs_fire);
    RUN_TEST(test_l006_longjmp_fires);
    RUN_TEST(test_l007_static_int_array_fires);
    RUN_TEST(test_l007_static_const_char_silent);
    RUN_TEST(test_l008_void_ptr_return_fires);
    RUN_TEST(test_l009_pragma_comment_silent);
    RUN_TEST(test_l009_pragma_pack_fires);
    RUN_TEST(test_l010_errno_include_silent);
    return UNITY_END();
}
