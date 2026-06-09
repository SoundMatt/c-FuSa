/*
 * Tests for static analysis rules A001-A007.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_analyze_register_rules(void);

#define ANA_TEST_DIR  "/tmp/cfusa_ana_testdir"
#define ANA_TEST_FILE ANA_TEST_DIR "/t.c"

static void run_analyze_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_analyze_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);

    (void)mkdir(ANA_TEST_DIR, 0700);
    FILE *f = fopen(ANA_TEST_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_ANALYZE, ANA_TEST_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void) {}
void tearDown(void) { (void)remove(ANA_TEST_FILE); }

/* ---- A001: Dangerous string functions ---- */
//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_gets_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *buf) { gets(buf); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA002
//cfusa:test REQ-ANA002
void test_a001_strcpy_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *d, char *s) { strcpy(d, s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA003
//cfusa:test REQ-ANA003
void test_a001_fgets_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *buf, FILE *f) { fgets(buf, 64, f); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A001"));
    cfusa_report_free(&rpt);
}

/* ---- A002: Unchecked malloc ---- */
//cfusa:req REQ-ANA004
//cfusa:test REQ-ANA004
void test_a002_unchecked_malloc_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { void *p = malloc(64); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA005
//cfusa:test REQ-ANA005
void test_a002_inline_check_silent(void)
{
    /* A002 is line-based: if the NULL check appears on the SAME line it is silent */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(void) {\n"
        "    void *p = malloc(64); if (!p) return;\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A002"));
    cfusa_report_free(&rpt);
}

/* ---- A003: Signed/unsigned comparison ---- */
//cfusa:req REQ-ANA006
//cfusa:test REQ-ANA006
void test_a003_sizeof_comparison_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("int fn(int n) { return n < sizeof(int); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A003") > 0);
    cfusa_report_free(&rpt);
}

/* ---- A005: assert in production ---- */
//cfusa:req REQ-ANA007
//cfusa:test REQ-ANA007
void test_a005_assert_fires(void)
{
    /* A005 requires assert( to start the line (after whitespace strip) */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "#include <assert.h>\n"
        "void fn(int x) {\n"
        "    assert(x > 0);\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A005") > 0);
    cfusa_report_free(&rpt);
}

/* ---- A006: Pointer arithmetic ---- */
//cfusa:req REQ-ANA008
//cfusa:test REQ-ANA008
void test_a006_ptr_arithmetic_fires(void)
{
    /* A006 looks for ++/--/+=/−= combined with * on the same line */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *p) { char *q = p++; (void)q; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A006") > 0);
    cfusa_report_free(&rpt);
}

/* ---- A007: Unchecked system call returns ---- */
//cfusa:req REQ-ANA009
//cfusa:test REQ-ANA009
void test_a007_unchecked_fclose_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "#include <stdio.h>\n"
        "void fn(FILE *f) { fclose(f); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA009
//cfusa:test REQ-ANA009
void test_a007_checked_fclose_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "#include <stdio.h>\n"
        "void fn(FILE *f) { int r = fclose(f); (void)r; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A007"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a001_gets_fires);
    RUN_TEST(test_a001_strcpy_fires);
    RUN_TEST(test_a001_fgets_silent);
    RUN_TEST(test_a002_unchecked_malloc_fires);
    RUN_TEST(test_a002_inline_check_silent);
    RUN_TEST(test_a003_sizeof_comparison_fires);
    RUN_TEST(test_a005_assert_fires);
    RUN_TEST(test_a006_ptr_arithmetic_fires);
    RUN_TEST(test_a007_unchecked_fclose_fires);
    RUN_TEST(test_a007_checked_fclose_silent);
    return UNITY_END();
}
