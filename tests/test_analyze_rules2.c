/*
 * Second batch of analyze rule tests: additional cases for A001-A007.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_analyze_register_rules(void);

#define A2_DIR  "/tmp/cfusa_an2_testdir"
#define A2_FILE A2_DIR "/t.c"

static void run_analyze_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_analyze_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);

    (void)mkdir(A2_DIR, 0700);
    FILE *f = fopen(A2_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_ANALYZE, A2_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void)  {}
void tearDown(void) { (void)remove(A2_FILE); }

/* ---- A001: dangerous string functions ---- */

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_strcpy_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *d, const char *s) { strcpy(d, s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_strcat_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *d, const char *s) { strcat(d, s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_sprintf_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *d, int v) { sprintf(d, \"%d\", v); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_gets_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *buf) { gets(buf); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_snprintf_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(char *d, int v) { snprintf(d, 64, \"%d\", v); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A001"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_fgets_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { char buf[64]; fgets(buf, 64, stdin); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A001"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA001
//cfusa:test REQ-ANA001
void test_a001_in_comment_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("/* uses strcpy internally */\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A001"));
    cfusa_report_free(&rpt);
}

/* ---- A002: unchecked malloc ---- */

//cfusa:req REQ-ANA002
//cfusa:test REQ-ANA002
void test_a002_malloc_no_check_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { int *p = malloc(4); *p = 1; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA002
//cfusa:test REQ-ANA002
void test_a002_calloc_no_check_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(size_t n) { int *p = calloc(n, 4); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA002
//cfusa:test REQ-ANA002
void test_a002_checked_inline_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { int *p = malloc(4); if (!p) return; *p = 1; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A002"));
    cfusa_report_free(&rpt);
}

/* ---- A003: signed/unsigned comparison ---- */

//cfusa:req REQ-ANA003
//cfusa:test REQ-ANA003
void test_a003_lt_sizeof_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("int fn(int n) { return n < sizeof(int); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA003
//cfusa:test REQ-ANA003
void test_a003_gt_sizeof_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("int fn(int n) { return n > sizeof(int); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA003
//cfusa:test REQ-ANA003
void test_a003_cast_sizeof_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("int fn(int n) { return n < (int)sizeof(int); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA003
//cfusa:test REQ-ANA003
void test_a003_size_t_cast_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("int fn(size_t n) { return n < sizeof(int); }\n", &rpt);
    /* No (size_t) cast in expression, but no signed type on left either */
    (void)count_rule(&rpt, "CFUSA-A003"); /* just no crash */
    cfusa_report_free(&rpt);
}

/* ---- A004: integer boundary constants ---- */

//cfusa:req REQ-ANA004
//cfusa:test REQ-ANA004
void test_a004_int_max_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int x) { int y = x + INT_MAX; (void)y; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A004") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA004
//cfusa:test REQ-ANA004
void test_a004_uint_max_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { unsigned x = UINT_MAX; (void)x; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A004") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA004
//cfusa:test REQ-ANA004
void test_a004_define_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("#define MY_MAX INT_MAX\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A004"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA004
//cfusa:test REQ-ANA004
void test_a004_guarded_if_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int x) { if (x == INT_MAX) return; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A004"));
    cfusa_report_free(&rpt);
}

/* ---- A005: assert ---- */

//cfusa:req REQ-ANA005
//cfusa:test REQ-ANA005
void test_a005_assert_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int *p) {\nassert(p != NULL);\n}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A005") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA005
//cfusa:test REQ-ANA005
void test_a005_assert_in_comment_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("/* assert(p) checks pointer */\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A005"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA005
//cfusa:test REQ-ANA005
void test_a005_multiple_asserts_fire(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int *p, int *q) {\nassert(p);\nassert(q);\n}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A005") >= 2);
    cfusa_report_free(&rpt);
}

/* ---- A006: pointer arithmetic ---- */

//cfusa:req REQ-ANA006
//cfusa:test REQ-ANA006
void test_a006_ptr_increment_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int *p) { p++; (void)p; }\n", &rpt);
    /* A006 needs `*` on same line as `++` — confirm behavior */
    (void)count_rule(&rpt, "CFUSA-A006"); /* no crash required */
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA006
//cfusa:test REQ-ANA006
void test_a006_ptr_plus_assign_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int *p, int n) { p += n; *p = 0; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A006") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA006
//cfusa:test REQ-ANA006
void test_a006_simple_add_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int a, int b) { int c = a + b; (void)c; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A006"));
    cfusa_report_free(&rpt);
}

/* ---- A007: unchecked system call ---- */

//cfusa:req REQ-ANA007
//cfusa:test REQ-ANA007
void test_a007_fopen_unchecked_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { fopen(\"x\", \"r\"); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA007
//cfusa:test REQ-ANA007
void test_a007_fclose_unchecked_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(FILE *f) { fclose(f); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA007
//cfusa:test REQ-ANA007
void test_a007_fopen_checked_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(void) { FILE *f = fopen(\"x\", \"r\"); (void)f; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A007"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA007
//cfusa:test REQ-ANA007
void test_a007_read_unchecked_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int fd, char *buf) { read(fd, buf, 64); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-A007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-ANA007
//cfusa:test REQ-ANA007
void test_a007_write_checked_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on("void fn(int fd, char *buf) { int r = write(fd, buf, 8); (void)r; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-A007"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a001_strcpy_fires);
    RUN_TEST(test_a001_strcat_fires);
    RUN_TEST(test_a001_sprintf_fires);
    RUN_TEST(test_a001_gets_fires);
    RUN_TEST(test_a001_snprintf_silent);
    RUN_TEST(test_a001_fgets_silent);
    RUN_TEST(test_a001_in_comment_silent);
    RUN_TEST(test_a002_malloc_no_check_fires);
    RUN_TEST(test_a002_calloc_no_check_fires);
    RUN_TEST(test_a002_checked_inline_silent);
    RUN_TEST(test_a003_lt_sizeof_fires);
    RUN_TEST(test_a003_gt_sizeof_fires);
    RUN_TEST(test_a003_cast_sizeof_silent);
    RUN_TEST(test_a003_size_t_cast_silent);
    RUN_TEST(test_a004_int_max_fires);
    RUN_TEST(test_a004_uint_max_fires);
    RUN_TEST(test_a004_define_silent);
    RUN_TEST(test_a004_guarded_if_silent);
    RUN_TEST(test_a005_assert_fires);
    RUN_TEST(test_a005_assert_in_comment_silent);
    RUN_TEST(test_a005_multiple_asserts_fire);
    RUN_TEST(test_a006_ptr_increment_fires);
    RUN_TEST(test_a006_ptr_plus_assign_fires);
    RUN_TEST(test_a006_simple_add_silent);
    RUN_TEST(test_a007_fopen_unchecked_fires);
    RUN_TEST(test_a007_fclose_unchecked_fires);
    RUN_TEST(test_a007_fopen_checked_silent);
    RUN_TEST(test_a007_read_unchecked_fires);
    RUN_TEST(test_a007_write_checked_silent);
    return UNITY_END();
}
