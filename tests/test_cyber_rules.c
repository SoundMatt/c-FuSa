/*
 * Tests for CWE-mapped cyber rules CY001-CY010.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_cyber_register_rules(void);

#define CYBER_TEST_DIR "/tmp/cfusa_cyber_testdir"
#define CYBER_TEST_FILE CYBER_TEST_DIR "/t.c"

static void run_cyber_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);

    (void)mkdir(CYBER_TEST_DIR, 0700);
    FILE *f = fopen(CYBER_TEST_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, CYBER_TEST_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void) {}
void tearDown(void) { (void)remove(CYBER_TEST_FILE); }

/* ---- CY001: Buffer copy without size check ---- */
//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_strcpy_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, const char *s) { strcpy(d, s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB002
//cfusa:test REQ-CYB002
void test_cy001_strcpy_in_string_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { const char *s = \"strcpy(d,s)\"; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY001"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB003
//cfusa:test REQ-CYB003
void test_cy001_no_false_positive_on_strncpy_prefix(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* strncpy should match CY001 but not double-fire for "cpy(" being a suffix */
    run_cyber_on("void fn(char *d, const char *s, int n) { strncpy(d,s,n); }\n", &rpt);
    TEST_ASSERT_EQUAL(1, count_rule(&rpt,"CFUSA-CY001"));
    cfusa_report_free(&rpt);
}

/* ---- CY002: Uncontrolled format string ---- */
//cfusa:req REQ-CYB004
//cfusa:test REQ-CYB004
void test_cy002_variable_format_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(const char *msg) { printf(msg); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB005
//cfusa:test REQ-CYB005
void test_cy002_literal_format_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(int x) { printf(\"%d\\n\", x); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY002"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB006
//cfusa:test REQ-CYB006
void test_cy002_fprintf_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(FILE *f, int x) { fprintf(f, \"%d\\n\", x); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY002"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB007
//cfusa:test REQ-CYB007
void test_cy002_fprintf_not_printf_mismatch(void)
{
    /* fprintf should not match as if printf to produce double-fire */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(FILE *f) { fprintf(f, \"ok\\n\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY002"));
    cfusa_report_free(&rpt);
}

/* ---- CY003: OS command injection ---- */
//cfusa:req REQ-CYB008
//cfusa:test REQ-CYB008
void test_cy003_popen_variable_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *cmd) { FILE *f = popen(cmd, \"r\"); pclose(f); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB009
//cfusa:test REQ-CYB009
void test_cy003_popen_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { FILE *f = popen(\"ls\", \"r\"); pclose(f); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY003"));
    cfusa_report_free(&rpt);
}

/* ---- CY004: NULL dereference after alloc ---- */
//cfusa:req REQ-CYB010
//cfusa:test REQ-CYB010
void test_cy004_malloc_then_deref_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { struct S *p = malloc(sizeof(*p)); p->x = 1; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY004") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB011
//cfusa:test REQ-CYB011
void test_cy004_safe_assign_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    /* ptr->field = malloc(...) — arrow precedes malloc, not immediate deref */
    run_cyber_on("void fn(struct T *t) { t->buf = malloc(64); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY004"));
    cfusa_report_free(&rpt);
}

/* ---- CY005: Integer overflow in alloc ---- */
//cfusa:req REQ-CYB012
//cfusa:test REQ-CYB012
void test_cy005_overflow_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(int n) { char *p = malloc(n * size); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY005") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY007: Double free ---- */
//cfusa:req REQ-CYB013
//cfusa:test REQ-CYB013
void test_cy007_double_free_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void *a, void *b) { free(a); free(b); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB014
//cfusa:test REQ-CYB014
void test_cy007_comment_two_frees_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("/* call free() before free() again */\nvoid fn(void){}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY007"));
    cfusa_report_free(&rpt);
}

/* ---- CY008: Insecure temp file ---- */
//cfusa:req REQ-CYB015
//cfusa:test REQ-CYB015
void test_cy008_tmpnam_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *buf) { tmpnam(buf); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY008") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY009: Broken crypto ---- */
//cfusa:req REQ-CYB016
//cfusa:test REQ-CYB016
void test_cy009_md5_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { MD5_CTX ctx; MD5_Init(&ctx); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY009") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY010: Dangerous function ---- */
//cfusa:req REQ-CYB017
//cfusa:test REQ-CYB017
void test_cy010_gets_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *buf) { gets(buf); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY010") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB018
//cfusa:test REQ-CYB018
void test_cy010_fgets_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *buf, FILE *f) { fgets(buf, 64, f); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY010"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cy001_strcpy_fires);
    RUN_TEST(test_cy001_strcpy_in_string_silent);
    RUN_TEST(test_cy001_no_false_positive_on_strncpy_prefix);
    RUN_TEST(test_cy002_variable_format_fires);
    RUN_TEST(test_cy002_literal_format_silent);
    RUN_TEST(test_cy002_fprintf_literal_silent);
    RUN_TEST(test_cy002_fprintf_not_printf_mismatch);
    RUN_TEST(test_cy003_popen_variable_fires);
    RUN_TEST(test_cy003_popen_literal_silent);
    RUN_TEST(test_cy004_malloc_then_deref_fires);
    RUN_TEST(test_cy004_safe_assign_silent);
    RUN_TEST(test_cy005_overflow_fires);
    RUN_TEST(test_cy007_double_free_fires);
    RUN_TEST(test_cy007_comment_two_frees_silent);
    RUN_TEST(test_cy008_tmpnam_fires);
    RUN_TEST(test_cy009_md5_fires);
    RUN_TEST(test_cy010_gets_fires);
    RUN_TEST(test_cy010_fgets_silent);
    return UNITY_END();
}
