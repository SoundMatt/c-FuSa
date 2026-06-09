/*
 * Extended edge-case tests for cyber rules CY001-CY010.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_cyber_register_rules(void);

#define CEXT_DIR  "/tmp/cfusa_cext_testdir"
#define CEXT_FILE CEXT_DIR "/t.c"

static void run_cyber_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);

    (void)mkdir(CEXT_DIR, 0700);
    FILE *f = fopen(CEXT_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, CEXT_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void)  {}
void tearDown(void) { (void)remove(CEXT_FILE); }

/* ---- CY001: more unsafe string functions ---- */

//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_strcat_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, const char *s) { strcat(d, s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_memmove_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, char *s, int n) { memmove(d, s, n); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB002
//cfusa:test REQ-CYB002
void test_cy001_snprintf_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, int n) { snprintf(d, 64, \"%d\", n); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY001"));
    cfusa_report_free(&rpt);
}

/* ---- CY002: more format string cases ---- */

//cfusa:req REQ-CYB004
//cfusa:test REQ-CYB004
void test_cy002_syslog_variable_fires(void)
{
    /* syslog with a non-literal format arg should fire CY002 */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *msg) { syslog(LOG_ERR, msg); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB005
//cfusa:test REQ-CYB005
void test_cy002_printf_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { printf(\"hello\\n\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY002"));
    cfusa_report_free(&rpt);
}

/* ---- CY003: command injection ---- */

//cfusa:req REQ-CYB008
//cfusa:test REQ-CYB008
void test_cy003_system_variable_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *cmd) { system(cmd); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB009
//cfusa:test REQ-CYB009
void test_cy003_system_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { system(\"ls\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY003"));
    cfusa_report_free(&rpt);
}

/* ---- CY005: more integer overflow patterns ---- */

//cfusa:req REQ-CYB012
//cfusa:test REQ-CYB012
void test_cy005_malloc_size_mul_fires(void)
{
    /* CY005 fires when a malloc/calloc size has a multiplication (e.g. n * size) */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(int n) { char *p = malloc(n * size); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY005") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY008: more unsafe temp file functions ---- */

//cfusa:req REQ-CYB015
//cfusa:test REQ-CYB015
void test_cy008_tempnam_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char *p = tempnam(NULL, \"tmp\"); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY008") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY009: more broken crypto ---- */

//cfusa:req REQ-CYB016
//cfusa:test REQ-CYB016
void test_cy009_sha1_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { SHA1_CTX ctx; SHA1_Init(&ctx); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY009") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB016
//cfusa:test REQ-CYB016
void test_cy009_desx_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { DES_key_schedule s; DES_set_key(&k, &s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY009") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY010: more dangerous functions ---- */

//cfusa:req REQ-CYB017
//cfusa:test REQ-CYB017
void test_cy010_strtok_fires(void)
{
    /* strtok is CY010 — non-reentrant, unsafe in multi-threaded code */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *s) { char *tok = strtok(s, \",\"); (void)tok; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-CY010") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB018
//cfusa:test REQ-CYB018
void test_cy010_getline_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(char **line, size_t *n, FILE *f) { getline(line, n, f); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-CY010"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cy001_strcat_fires);
    RUN_TEST(test_cy001_memmove_fires);
    RUN_TEST(test_cy001_snprintf_silent);
    RUN_TEST(test_cy002_syslog_variable_fires);
    RUN_TEST(test_cy002_printf_literal_silent);
    RUN_TEST(test_cy003_system_variable_fires);
    RUN_TEST(test_cy003_system_literal_silent);
    RUN_TEST(test_cy005_malloc_size_mul_fires);
    RUN_TEST(test_cy008_tempnam_fires);
    RUN_TEST(test_cy009_sha1_fires);
    RUN_TEST(test_cy009_desx_fires);
    RUN_TEST(test_cy010_strtok_fires);
    RUN_TEST(test_cy010_getline_silent);
    return UNITY_END();
}
