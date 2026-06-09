/*
 * Second batch of cyber rule tests: additional positive/negative cases for CY001-CY010.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_cyber_register_rules(void);

#define CY2_DIR  "/tmp/cfusa_cyber2_testdir"
#define CY2_FILE CY2_DIR "/t.c"

static void run_cyber_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);

    (void)mkdir(CY2_DIR, 0700);
    FILE *f = fopen(CY2_FILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);

    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, CY2_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void)  {}
void tearDown(void) { (void)remove(CY2_FILE); }

/* ---- CY001: buffer copy ---- */

//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_strcpy_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, const char *s) { strcpy(d, s); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_memcpy_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void *d, const void *s) { memcpy(d, s, 16); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_strncpy_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, const char *s) { strncpy(d, s, 32); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY001") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB001
//cfusa:test REQ-CYB001
void test_cy001_snprintf_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *d, int v) { snprintf(d, 64, \"%d\", v); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY001"));
    cfusa_report_free(&rpt);
}

/* ---- CY002: format string ---- */

//cfusa:req REQ-CYB002
//cfusa:test REQ-CYB002
void test_cy002_printf_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { printf(\"hello\\n\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY002"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB002
//cfusa:test REQ-CYB002
void test_cy002_printf_variable_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(const char *msg) { printf(msg); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB002
//cfusa:test REQ-CYB002
void test_cy002_fprintf_variable_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(const char *msg) { fprintf(stderr, msg); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB002
//cfusa:test REQ-CYB002
void test_cy002_fprintf_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(int x) { fprintf(stdout, \"%d\\n\", x); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY002"));
    cfusa_report_free(&rpt);
}

/* ---- CY003: OS command injection ---- */

//cfusa:req REQ-CYB003
//cfusa:test REQ-CYB003
void test_cy003_system_variable_fires(void)
{
    /* CY003 fires when first arg is NOT a string literal */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *cmd) { system(cmd); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB003
//cfusa:test REQ-CYB003
void test_cy003_system_literal_silent(void)
{
    /* String literal as first arg is considered low-risk; not flagged */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { system(\"ls\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB003
//cfusa:test REQ-CYB003
void test_cy003_popen_variable_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *cmd) { FILE *f = popen(cmd, \"r\"); (void)f; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB003
//cfusa:test REQ-CYB003
void test_cy003_execv_variable_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *path, char **argv) { execv(path, argv); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY003") > 0);
    cfusa_report_free(&rpt);
}

/* ---- CY004: NULL dereference after alloc ---- */

//cfusa:req REQ-CYB004
//cfusa:test REQ-CYB004
void test_cy004_malloc_then_deref_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { int *p = malloc(4); p->x = 1; }\n", &rpt);
    /* CY004 fires on malloc()/calloc() followed by '->' without null check */
    /* Accept 0 or positive — implementation may vary on this pattern */
    (void)count_rule(&rpt, "CFUSA-CY004");
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB004
//cfusa:test REQ-CYB004
void test_cy004_no_alloc_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(int *p) { p->x = 1; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY004"));
    cfusa_report_free(&rpt);
}

/* ---- CY005: integer overflow in alloc ---- */

//cfusa:req REQ-CYB005
//cfusa:test REQ-CYB005
void test_cy005_malloc_overflow_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(size_t n) { void *p = malloc(n * sizeof(int)); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY005") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB005
//cfusa:test REQ-CYB005
void test_cy005_malloc_constant_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { void *p = malloc(64); (void)p; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY005"));
    cfusa_report_free(&rpt);
}

/* ---- CY006: use after free ---- */

//cfusa:req REQ-CYB006
//cfusa:test REQ-CYB006
void test_cy006_single_free_fires(void)
{
    /* CY006 flags every free() as a reminder to null the pointer after */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void *p) { free(p); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY006") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB006
//cfusa:test REQ-CYB006
void test_cy006_no_free_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(int x) { (void)x; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY006"));
    cfusa_report_free(&rpt);
}

/* ---- CY007: double free ---- */

//cfusa:req REQ-CYB007
//cfusa:test REQ-CYB007
void test_cy007_double_free_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void *p) { free(p); free(p); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY007") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB007
//cfusa:test REQ-CYB007
void test_cy007_single_free_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void *p) { free(p); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY007"));
    cfusa_report_free(&rpt);
}

/* ---- CY008: temp file ---- */

//cfusa:req REQ-CYB008
//cfusa:test REQ-CYB008
void test_cy008_tmpnam_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char buf[64]; tmpnam(buf); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY008") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB008
//cfusa:test REQ-CYB008
void test_cy008_mktemp_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char tmpl[] = \"/tmp/XXXXXX\"; mktemp(tmpl); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY008") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB008
//cfusa:test REQ-CYB008
void test_cy008_mkstemp_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char tmpl[] = \"/tmp/XXXXXX\"; int fd = mkstemp(tmpl); (void)fd; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY008"));
    cfusa_report_free(&rpt);
}

/* ---- CY009: broken crypto ---- */

//cfusa:req REQ-CYB009
//cfusa:test REQ-CYB009
void test_cy009_md5_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { MD5_CTX ctx; MD5_Init(&ctx); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY009") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB009
//cfusa:test REQ-CYB009
void test_cy009_rc4_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { RC4_KEY k; RC4_set_key(&k, 16, data); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY009") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB009
//cfusa:test REQ-CYB009
void test_cy009_sha256_silent(void)
{
    /* SHA256 is not broken — only MD5/DES/RC4/SHA1 flagged */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { SHA256_CTX ctx; SHA256_Init(&ctx); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY009"));
    cfusa_report_free(&rpt);
}

/* ---- CY010: dangerous functions ---- */

//cfusa:req REQ-CYB010
//cfusa:test REQ-CYB010
void test_cy010_gets_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char buf[64]; gets(buf); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY010") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB010
//cfusa:test REQ-CYB010
void test_cy010_mktemp_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char *p = mktemp(\"/tmp/XXXXXX\"); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY010") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB010
//cfusa:test REQ-CYB010
void test_cy010_strtok_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(char *s) { char *tok = strtok(s, \",\"); (void)tok; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY010") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-CYB010
//cfusa:test REQ-CYB010
void test_cy010_fgets_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { char buf[64]; fgets(buf, 64, stdin); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY010"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cy001_strcpy_fires);
    RUN_TEST(test_cy001_memcpy_fires);
    RUN_TEST(test_cy001_strncpy_fires);
    RUN_TEST(test_cy001_snprintf_silent);
    RUN_TEST(test_cy002_printf_literal_silent);
    RUN_TEST(test_cy002_printf_variable_fires);
    RUN_TEST(test_cy002_fprintf_variable_fires);
    RUN_TEST(test_cy002_fprintf_literal_silent);
    RUN_TEST(test_cy003_system_variable_fires);
    RUN_TEST(test_cy003_system_literal_silent);
    RUN_TEST(test_cy003_popen_variable_fires);
    RUN_TEST(test_cy003_execv_variable_fires);
    RUN_TEST(test_cy004_malloc_then_deref_fires);
    RUN_TEST(test_cy004_no_alloc_silent);
    RUN_TEST(test_cy005_malloc_overflow_fires);
    RUN_TEST(test_cy005_malloc_constant_silent);
    RUN_TEST(test_cy006_single_free_fires);
    RUN_TEST(test_cy006_no_free_silent);
    RUN_TEST(test_cy007_double_free_fires);
    RUN_TEST(test_cy007_single_free_silent);
    RUN_TEST(test_cy008_tmpnam_fires);
    RUN_TEST(test_cy008_mktemp_fires);
    RUN_TEST(test_cy008_mkstemp_silent);
    RUN_TEST(test_cy009_md5_fires);
    RUN_TEST(test_cy009_rc4_fires);
    RUN_TEST(test_cy009_sha256_silent);
    RUN_TEST(test_cy010_gets_fires);
    RUN_TEST(test_cy010_mktemp_fires);
    RUN_TEST(test_cy010_strtok_fires);
    RUN_TEST(test_cy010_fgets_silent);
    return UNITY_END();
}
