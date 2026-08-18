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

//cfusa:req REQ-ANA003
//cfusa:test REQ-ANA003
void test_a001_real_call_still_fires_after_earlier_substring_hit(void)
{
    /* issue #151: a real "strcpy(" later on the same line as an earlier
     * "mystrcpy(" (a substring-like false match rejected by the boundary
     * check) must still be caught — the old code abandoned the ENTIRE
     * pattern after the first rejected hit and never saw the real call. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(char *d1,char *s1,char *d2,char *s2) { "
        "mystrcpy(d1, s1); strcpy(d2, s2); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A001") > 0);
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

/* issue #126: a size_t-typed local compared against sizeof(...) is not a
 * signed/unsigned mismatch -- CERT INT02-C-correct code, must be silent. */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_size_t_local_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(char *buf) {\n"
        "    size_t len = 4;\n"
        "    if (len < sizeof(buf)) { return; }\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A003"));
    cfusa_report_free(&rpt);
}

/* issue #126: same guarantee for a size_t-typed function parameter. */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_size_t_parameter_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "int fn(size_t n) { return n >= sizeof(int); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A003"));
    cfusa_report_free(&rpt);
}

/* issue #126: an unsigned-family typedef (uint32_t) is recognized too. */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_uint32_local_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(void) {\n"
        "    uint32_t count = 0;\n"
        "    if (count == sizeof(int)) { return; }\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A003"));
    cfusa_report_free(&rpt);
}

/* issue #126: a genuinely signed int compared to sizeof(...) must still
 * fire -- the fix must not overcorrect into never flagging anything. */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_int_local_still_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(void) {\n"
        "    int idx = 0;\n"
        "    if (idx < sizeof(int)) { return; }\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A003") > 0);
    cfusa_report_free(&rpt);
}

/* issue #150: "size_t a, b, c;" — only the first declarator ("a") used to
 * be recognized as unsigned; "b"/"c" (equally size_t) were not. */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_multi_declarator_all_recognized_unsigned(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(void) {\n"
        "    size_t a, b, c;\n"
        "    a = 0; c = 0;\n"
        "    if (b < sizeof(int)) { return; }\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A003"));
    cfusa_report_free(&rpt);
}

/* issue #150: an array-subscript declarator in the same comma list must
 * not confuse the multi-declarator scan. */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_multi_declarator_with_array_subscript(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(void) {\n"
        "    size_t buf[16], n;\n"
        "    (void)buf;\n"
        "    if (n < sizeof(int)) { return; }\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A003"));
    cfusa_report_free(&rpt);
}

/* issue #169: the no-space variant "n<sizeof(int)" must be caught the
 * same as "n < sizeof(int)". */
//cfusa:req REQ-ANA010
//cfusa:test REQ-ANA010
void test_a003_no_space_before_sizeof_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(void) {\n"
        "    int n = -1;\n"
        "    if (n<sizeof(int)) { return; }\n"
        "}\n", &rpt);
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

//cfusa:req REQ-ANA008
//cfusa:test REQ-ANA008
void test_a006_int_self_multiply_silent(void)
{
    /* issue #149: "side*side" is an ordinary int self-multiplication, not
     * pointer arithmetic — "side" is never declared or used as a pointer
     * anywhere on the line, it just happens to share the line with an
     * unrelated "side++" and a coincidental "*side" substring inside the
     * multiplication. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(int limit) {\n"
        "    int side;\n"
        "    for (side = 1; side*side < limit; side++) { }\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-A006"));
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

//cfusa:req REQ-ANA009
//cfusa:test REQ-ANA009
void test_a007_real_call_still_fires_after_earlier_substring_hit(void)
{
    /* issue #151: same fix as A001 — a real bare "close(" call later on
     * the same line as an earlier substring-only "myclose(" (rejected by
     * the boundary check) must still be caught. Uses the same pattern
     * name ("close(") both times so this isolates the fix — "fclose("
     * would independently fire on its own and wouldn't prove anything. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_analyze_on(
        "void fn(int fd1, int fd2) { myclose(fd1); close(fd2); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-A007") > 0);
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a001_gets_fires);
    RUN_TEST(test_a001_strcpy_fires);
    RUN_TEST(test_a001_fgets_silent);
    RUN_TEST(test_a001_real_call_still_fires_after_earlier_substring_hit);
    RUN_TEST(test_a002_unchecked_malloc_fires);
    RUN_TEST(test_a002_inline_check_silent);
    RUN_TEST(test_a003_sizeof_comparison_fires);
    RUN_TEST(test_a003_size_t_local_silent);
    RUN_TEST(test_a003_size_t_parameter_silent);
    RUN_TEST(test_a003_uint32_local_silent);
    RUN_TEST(test_a003_int_local_still_fires);
    RUN_TEST(test_a003_multi_declarator_all_recognized_unsigned);
    RUN_TEST(test_a003_multi_declarator_with_array_subscript);
    RUN_TEST(test_a003_no_space_before_sizeof_fires);
    RUN_TEST(test_a005_assert_fires);
    RUN_TEST(test_a006_ptr_arithmetic_fires);
    RUN_TEST(test_a006_int_self_multiply_silent);
    RUN_TEST(test_a007_unchecked_fclose_fires);
    RUN_TEST(test_a007_checked_fclose_silent);
    RUN_TEST(test_a007_real_call_still_fires_after_earlier_substring_hit);
    return UNITY_END();
}
