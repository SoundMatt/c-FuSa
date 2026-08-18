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

/* ---- L011: octal constant (MISRA-C 2012 Rule 7.1) — issue #108 ---- */

//cfusa:req REQ-LINT015
//cfusa:test REQ-LINT015
void test_l011_octal_literal_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int mode = 0755; (void)mode; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L011") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT015
//cfusa:test REQ-LINT015
void test_l011_hex_literal_silent(void)
{
    /* The '0' in 0x0A is never checked in isolation: the boundary-before
     * check on the second '0' (preceded by 'x') rejects it, and the first
     * '0' is followed by 'x' (not a digit) so it never matches either. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int mode = 0x0A; (void)mode; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L011"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT015
//cfusa:test REQ-LINT015
void test_l011_plain_zero_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { int z = 0; (void)z; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L011"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT015
//cfusa:test REQ-LINT015
void test_l011_float_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { double d = 0.5; (void)d; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L011"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT015
//cfusa:test REQ-LINT015
void test_l011_octal_in_string_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { const char *s = \"mode 0755\"; (void)s; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L011"));
    cfusa_report_free(&rpt);
}

/* issue #204: L011 already skipped octal-looking text inside a string
 * literal, but had no awareness of a TRAILING comment on an otherwise
 * real code line (only checked whether the line's first non-whitespace
 * character was '/' or '*') -- an octal-looking id number in a trailing
 * comment (e.g. this project's own test_hlr_llr.c has a trailing
 * comment reading "HLR-0550 deliberately left uncovered" right after
 * real code) used to false-positive. Migrating L011 onto the engine's shared
 * cfusa_lex_strip_line() fixes this for free. */
//cfusa:req REQ-LINT015
//cfusa:test REQ-LINT015
void test_l011_octal_in_trailing_comment_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(int i) {\n"
        "    if (i == 550) continue; /* HLR-0550 deliberately left uncovered */\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L011"));
    cfusa_report_free(&rpt);
}

/* ---- L012: keyword-named macro (MISRA-C 2012 Rule 20.4) — issue #108 ---- */

//cfusa:req REQ-LINT016
//cfusa:test REQ-LINT016
void test_l012_keyword_macro_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define int short\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt,"CFUSA-L012") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT016
//cfusa:test REQ-LINT016
void test_l012_non_keyword_macro_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define MAX_SIZE 128\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L012"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT016
//cfusa:test REQ-LINT016
void test_l012_keyword_prefixed_identifier_silent(void)
{
    /* "integer" is not the keyword "int" -- exact-length match only. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("#define integer long\nvoid fn(void) {}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt,"CFUSA-L012"));
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
    RUN_TEST(test_l011_octal_literal_fires);
    RUN_TEST(test_l011_hex_literal_silent);
    RUN_TEST(test_l011_plain_zero_silent);
    RUN_TEST(test_l011_float_literal_silent);
    RUN_TEST(test_l011_octal_in_string_silent);
    RUN_TEST(test_l011_octal_in_trailing_comment_silent);
    RUN_TEST(test_l012_keyword_macro_fires);
    RUN_TEST(test_l012_non_keyword_macro_silent);
    RUN_TEST(test_l012_keyword_prefixed_identifier_silent);
    return UNITY_END();
}
