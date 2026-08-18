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
#include "../include/cfusa/utils.h"

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
    FILE *f = cfusa_fopen_write(L2_FILE);
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, L2_DIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

/* Same as run_lint_on() but declares an "iso26262:<asil>" standard on the
 * config first, for exercising L003's ASIL-scaled severity. asil == NULL
 * leaves no standard declared (matches run_lint_on()'s behavior). */
static void run_lint_on_with_asil(const char *code, const char *asil, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfg.max_function_lines = 5;
    if (asil) {
        snprintf(cfg.standards[0], sizeof(cfg.standards[0]), "iso26262:%s", asil);
        cfg.standards_count = 1;
    }

    (void)mkdir(L2_DIR, 0700);
    FILE *f = cfusa_fopen_write(L2_FILE);
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");

    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, L2_DIR, &cfg, rpt);
}

static cfusa_severity_t first_severity(const cfusa_report_t *rpt, const char *id)
{
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) return rpt->findings[i].severity;
    TEST_FAIL_MESSAGE("rule id not found in report");
    return SEV_INFO;
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

//cfusa:req REQ-LINT001
//cfusa:test REQ-LINT001
void test_l001_long_line_no_crash(void)
{
    /* issue #177: a single physical source line >=4095 bytes with no
     * embedded newline in the first 4095 bytes used to leave `trimmed`
     * without a guaranteed NUL terminator before cfusa_str_trim()'s
     * internal strlen() ran on it (undefined behavior, potential OOB
     * read past the 4096-byte buffer). Exercises that exact code path —
     * must not crash or hang. */
    static char code[9000];
    size_t n = 0;
    memcpy(code, "int fn(void) { int a[] = {", 27); n += 27;
    for (int i = 0; i < 1000 && n < sizeof(code) - 20; i++)
        n += (size_t)snprintf(code + n, sizeof(code) - n, "%d,", i);
    n += (size_t)snprintf(code + n, sizeof(code) - n, "0}; return a[0]; }\n");

    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(code, &rpt);
    cfusa_report_free(&rpt);
}

/* ---- L002: goto edge cases ---- */

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_bare_goto_fires(void)
{
    /* 'goto' at the start of a line (after whitespace trim) */
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

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_inline_if_goto_fires(void)
{
    /* issue #162: this used to be the single biggest gap in L002 — the
     * most common real-world goto idiom, "if (cond) goto label;" on one
     * line, was never detected because the old check only matched when
     * the trimmed line literally BEGAN with "goto". */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(int x) { if (x < 0) goto fail; fail: return; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L002") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT003
//cfusa:test REQ-LINT003
void test_l002_identifier_prefix_or_suffix_silent(void)
{
    /* neither a leading nor a trailing identifier-boundary violation
     * should match: "notgoto" and "gotoward" are not the goto keyword. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(void) { int notgoto = 1; int gotoward = 2; "
        "(void)notgoto; (void)gotoward; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L002"));
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

/* ---- L003: boundary/ASIL precision ---- */

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_custom_free_suffixed_function_silent(void)
{
    /* "cfusa_report_free(" contains "free(" as a substring but is not a
     * call to stdlib free() — must not fire. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *p) { cfusa_report_free(p); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_string_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void) { puts(\"call malloc(10) to allocate\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_genuine_call_still_fires_beside_custom_free(void)
{
    /* Same line as a custom _free()-suffixed call plus a genuine free() —
     * the genuine call must still be caught, not masked by the skip. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on("void fn(void *p) { cfusa_report_free(p); free(p); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_multiline_block_comment_prose_silent(void)
{
    /* issue #163: only a single-line heuristic ("does THIS line start
     * with '/' or '*'?") skipped comments, so a multi-line block comment
     * whose continuation lines don't start with '*' produced false
     * findings on prose that merely mentions malloc/free. Persistent
     * in_block_comment state must track across fgets() iterations the
     * same way L004's already does. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "/* This helper wraps error handling. Historically it used to call\n"
        "   malloc(sizeof(ctx)) internally as an example of what NOT to do,\n"
        "   but that has been removed from this codebase entirely. */\n"
        "int helper(void) { return 0; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_genuine_call_still_fires_after_block_comment(void)
{
    /* a real call right after a closed block comment must still fire —
     * proves in_block_comment is correctly cleared on the comment's
     * closing delimiter, not stuck permanently open. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "/* comment mentioning malloc(1) in prose\n"
        " * more prose here */\n"
        "void fn(void) { void *p = malloc(64); (void)p; }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L003") > 0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_severity_warning_when_asil_undeclared(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on_with_asil("void fn(void) { void *p = malloc(8); (void)p; }\n", NULL, &rpt);
    TEST_ASSERT_EQUAL(SEV_WARNING, first_severity(&rpt, "CFUSA-L003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_severity_warning_at_asil_b(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on_with_asil("void fn(void) { void *p = malloc(8); (void)p; }\n", "ASIL-B", &rpt);
    TEST_ASSERT_EQUAL(SEV_WARNING, first_severity(&rpt, "CFUSA-L003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_severity_error_at_asil_c(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on_with_asil("void fn(void) { void *p = malloc(8); (void)p; }\n", "ASIL-C", &rpt);
    TEST_ASSERT_EQUAL(SEV_ERROR, first_severity(&rpt, "CFUSA-L003"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT017
//cfusa:test REQ-LINT017
void test_l003_severity_error_at_asil_d(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on_with_asil("void fn(void) { void *p = malloc(8); (void)p; }\n", "ASIL-D", &rpt);
    TEST_ASSERT_EQUAL(SEV_ERROR, first_severity(&rpt, "CFUSA-L003"));
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

//cfusa:req REQ-LINT009
//cfusa:test REQ-LINT009
void test_l006_wrapper_name_silent(void)
{
    /* issue #161: a project-local helper whose name merely ends with the
     * jmp-family token — no real <setjmp.h> call at all. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "int cfusa_setjmp(int state) { return state + 1; }\n"
        "void fn(void) { (void)cfusa_setjmp(1); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L006"));
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-LINT009
//cfusa:test REQ-LINT009
void test_l006_multiline_comment_prose_silent(void)
{
    /* L006 previously had no comment-awareness at all (not even the
     * single-line heuristic other rules in this file use) — prose in a
     * multi-line block comment merely mentioning the jmp-family tokens
     * must not fire. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "/* This module historically called setjmp(env) directly for\n"
        "   error recovery, but that has been removed from this codebase\n"
        "   entirely in favor of explicit error-code returns. */\n"
        "int fn(void) { return 0; }\n", &rpt);
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

/* issue #204: L007 previously matched "static " with a bare strstr() on
 * the raw line, no string-literal awareness at all -- a string-literal
 * array entry like `"static ", "extern ", NULL` (this project's own
 * cmd_trace.c has exactly this) contains the text "static " purely as
 * quoted data, not a real declaration, and used to false-positive.
 * Migrating L007 onto the engine's shared cfusa_lex_strip_line() (which
 * every line rule now goes through) fixes this for free. */
//cfusa:req REQ-LINT011
//cfusa:test REQ-LINT011
void test_l007_static_in_string_literal_silent(void)
{
    /* Exact repro shape from cmd_trace.c's own kws[] array: the
     * continuation line carries the closing `};` (so L007's own ";"
     * requirement is met) and the quoted "static " text, with no
     * "const"/"(" on that same physical line to otherwise exclude it. */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(void) {\n"
        "    static char *kws[] = {\"typedef \",\n"
        "                          \"static \", \"extern \", 0};\n"
        "    (void)kws;\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L007"));
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

/* issue #204: L008 previously matched "void *" with a bare strstr() on
 * the raw line, no string-literal awareness at all -- a string literal
 * containing example/remediation C code that mentions "void *" as text
 * (this project's own cmd_fix.c ships exactly this kind of remediation
 * guidance string) used to false-positive. Migrating L008 onto the
 * engine's shared cfusa_lex_strip_line() fixes this for free. */
//cfusa:req REQ-LINT012
//cfusa:test REQ-LINT012
void test_l008_void_ptr_in_string_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(void) {\n"
        "    const char *msg = \"example: void *p = malloc(n);\";\n"
        "    (void)msg;\n"
        "}\n", &rpt);
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

/* issue #204: L010 previously matched "errno" with a bare strstr() on
 * the raw line, no string-literal awareness at all -- a string literal
 * containing remediation-guidance text that mentions "errno" as prose
 * (this project's own cmd_fix.c ships exactly this kind of guidance
 * string for other rules) used to false-positive. Migrating L010 onto
 * the engine's shared cfusa_lex_strip_line() fixes this for free. */
//cfusa:req REQ-LINT014
//cfusa:test REQ-LINT014
void test_l010_errno_in_string_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void fn(void) {\n"
        "    const char *msg = \"remember to zero errno before the call\";\n"
        "    (void)msg;\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L010"));
    cfusa_report_free(&rpt);
}

/* ---- L004 regression: bug #59 — definition-line and brace mis-tracking ---- */

/* Helper: run lint with a caller-supplied config (for disabled_rules test). */
static void run_lint_on_cfg(const char *code, cfusa_config_t *cfg,
                             cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    (void)mkdir(L2_DIR, 0700);
    FILE *f = cfusa_fopen_write(L2_FILE);
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, L2_DIR, cfg, rpt);
}

/* The reported false positive: a multi-line function whose signature line
 * contains "fn_name(" — it should NOT be flagged as recursive.
 * (c-FuSa issue #59)  */
//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_definition_line_not_recursive(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void process(void) {\n"
        "    int x = 1;\n"
        "    (void)x;\n"
        "}\n",
        &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L004"));
    cfusa_report_free(&rpt);
}

/* Braces inside a block comment must not corrupt depth tracking. */
//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_brace_in_block_comment_not_recursive(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "/* This comment has a { brace } that must be ignored */\n"
        "void helper(void) {\n"
        "    int v = 0;\n"
        "    (void)v;\n"
        "}\n",
        &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L004"));
    cfusa_report_free(&rpt);
}

/* Braces inside a string literal must not corrupt depth tracking. */
//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_brace_in_string_not_recursive(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "void printer(void) {\n"
        "    const char *msg = \"open: { close: }\";\n"
        "    (void)msg;\n"
        "}\n",
        &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L004"));
    cfusa_report_free(&rpt);
}

/* Real self-call must still be detected after the fix. */
//cfusa:req REQ-LINT007
//cfusa:test REQ-LINT007
void test_l004_real_recursion_still_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_lint_on(
        "int fib(int n) {\n"
        "    if (n < 2) return n;\n"
        "    return fib(n - 1) + fib(n - 2);\n"
        "}\n",
        &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L004") > 0);
    cfusa_report_free(&rpt);
}

/* disabled_rules in config must suppress L004 entirely. */
//cfusa:req REQ-CFG007
//cfusa:test REQ-CFG007
void test_disabled_rules_suppresses_l004(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfg.max_function_lines = 5;
    strncpy(cfg.disabled_rules[0], "CFUSA-L004", 31);
    cfg.disabled_rules_count = 1;
    run_lint_on_cfg(
        "int fact(int n) {\n"
        "    if (n <= 1) return 1;\n"
        "    return n * fact(n - 1);\n"
        "}\n",
        &cfg, &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L004"));
    cfusa_report_free(&rpt);
}

/* issue #204: L003 is now registered via cfusa_engine_register_line_rule()
 * instead of cfusa_engine_register() -- disabled_rules must still suppress
 * it. This specifically exercises the new single-walk dispatcher's own
 * cfusa_config_is_rule_disabled() check in cfusa_engine_run_line_rules(),
 * not just the pre-existing whole-rule check test_disabled_rules_
 * suppresses_l004() above already covers. */
//cfusa:req REQ-CFG007
//cfusa:test REQ-CFG007
void test_disabled_rules_suppresses_line_rule_l003(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfg.max_function_lines = 5;
    strncpy(cfg.disabled_rules[0], "CFUSA-L003", 31);
    cfg.disabled_rules_count = 1;
    run_lint_on_cfg("void fn(void) { void *p = malloc(64); (void)p; }\n",
                     &cfg, &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-L003"));
    /* a different, still-enabled line rule scanning the SAME file must be
     * unaffected -- proves the disabled check is per-rule, not per-file. */
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-L008") > 0);
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_l001_exactly_at_limit_silent);
    RUN_TEST(test_l001_two_functions_both_long_fire);
    RUN_TEST(test_l001_empty_function_silent);
    RUN_TEST(test_l001_long_line_no_crash);
    RUN_TEST(test_l002_bare_goto_fires);
    RUN_TEST(test_l002_goto_in_string_silent);
    RUN_TEST(test_l002_goto_keyword_multiple_fires);
    RUN_TEST(test_l002_inline_if_goto_fires);
    RUN_TEST(test_l002_identifier_prefix_or_suffix_silent);
    RUN_TEST(test_l003_malloc_fires);
    RUN_TEST(test_l003_calloc_alone_fires);
    RUN_TEST(test_l003_realloc_fires_once);
    RUN_TEST(test_l003_custom_free_suffixed_function_silent);
    RUN_TEST(test_l003_string_literal_silent);
    RUN_TEST(test_l003_genuine_call_still_fires_beside_custom_free);
    RUN_TEST(test_l003_multiline_block_comment_prose_silent);
    RUN_TEST(test_l003_genuine_call_still_fires_after_block_comment);
    RUN_TEST(test_l003_severity_warning_when_asil_undeclared);
    RUN_TEST(test_l003_severity_warning_at_asil_b);
    RUN_TEST(test_l003_severity_error_at_asil_c);
    RUN_TEST(test_l003_severity_error_at_asil_d);
    RUN_TEST(test_l004_direct_recursion_fires);
    RUN_TEST(test_l004_no_recursion_silent);
    RUN_TEST(test_l004_forward_decl_silent);
    RUN_TEST(test_l004_definition_line_not_recursive);
    RUN_TEST(test_l004_brace_in_block_comment_not_recursive);
    RUN_TEST(test_l004_brace_in_string_not_recursive);
    RUN_TEST(test_l004_real_recursion_still_fires);
    RUN_TEST(test_disabled_rules_suppresses_l004);
    RUN_TEST(test_disabled_rules_suppresses_line_rule_l003);
    RUN_TEST(test_l005_single_undef_fires);
    RUN_TEST(test_l005_no_undef_silent);
    RUN_TEST(test_l006_setjmp_fires);
    RUN_TEST(test_l006_no_setjmp_silent);
    RUN_TEST(test_l006_wrapper_name_silent);
    RUN_TEST(test_l006_multiline_comment_prose_silent);
    RUN_TEST(test_l007_static_global_int_fires);
    RUN_TEST(test_l007_static_const_ptr_silent);
    RUN_TEST(test_l007_static_struct_fires);
    RUN_TEST(test_l007_static_in_string_literal_silent);
    RUN_TEST(test_l008_void_ptr_param_fires);
    RUN_TEST(test_l008_typed_ptr_silent);
    RUN_TEST(test_l008_void_ptr_in_string_literal_silent);
    RUN_TEST(test_l009_pragma_optimize_fires);
    RUN_TEST(test_l009_pragma_once_fires);
    RUN_TEST(test_l010_errno_no_include_fires);
    RUN_TEST(test_l010_no_errno_silent);
    RUN_TEST(test_l010_errno_direct_fires);
    RUN_TEST(test_l010_errno_in_string_literal_silent);
    return UNITY_END();
}
