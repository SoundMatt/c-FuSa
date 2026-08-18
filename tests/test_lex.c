/*
 * Tests for cfusa_lex_strip_line()/cfusa_lex_reset() (issue #203) -- the
 * shared comment/string-literal-aware line-stripping primitive that
 * replaces the ad hoc in_block_comment/in_str tracking previously
 * duplicated across l003_ctx_t, l004_ctx_t, l006_ctx_t, coup_ctx_t.
 */
#include <stdio.h>
#include <string.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/lex.h"

void setUp(void) {}
void tearDown(void) {}

static char out[256];

/* Builds the expected output by copying `input` and blanking (with
 * spaces) the half-open byte range [start, end) -- avoids hand-counting
 * spaces in a literal expected string, which is exactly what produced
 * off-by-one mistakes the first time these tests were written. */
static void expected_blanked(char *dst, size_t dst_sz, const char *input,
                              int start, int end)
{
    strncpy(dst, input, dst_sz - 1);
    dst[dst_sz - 1] = '\0';
    for (int i = start; i < end && dst[i]; i++) dst[i] = ' ';
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_plain_code_line_unchanged(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "int x = 1;", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("int x = 1;", out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_line_comment_blanked_to_end_of_line(void)
{
    const char *input = "int x = 1; // extern foo(";
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, input, out, sizeof(out));

    char expected[64];
    expected_blanked(expected, sizeof(expected), input,
                      (int)(strchr(input, '/') - input), (int)strlen(input));
    TEST_ASSERT_EQUAL_STRING(expected, out);
    TEST_ASSERT_EQUAL(strlen(input), strlen(out));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_single_line_block_comment_blanked(void)
{
    const char *input = "int x /* extern foo( */ = 1;";
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, input, out, sizeof(out));

    char expected[64];
    const char *cstart = strstr(input, "/*");
    const char *cend = strstr(input, "*/") + 2;
    expected_blanked(expected, sizeof(expected), input,
                      (int)(cstart - input), (int)(cend - input));
    TEST_ASSERT_EQUAL_STRING(expected, out);
    TEST_ASSERT_EQUAL(0, st.in_block_comment);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_string_literal_interior_blanked_but_quotes_kept(void)
{
    const char *input = "char *s = \"extern foo(\";";
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, input, out, sizeof(out));

    char expected[64];
    const char *q1 = strchr(input, '"');
    const char *q2 = strchr(q1 + 1, '"');
    expected_blanked(expected, sizeof(expected), input,
                      (int)(q1 - input) + 1, (int)(q2 - input));
    TEST_ASSERT_EQUAL_STRING(expected, out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_char_literal_interior_blanked_but_quotes_kept(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "char c = 'x';", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("char c = ' ';", out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_escaped_quote_inside_string_does_not_close_it(void)
{
    /* the escaped quote must not be mistaken for the closing quote --
     * "foo(\")" is one string literal, not "foo(\"" followed by real
     * code ")". */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "x(\"a\\\"b\"); real_call(", out, sizeof(out));
    /* the string "a\"b" is fully blanked (quotes kept), then real code */
    char expected[64];
    strcpy(expected, "x(\"    \"); real_call(");
    TEST_ASSERT_EQUAL_STRING(expected, out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_block_comment_persists_across_lines(void)
{
    /* multi-line block comment continuation with NO leading '*' -- the
     * exact issue #187 shape (a doc-comment continuation line mentioning
     * a function call, with no leading '*' marking it as comment text). */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);

    const char *line1 = "/* fixtures created by";
    cfusa_lex_strip_line(&st, line1, out, sizeof(out));
    TEST_ASSERT_EQUAL(1, st.in_block_comment);
    TEST_ASSERT_EQUAL(strlen(line1), strlen(out));
    TEST_ASSERT_NULL(strchr(out, '/'));
    TEST_ASSERT_TRUE(strstr(out, "fixtures") == NULL);

    cfusa_lex_strip_line(&st, " this setUp() writes below", out, sizeof(out));
    TEST_ASSERT_EQUAL(1, st.in_block_comment);
    TEST_ASSERT_TRUE(strstr(out, "setUp") == NULL);

    cfusa_lex_strip_line(&st, " are cleaned up in tearDown() */", out, sizeof(out));
    TEST_ASSERT_EQUAL(0, st.in_block_comment);
    TEST_ASSERT_TRUE(strstr(out, "tearDown") == NULL);

    cfusa_lex_strip_line(&st, "real_call();", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("real_call();", out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_reset_clears_in_block_comment(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "/* unterminated", out, sizeof(out));
    TEST_ASSERT_EQUAL(1, st.in_block_comment);

    /* a caller starting a new file must reset explicitly -- this is not
     * automatic, matching how l003_file()/l004_file()/l006_file()
     * already reset their own in_block_comment per file. */
    cfusa_lex_reset(&st);
    TEST_ASSERT_EQUAL(0, st.in_block_comment);
    cfusa_lex_strip_line(&st, "int y = 2;", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("int y = 2;", out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_empty_comment_does_not_glue_adjacent_tokens(void)
{
    /* the exact failure mode a delete-based strip has: an empty block
     * comment between "x" and "y(" must NOT collapse the two into the
     * glued-together "xy(" -- blanking with spaces keeps them apart in
     * the stripped output. */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "x/**/y(", out, sizeof(out));
    TEST_ASSERT_TRUE(strstr(out, "xy(") == NULL);
    TEST_ASSERT_EQUAL(strlen("x/**/y("), strlen(out));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_output_truncates_safely_on_small_buffer(void)
{
    char small[5];
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "int x = 1;", small, sizeof(small));
    TEST_ASSERT_EQUAL(4, strlen(small)); /* out_sz - 1 */
    TEST_ASSERT_EQUAL('\0', small[4]);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_zero_size_buffer_does_not_write(void)
{
    char tiny[1] = {'X'};
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    /* out_sz == 0: must return immediately without touching `out` at all */
    cfusa_lex_strip_line(&st, "int x;", tiny, 0);
    TEST_ASSERT_EQUAL('X', tiny[0]);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_empty_line(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("", out);
}

/* ---- issue #205: #if 0 preprocessor-lite awareness ---- */

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_blanks_content_until_endif(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);

    /* the #if 0 line itself is a structural marker, not dead code --
     * NOT blanked. */
    cfusa_lex_strip_line(&st, "#if 0", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("#if 0", out);

    cfusa_lex_strip_line(&st, "extern int legacy_hook(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "legacy_hook"));

    /* the #endif line itself is also a structural marker -- NOT blanked. */
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("#endif", out);

    cfusa_lex_strip_line(&st, "int real_code(void) { return 1; }", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("int real_code(void) { return 1; }", out);
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_nested_ifdef_does_not_close_early(void)
{
    /* a nested #ifdef/#endif inside the dead #if 0 span must not be
     * mistaken for the #if 0's OWN closing #endif -- content after the
     * inner #endif but still before the outer one must stay blanked. */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);

    cfusa_lex_strip_line(&st, "#if 0", out, sizeof(out));
    cfusa_lex_strip_line(&st, "#ifdef SOME_MACRO", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int dead_one(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "dead_one"));
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out)); /* closes #ifdef */
    cfusa_lex_strip_line(&st, "int dead_two(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "dead_two")); /* still inside outer #if 0 */
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out)); /* closes #if 0 */
    cfusa_lex_strip_line(&st, "int live_code(void);", out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "live_code"));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_else_branch_resumes_scanning(void)
{
    /* #else of a known-false #if 0 IS the branch actually compiled. */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);

    cfusa_lex_strip_line(&st, "#if 0", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int dead(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "dead"));
    cfusa_lex_strip_line(&st, "#else", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int alive(void);", out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "alive"));
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int after(void);", out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "after"));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_elif_zero_stays_disabled(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "#if 0", out, sizeof(out));
    cfusa_lex_strip_line(&st, "#elif 0", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int still_dead(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "still_dead"));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_elif_unknown_condition_resumes_scanning(void)
{
    /* an #elif whose condition can't be evaluated is conservatively
     * treated as "not provably dead" -- scanned, not blanked. */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "#if 0", out, sizeof(out));
    cfusa_lex_strip_line(&st, "#elif SOME_MACRO", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int maybe_alive(void);", out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "maybe_alive"));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_unknown_ifdef_condition_not_disabled(void)
{
    /* this deliberately does NOT attempt general #ifdef branch
     * resolution -- an ordinary #ifdef FOO is left alone (scanned
     * normally on both sides), matching this codebase's status quo
     * before issue #205 (no worse, only strictly more precise for the
     * literal #if 0 case). */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "#ifdef SOME_MACRO", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int fn(void);", out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "fn"));
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if_paren_zero_form_recognized(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "#if (0)", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int dead(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "dead"));
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_with_trailing_comment_recognized(void)
{
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "#if 0 /* disabled during bring-up */", out, sizeof(out));
    cfusa_lex_strip_line(&st, "int dead(void);", out, sizeof(out));
    TEST_ASSERT_NULL(strstr(out, "dead"));
    cfusa_lex_strip_line(&st, "#endif", out, sizeof(out));
}

//cfusa:req REQ-UTIL020
//cfusa:test REQ-UTIL020
void test_lex_if0_looking_text_inside_real_comment_not_a_directive(void)
{
    /* a genuinely unterminated block comment spanning what LOOKS like a
     * "#if 0" directive is comment text, not a real directive -- must
     * not be interpreted as one. */
    cfusa_lex_state_t st; cfusa_lex_reset(&st);
    cfusa_lex_strip_line(&st, "/* example:", out, sizeof(out));
    TEST_ASSERT_EQUAL(1, st.in_block_comment);
    cfusa_lex_strip_line(&st, "#if 0", out, sizeof(out));
    TEST_ASSERT_EQUAL(-1, st.disabled_at); /* not treated as a real directive */
    cfusa_lex_strip_line(&st, "*/", out, sizeof(out));
    TEST_ASSERT_EQUAL(0, st.in_block_comment);
    cfusa_lex_strip_line(&st, "int real_code(void);", out, sizeof(out));
    TEST_ASSERT_NOT_NULL(strstr(out, "real_code"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_lex_plain_code_line_unchanged);
    RUN_TEST(test_lex_line_comment_blanked_to_end_of_line);
    RUN_TEST(test_lex_single_line_block_comment_blanked);
    RUN_TEST(test_lex_string_literal_interior_blanked_but_quotes_kept);
    RUN_TEST(test_lex_char_literal_interior_blanked_but_quotes_kept);
    RUN_TEST(test_lex_escaped_quote_inside_string_does_not_close_it);
    RUN_TEST(test_lex_block_comment_persists_across_lines);
    RUN_TEST(test_lex_reset_clears_in_block_comment);
    RUN_TEST(test_lex_empty_comment_does_not_glue_adjacent_tokens);
    RUN_TEST(test_lex_output_truncates_safely_on_small_buffer);
    RUN_TEST(test_lex_zero_size_buffer_does_not_write);
    RUN_TEST(test_lex_empty_line);
    RUN_TEST(test_lex_if0_blanks_content_until_endif);
    RUN_TEST(test_lex_if0_nested_ifdef_does_not_close_early);
    RUN_TEST(test_lex_if0_else_branch_resumes_scanning);
    RUN_TEST(test_lex_if0_elif_zero_stays_disabled);
    RUN_TEST(test_lex_if0_elif_unknown_condition_resumes_scanning);
    RUN_TEST(test_lex_unknown_ifdef_condition_not_disabled);
    RUN_TEST(test_lex_if_paren_zero_form_recognized);
    RUN_TEST(test_lex_if0_with_trailing_comment_recognized);
    RUN_TEST(test_lex_if0_looking_text_inside_real_comment_not_a_directive);
    return UNITY_END();
}
