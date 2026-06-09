/*
 * Tests for cfusa_match_outside_string and cfusa_walk_sources exclusions.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/utils.h"

void setUp(void) {}
void tearDown(void) {}

/* ---- cfusa_match_outside_string ---- */

//cfusa:req REQ-UTIL001
//cfusa:test REQ-UTIL001
void test_match_found_bare(void)
{
    TEST_ASSERT_EQUAL(1, cfusa_match_outside_string("gets(buf)", "gets("));
}

//cfusa:req REQ-UTIL001
//cfusa:test REQ-UTIL001
void test_match_not_found_in_string_literal(void)
{
    TEST_ASSERT_EQUAL(0, cfusa_match_outside_string(
        "const char *s = \"gets(buf)\";", "gets("));
}

//cfusa:req REQ-UTIL002
//cfusa:test REQ-UTIL002
void test_match_found_after_string(void)
{
    /* token appears AFTER a string literal */
    TEST_ASSERT_EQUAL(1, cfusa_match_outside_string(
        "printf(\"ok\"); gets(buf);", "gets("));
}

//cfusa:req REQ-UTIL002
//cfusa:test REQ-UTIL002
void test_match_empty_line(void)
{
    TEST_ASSERT_EQUAL(0, cfusa_match_outside_string("", "gets("));
}

//cfusa:req REQ-UTIL003
//cfusa:test REQ-UTIL003
void test_match_escaped_quote_not_string_end(void)
{
    /* backslash-quote inside a string should not end the string */
    TEST_ASSERT_EQUAL(0, cfusa_match_outside_string(
        "printf(\"he said \\\"gets( surprise\\\"\");", "gets("));
}

//cfusa:req REQ-UTIL003
//cfusa:test REQ-UTIL003
void test_match_substring_inside_identifier(void)
{
    /* cfusa_match_outside_string is a substring (not word-boundary) checker.
     * "gets(" appears inside "fgets(" so it returns 1 — callers add their own
     * word-boundary guard when needed. */
    TEST_ASSERT_EQUAL(1, cfusa_match_outside_string(
        "int x = fgets(buf, 64, f);", "gets("));
}

/* ---- cfusa_walk_sources vendor exclusion ---- */

#define WALK_BASE "/tmp/cfusa_walk_test"

static int walk_count;
static int walk_counter(const char *path, void *ctx)
{
    (void)ctx; (void)path;
    walk_count++;
    return 0;
}

//cfusa:req REQ-UTIL004
//cfusa:test REQ-UTIL004
void test_walk_skips_vendor(void)
{
    /* Create a vendor subdir with a .c file — walk should skip it */
    char dir[256], vend[256], file[256];
    snprintf(dir,  sizeof(dir),  "%s/src",           WALK_BASE);
    snprintf(vend, sizeof(vend), "%s/vendor",        WALK_BASE);
    snprintf(file, sizeof(file), "%s/vendor/lib.c",  WALK_BASE);

    (void)mkdir(WALK_BASE, 0700);
    (void)mkdir(dir,  0700);
    (void)mkdir(vend, 0700);

    char src_file[256];
    snprintf(src_file, sizeof(src_file), "%s/src/main.c", WALK_BASE);
    FILE *f = fopen(src_file, "w"); if (f) { fputs("int x;\n", f); fclose(f); }
    FILE *g = fopen(file,     "w"); if (g) { fputs("int y;\n", g); fclose(g); }

    walk_count = 0;
    static const char * const exts[] = {".c"};
    cfusa_walk_sources(WALK_BASE, exts, 1, walk_counter, NULL);

    /* Only main.c should be counted; vendor/lib.c excluded */
    TEST_ASSERT_EQUAL(1, walk_count);

    (void)remove(src_file);
    (void)remove(file);
    (void)rmdir(vend);
    (void)rmdir(dir);
    (void)rmdir(WALK_BASE);
}

//cfusa:req REQ-UTIL005
//cfusa:test REQ-UTIL005
void test_walk_skips_build(void)
{
    char bld[256], file[256], src_file[256];
    snprintf(bld,      sizeof(bld),      "%s2/build",      WALK_BASE);
    snprintf(file,     sizeof(file),     "%s2/build/x.c",  WALK_BASE);
    snprintf(src_file, sizeof(src_file), "%s2/real.c",     WALK_BASE);
    char base2[256]; snprintf(base2, sizeof(base2), "%s2", WALK_BASE);

    (void)mkdir(base2, 0700);
    (void)mkdir(bld,   0700);
    FILE *f = fopen(src_file, "w"); if (f) { fputs("int a;\n", f); fclose(f); }
    FILE *g = fopen(file,     "w"); if (g) { fputs("int b;\n", g); fclose(g); }

    walk_count = 0;
    static const char * const exts[] = {".c"};
    cfusa_walk_sources(base2, exts, 1, walk_counter, NULL);

    TEST_ASSERT_EQUAL(1, walk_count);

    (void)remove(src_file);
    (void)remove(file);
    (void)rmdir(bld);
    (void)rmdir(base2);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_match_found_bare);
    RUN_TEST(test_match_not_found_in_string_literal);
    RUN_TEST(test_match_found_after_string);
    RUN_TEST(test_match_empty_line);
    RUN_TEST(test_match_escaped_quote_not_string_end);
    RUN_TEST(test_match_substring_inside_identifier);
    RUN_TEST(test_walk_skips_vendor);
    RUN_TEST(test_walk_skips_build);
    return UNITY_END();
}
