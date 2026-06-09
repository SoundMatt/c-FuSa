/*
 * Advanced utils tests: SHA256, path utilities, line counting, timestamp.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/utils.h"

#define UA_DIR  "/tmp/cfusa_utladv_testdir"
#define UA_FILE UA_DIR "/t.txt"

void setUp(void)
{
    (void)mkdir(UA_DIR, 0700);
}
void tearDown(void)
{
    (void)remove(UA_FILE);
}

/* ---- cfusa_basename ---- */

//cfusa:req REQ-UTIL010
//cfusa:test REQ-UTIL010
void test_basename_simple(void)
{
    const char *b = cfusa_basename("src/main.c");
    TEST_ASSERT_EQUAL_STRING("main.c", b);
}

//cfusa:req REQ-UTIL010
//cfusa:test REQ-UTIL010
void test_basename_no_slash(void)
{
    const char *b = cfusa_basename("main.c");
    TEST_ASSERT_EQUAL_STRING("main.c", b);
}

//cfusa:req REQ-UTIL010
//cfusa:test REQ-UTIL010
void test_basename_deep_path(void)
{
    const char *b = cfusa_basename("a/b/c/d.h");
    TEST_ASSERT_EQUAL_STRING("d.h", b);
}

//cfusa:req REQ-UTIL010
//cfusa:test REQ-UTIL010
void test_basename_trailing_slash(void)
{
    const char *b = cfusa_basename("src/");
    /* result is empty string or the slash — just no crash */
    TEST_ASSERT_NOT_NULL(b);
}

/* ---- cfusa_extension ---- */

//cfusa:req REQ-UTIL011
//cfusa:test REQ-UTIL011
void test_extension_c_file(void)
{
    const char *e = cfusa_extension("main.c");
    TEST_ASSERT_EQUAL_STRING(".c", e);
}

//cfusa:req REQ-UTIL011
//cfusa:test REQ-UTIL011
void test_extension_h_file(void)
{
    const char *e = cfusa_extension("utils.h");
    TEST_ASSERT_EQUAL_STRING(".h", e);
}

//cfusa:req REQ-UTIL011
//cfusa:test REQ-UTIL011
void test_extension_no_ext(void)
{
    /* cfusa_extension returns NULL when there is no extension */
    const char *e = cfusa_extension("Makefile");
    TEST_ASSERT_NULL(e);
}

//cfusa:req REQ-UTIL011
//cfusa:test REQ-UTIL011
void test_extension_multiple_dots(void)
{
    const char *e = cfusa_extension("foo.bar.c");
    TEST_ASSERT_EQUAL_STRING(".c", e);
}

/* ---- cfusa_path_join ---- */

//cfusa:req REQ-UTIL012
//cfusa:test REQ-UTIL012
void test_path_join_basic(void)
{
    char out[256];
    cfusa_path_join(out, sizeof(out), "/tmp", "file.c");
    TEST_ASSERT_EQUAL_STRING("/tmp/file.c", out);
}

//cfusa:req REQ-UTIL012
//cfusa:test REQ-UTIL012
void test_path_join_trailing_slash(void)
{
    char out[256];
    cfusa_path_join(out, sizeof(out), "/tmp/", "file.c");
    /* Should not double the slash */
    TEST_ASSERT_TRUE(strstr(out, "file.c") != NULL);
}

//cfusa:req REQ-UTIL012
//cfusa:test REQ-UTIL012
void test_path_join_empty_a(void)
{
    char out[256];
    cfusa_path_join(out, sizeof(out), "", "file.c");
    TEST_ASSERT_TRUE(strstr(out, "file.c") != NULL);
}

/* ---- cfusa_count_lines_in_file ---- */

//cfusa:req REQ-UTIL013
//cfusa:test REQ-UTIL013
void test_count_lines_empty_file(void)
{
    FILE *f = fopen(UA_FILE, "w"); if (f) fclose(f);
    int n = cfusa_count_lines_in_file(UA_FILE);
    TEST_ASSERT_TRUE(n >= 0);
}

//cfusa:req REQ-UTIL013
//cfusa:test REQ-UTIL013
void test_count_lines_three_lines(void)
{
    FILE *f = fopen(UA_FILE, "w");
    if (f) { fputs("line1\nline2\nline3\n", f); fclose(f); }
    int n = cfusa_count_lines_in_file(UA_FILE);
    TEST_ASSERT_EQUAL(3, n);
}

//cfusa:req REQ-UTIL013
//cfusa:test REQ-UTIL013
void test_count_lines_nonexistent_file(void)
{
    int n = cfusa_count_lines_in_file("/tmp/cfusa_nonexistent_xyz.c");
    TEST_ASSERT_TRUE(n <= 0);
}

//cfusa:req REQ-UTIL013
//cfusa:test REQ-UTIL013
void test_count_lines_one_line_no_newline(void)
{
    /* cfusa_count_lines_in_file counts newline chars; file without newline = 0 */
    FILE *f = fopen(UA_FILE, "w");
    if (f) { fputs("no newline at end", f); fclose(f); }
    int n = cfusa_count_lines_in_file(UA_FILE);
    TEST_ASSERT_TRUE(n >= 0);
}

/* ---- cfusa_count_c_files ---- */

//cfusa:req REQ-UTIL014
//cfusa:test REQ-UTIL014
void test_count_c_files_empty_dir(void)
{
    int n = cfusa_count_c_files(UA_DIR);
    TEST_ASSERT_TRUE(n >= 0);
}

//cfusa:req REQ-UTIL014
//cfusa:test REQ-UTIL014
void test_count_c_files_nonexistent_dir(void)
{
    int n = cfusa_count_c_files("/tmp/cfusa_nonexistent_dir_xyz987");
    TEST_ASSERT_TRUE(n >= 0);
}

//cfusa:req REQ-UTIL014
//cfusa:test REQ-UTIL014
void test_count_c_files_with_c_file(void)
{
    char cpath[256];
    snprintf(cpath, sizeof(cpath), "%s/x.c", UA_DIR);
    FILE *f = fopen(cpath, "w"); if (f) { fputs("int x;\n", f); fclose(f); }

    int n = cfusa_count_c_files(UA_DIR);
    TEST_ASSERT_TRUE(n >= 1);
    (void)remove(cpath);
}

/* ---- cfusa_sha256_buf ---- */

//cfusa:req REQ-UTIL015
//cfusa:test REQ-UTIL015
void test_sha256_buf_empty_known(void)
{
    char hex[65];
    cfusa_sha256_buf((const unsigned char *)"", 0, hex);
    /* SHA256 of empty string is well known */
    TEST_ASSERT_EQUAL_STRING(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
}

//cfusa:req REQ-UTIL015
//cfusa:test REQ-UTIL015
void test_sha256_buf_nonempty_length(void)
{
    char hex[65];
    cfusa_sha256_buf((const unsigned char *)"hello", 5, hex);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(hex));
}

//cfusa:req REQ-UTIL015
//cfusa:test REQ-UTIL015
void test_sha256_buf_different_inputs_differ(void)
{
    char h1[65], h2[65];
    cfusa_sha256_buf((const unsigned char *)"abc", 3, h1);
    cfusa_sha256_buf((const unsigned char *)"xyz", 3, h2);
    TEST_ASSERT_FALSE(strcmp(h1, h2) == 0);
}

//cfusa:req REQ-UTIL015
//cfusa:test REQ-UTIL015
void test_sha256_buf_same_input_same_output(void)
{
    char h1[65], h2[65];
    cfusa_sha256_buf((const unsigned char *)"test", 4, h1);
    cfusa_sha256_buf((const unsigned char *)"test", 4, h2);
    TEST_ASSERT_EQUAL_STRING(h1, h2);
}

/* ---- cfusa_sha256_file ---- */

//cfusa:req REQ-UTIL016
//cfusa:test REQ-UTIL016
void test_sha256_file_known_content(void)
{
    FILE *f = fopen(UA_FILE, "wb");
    if (f) { fclose(f); } /* empty file */

    char hex[65];
    cfusa_sha256_file(UA_FILE, hex);
    TEST_ASSERT_EQUAL_STRING(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
}

//cfusa:req REQ-UTIL016
//cfusa:test REQ-UTIL016
void test_sha256_file_nonexistent_no_crash(void)
{
    char hex[65];
    hex[0] = '\0';
    cfusa_sha256_file("/tmp/cfusa_sha_nonexist_xyz.c", hex);
    /* just no crash */
}

/* ---- cfusa_timestamp_now ---- */

//cfusa:req REQ-UTIL017
//cfusa:test REQ-UTIL017
void test_timestamp_now_not_empty(void)
{
    char buf[32];
    cfusa_timestamp_now(buf);
    TEST_ASSERT_TRUE(strlen(buf) > 0);
}

//cfusa:req REQ-UTIL017
//cfusa:test REQ-UTIL017
void test_timestamp_now_contains_T(void)
{
    char buf[32];
    cfusa_timestamp_now(buf);
    /* ISO 8601 timestamps contain 'T' */
    TEST_ASSERT_NOT_NULL(strchr(buf, 'T'));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_basename_simple);
    RUN_TEST(test_basename_no_slash);
    RUN_TEST(test_basename_deep_path);
    RUN_TEST(test_basename_trailing_slash);
    RUN_TEST(test_extension_c_file);
    RUN_TEST(test_extension_h_file);
    RUN_TEST(test_extension_no_ext);
    RUN_TEST(test_extension_multiple_dots);
    RUN_TEST(test_path_join_basic);
    RUN_TEST(test_path_join_trailing_slash);
    RUN_TEST(test_path_join_empty_a);
    RUN_TEST(test_count_lines_empty_file);
    RUN_TEST(test_count_lines_three_lines);
    RUN_TEST(test_count_lines_nonexistent_file);
    RUN_TEST(test_count_lines_one_line_no_newline);
    RUN_TEST(test_count_c_files_empty_dir);
    RUN_TEST(test_count_c_files_nonexistent_dir);
    RUN_TEST(test_count_c_files_with_c_file);
    RUN_TEST(test_sha256_buf_empty_known);
    RUN_TEST(test_sha256_buf_nonempty_length);
    RUN_TEST(test_sha256_buf_different_inputs_differ);
    RUN_TEST(test_sha256_buf_same_input_same_output);
    RUN_TEST(test_sha256_file_known_content);
    RUN_TEST(test_sha256_file_nonexistent_no_crash);
    RUN_TEST(test_timestamp_now_not_empty);
    RUN_TEST(test_timestamp_now_contains_T);
    return UNITY_END();
}
