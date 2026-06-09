#include "../vendor/unity/unity.h"
#include "../include/cfusa/utils.h"
#include <string.h>

void setUp(void)  {}
void tearDown(void) {}

/* ---- SHA-256 known-answer tests ---- */

void test_sha256_empty(void)
{
    char hex[65];
    cfusa_sha256_buf((const unsigned char *)"", 0, hex);
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    TEST_ASSERT_EQUAL_STRING(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855",
        hex);
}

void test_sha256_abc(void)
{
    char hex[65];
    cfusa_sha256_buf((const unsigned char *)"abc", 3, hex);
    TEST_ASSERT_EQUAL_STRING(
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad",
        hex);
}

void test_sha256_length(void)
{
    char hex[65];
    cfusa_sha256_buf((const unsigned char *)"test", 4, hex);
    TEST_ASSERT_EQUAL_INT(64, (int)strlen(hex));
}

/* ---- HMAC-SHA256 ---- */

void test_hmac_sha256_known(void)
{
    char hex[65];
    cfusa_hmac_sha256(
        (const unsigned char *)"key", 3,
        (const unsigned char *)"The quick brown fox jumps over the lazy dog", 43,
        hex);
    TEST_ASSERT_EQUAL_STRING(
        "f7bc83f430538424b13298e6aa6fb143"
        "ef4d59a14946175997479dbc2d1a3cd8",
        hex);
}

/* ---- String helpers ---- */

void test_str_contains_found(void)
{
    TEST_ASSERT_TRUE(cfusa_str_contains("hello world", "world"));
}

void test_str_contains_not_found(void)
{
    TEST_ASSERT_FALSE(cfusa_str_contains("hello world", "xyz"));
}

void test_str_starts_with(void)
{
    TEST_ASSERT_TRUE(cfusa_str_starts_with("cfusa check", "cfusa"));
    TEST_ASSERT_FALSE(cfusa_str_starts_with("cfusa check", "check"));
}

void test_basename(void)
{
    TEST_ASSERT_EQUAL_STRING("main.c",  cfusa_basename("/src/main.c"));
    TEST_ASSERT_EQUAL_STRING("main.c",  cfusa_basename("main.c"));
    TEST_ASSERT_EQUAL_STRING("utils.h", cfusa_basename("include/cfusa/utils.h"));
}

void test_extension(void)
{
    TEST_ASSERT_EQUAL_STRING(".c", cfusa_extension("main.c"));
    TEST_ASSERT_EQUAL_STRING(".h", cfusa_extension("include/utils.h"));
}

void test_str_trim(void)
{
    char s1[] = "  hello  ";
    TEST_ASSERT_EQUAL_STRING("hello", cfusa_str_trim(s1));
    char s2[] = "\t trim me \t";
    TEST_ASSERT_EQUAL_STRING("trim me", cfusa_str_trim(s2));
}

void test_str_escape_json(void)
{
    char out[128];
    cfusa_str_escape_json("hello \"world\"", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("hello \\\"world\\\"", out);
}

void test_path_join(void)
{
    char out[256];
    cfusa_path_join(out, sizeof(out), "/usr/local", "bin");
    TEST_ASSERT_EQUAL_STRING("/usr/local/bin", out);
}

void test_path_join_trailing_slash(void)
{
    char out[256];
    cfusa_path_join(out, sizeof(out), "/usr/local/", "bin");
    TEST_ASSERT_EQUAL_STRING("/usr/local/bin", out);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_empty);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_length);
    RUN_TEST(test_hmac_sha256_known);
    RUN_TEST(test_str_contains_found);
    RUN_TEST(test_str_contains_not_found);
    RUN_TEST(test_str_starts_with);
    RUN_TEST(test_basename);
    RUN_TEST(test_extension);
    RUN_TEST(test_str_trim);
    RUN_TEST(test_str_escape_json);
    RUN_TEST(test_path_join);
    RUN_TEST(test_path_join_trailing_slash);
    return UNITY_END();
}
