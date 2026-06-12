/*
 * Tests for cmd_qualify — exercises KAT and FUSA rule exercise paths.
 */
#include <stdio.h>
#include <string.h>
#include "unity.h"

extern int cmd_qualify(int argc, char **argv);

void setUp(void)  {}
void tearDown(void) {}

void test_qualify_text_qualified(void)
{
    char *argv[] = {"cfusa", "qualify", NULL};
    int rc = cmd_qualify(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_qualify_json_qualified(void)
{
    char *argv[] = {"cfusa", "qualify", "--format", "json", NULL};
    int rc = cmd_qualify(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_qualify_verbose_qualified(void)
{
    char *argv[] = {"cfusa", "qualify", "--verbose", NULL};
    int rc = cmd_qualify(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_qualify_output_file(void)
{
    char *argv[] = {"cfusa", "qualify", "--format", "json",
                    "--output", "/tmp/cfusa_qualify_test_out.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(0, rc);
    /* Verify output file was created */
    FILE *f = fopen("/tmp/cfusa_qualify_test_out.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
}

void test_qualify_help(void)
{
    char *argv[] = {"cfusa", "qualify", "--help", NULL};
    int rc = cmd_qualify(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_qualify_text_qualified);
    RUN_TEST(test_qualify_json_qualified);
    RUN_TEST(test_qualify_verbose_qualified);
    RUN_TEST(test_qualify_output_file);
    RUN_TEST(test_qualify_help);
    return UNITY_END();
}
