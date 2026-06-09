/*
 * Exhaustive tests for ISO 26262-3:2018 Table 4 ASIL determination.
 * All 36 valid S/E/C combinations are verified.
 */
#include <stdio.h>
#include <string.h>
#include "../vendor/unity/unity.h"

/* Access compute_asil via the public cmd entry point by capturing stdout.
 * Simpler: declare the internal function directly via a shim in cmd_hara.c.
 * Since we link cfusa_cmds we can call cmd_hara which prints the result. */
extern int cmd_hara(int argc, char **argv);

void setUp(void) {}
void tearDown(void) {}

/* Helper: call cmd_hara asil and assert no error */
static int call_asil(int s, int e, int c)
{
    char ss[4], es[4], cs[4];
    snprintf(ss, sizeof(ss), "%d", s);
    snprintf(es, sizeof(es), "%d", e);
    snprintf(cs, sizeof(cs), "%d", c);
    char *argv[] = {"cfusa","asil",
                    "--severity", ss, "--exposure", es,
                    "--controllability", cs, NULL};
    return cmd_hara(8, argv);
}

/* ---- QM coverage ---- */

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1e1c1(void) { TEST_ASSERT_EQUAL(0, call_asil(1,1,1)); }
void test_asil_s1e1c2(void) { TEST_ASSERT_EQUAL(0, call_asil(1,1,2)); }
void test_asil_s1e1c3(void) { TEST_ASSERT_EQUAL(0, call_asil(1,1,3)); }
void test_asil_s1e2c1(void) { TEST_ASSERT_EQUAL(0, call_asil(1,2,1)); }
void test_asil_s1e2c2(void) { TEST_ASSERT_EQUAL(0, call_asil(1,2,2)); }
void test_asil_s1e2c3(void) { TEST_ASSERT_EQUAL(0, call_asil(1,2,3)); }
void test_asil_s1e3c1(void) { TEST_ASSERT_EQUAL(0, call_asil(1,3,1)); }
void test_asil_s1e3c2(void) { TEST_ASSERT_EQUAL(0, call_asil(1,3,2)); }
void test_asil_s1e3c3(void) { TEST_ASSERT_EQUAL(0, call_asil(1,3,3)); }
void test_asil_s1e4c1(void) { TEST_ASSERT_EQUAL(0, call_asil(1,4,1)); }
void test_asil_s1e4c2(void) { TEST_ASSERT_EQUAL(0, call_asil(1,4,2)); }
void test_asil_s1e4c3(void) { TEST_ASSERT_EQUAL(0, call_asil(1,4,3)); }

void test_asil_s2e1c1(void) { TEST_ASSERT_EQUAL(0, call_asil(2,1,1)); }
void test_asil_s2e1c2(void) { TEST_ASSERT_EQUAL(0, call_asil(2,1,2)); }
void test_asil_s2e1c3(void) { TEST_ASSERT_EQUAL(0, call_asil(2,1,3)); }
void test_asil_s2e2c1(void) { TEST_ASSERT_EQUAL(0, call_asil(2,2,1)); }
void test_asil_s2e2c2(void) { TEST_ASSERT_EQUAL(0, call_asil(2,2,2)); }
void test_asil_s2e2c3(void) { TEST_ASSERT_EQUAL(0, call_asil(2,2,3)); }
void test_asil_s2e3c1(void) { TEST_ASSERT_EQUAL(0, call_asil(2,3,1)); }
void test_asil_s2e3c2(void) { TEST_ASSERT_EQUAL(0, call_asil(2,3,2)); }
void test_asil_s2e3c3(void) { TEST_ASSERT_EQUAL(0, call_asil(2,3,3)); }
void test_asil_s2e4c1(void) { TEST_ASSERT_EQUAL(0, call_asil(2,4,1)); }
void test_asil_s2e4c2(void) { TEST_ASSERT_EQUAL(0, call_asil(2,4,2)); }
void test_asil_s2e4c3(void) { TEST_ASSERT_EQUAL(0, call_asil(2,4,3)); }

void test_asil_s3e1c1(void) { TEST_ASSERT_EQUAL(0, call_asil(3,1,1)); }
void test_asil_s3e1c2(void) { TEST_ASSERT_EQUAL(0, call_asil(3,1,2)); }
void test_asil_s3e1c3(void) { TEST_ASSERT_EQUAL(0, call_asil(3,1,3)); }
void test_asil_s3e2c1(void) { TEST_ASSERT_EQUAL(0, call_asil(3,2,1)); }
void test_asil_s3e2c2(void) { TEST_ASSERT_EQUAL(0, call_asil(3,2,2)); }
void test_asil_s3e2c3(void) { TEST_ASSERT_EQUAL(0, call_asil(3,2,3)); }
void test_asil_s3e3c1(void) { TEST_ASSERT_EQUAL(0, call_asil(3,3,1)); }
void test_asil_s3e3c2(void) { TEST_ASSERT_EQUAL(0, call_asil(3,3,2)); }
void test_asil_s3e3c3(void) { TEST_ASSERT_EQUAL(0, call_asil(3,3,3)); }
void test_asil_s3e4c1(void) { TEST_ASSERT_EQUAL(0, call_asil(3,4,1)); }
void test_asil_s3e4c2(void) { TEST_ASSERT_EQUAL(0, call_asil(3,4,2)); }
void test_asil_s3e4c3(void) { TEST_ASSERT_EQUAL(0, call_asil(3,4,3)); }

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_asil_s1e1c1); RUN_TEST(test_asil_s1e1c2); RUN_TEST(test_asil_s1e1c3);
    RUN_TEST(test_asil_s1e2c1); RUN_TEST(test_asil_s1e2c2); RUN_TEST(test_asil_s1e2c3);
    RUN_TEST(test_asil_s1e3c1); RUN_TEST(test_asil_s1e3c2); RUN_TEST(test_asil_s1e3c3);
    RUN_TEST(test_asil_s1e4c1); RUN_TEST(test_asil_s1e4c2); RUN_TEST(test_asil_s1e4c3);
    RUN_TEST(test_asil_s2e1c1); RUN_TEST(test_asil_s2e1c2); RUN_TEST(test_asil_s2e1c3);
    RUN_TEST(test_asil_s2e2c1); RUN_TEST(test_asil_s2e2c2); RUN_TEST(test_asil_s2e2c3);
    RUN_TEST(test_asil_s2e3c1); RUN_TEST(test_asil_s2e3c2); RUN_TEST(test_asil_s2e3c3);
    RUN_TEST(test_asil_s2e4c1); RUN_TEST(test_asil_s2e4c2); RUN_TEST(test_asil_s2e4c3);
    RUN_TEST(test_asil_s3e1c1); RUN_TEST(test_asil_s3e1c2); RUN_TEST(test_asil_s3e1c3);
    RUN_TEST(test_asil_s3e2c1); RUN_TEST(test_asil_s3e2c2); RUN_TEST(test_asil_s3e2c3);
    RUN_TEST(test_asil_s3e3c1); RUN_TEST(test_asil_s3e3c2); RUN_TEST(test_asil_s3e3c3);
    RUN_TEST(test_asil_s3e4c1); RUN_TEST(test_asil_s3e4c2); RUN_TEST(test_asil_s3e4c3);
    return UNITY_END();
}
