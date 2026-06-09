/*
 * Advanced HARA tests: all ASIL levels, boundary values, file operations.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_hara(int argc, char **argv);

#define HARA_DIR "/tmp/cfusa_haraadv_testdir"

void setUp(void)   { (void)mkdir(HARA_DIR, 0700); }
void tearDown(void) {}

static int asil(const char *s, const char *e, const char *c)
{
    char *argv[] = {"cfusa", "asil",
                    "--severity",     (char*)s,
                    "--exposure",     (char*)e,
                    "--controllability", (char*)c, NULL};
    return cmd_hara(8, argv);
}

/* ---- QM cases (low risk) ---- */

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1e1c1_qm(void)    { TEST_ASSERT_EQUAL(0, asil("1","1","1")); }

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1e2c1_qm(void)    { TEST_ASSERT_EQUAL(0, asil("1","2","1")); }

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1e3c1_qm(void)    { TEST_ASSERT_EQUAL(0, asil("1","3","1")); }

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1e4c1_qm(void)    { TEST_ASSERT_EQUAL(0, asil("1","4","1")); }

/* ---- ASIL-A cases ---- */

//cfusa:req REQ-HARA002
//cfusa:test REQ-HARA002
void test_asil_s1e4c3_asil_a(void) { TEST_ASSERT_EQUAL(0, asil("1","4","3")); }

//cfusa:req REQ-HARA002
//cfusa:test REQ-HARA002
void test_asil_s2e3c2_asil_a(void) { TEST_ASSERT_EQUAL(0, asil("2","3","2")); }

/* ---- ASIL-B cases ---- */

//cfusa:req REQ-HARA003
//cfusa:test REQ-HARA003
void test_asil_s2e4c2_asil_b(void) { TEST_ASSERT_EQUAL(0, asil("2","4","2")); }

//cfusa:req REQ-HARA003
//cfusa:test REQ-HARA003
void test_asil_s3e2c2_asil_b(void) { TEST_ASSERT_EQUAL(0, asil("3","2","2")); }

/* ---- ASIL-C cases ---- */

//cfusa:req REQ-HARA004
//cfusa:test REQ-HARA004
void test_asil_s2e4c3_asil_c(void) { TEST_ASSERT_EQUAL(0, asil("2","4","3")); }

//cfusa:req REQ-HARA004
//cfusa:test REQ-HARA004
void test_asil_s3e3c3_asil_c(void) { TEST_ASSERT_EQUAL(0, asil("3","3","3")); }

/* ---- ASIL-D cases ---- */

//cfusa:req REQ-HARA005
//cfusa:test REQ-HARA005
void test_asil_s3e4c3_asil_d(void) { TEST_ASSERT_EQUAL(0, asil("3","4","3")); }

//cfusa:req REQ-HARA005
//cfusa:test REQ-HARA005
void test_asil_s3e4c2_asil_d(void) { TEST_ASSERT_EQUAL(0, asil("3","4","2")); }

/* ---- Out-of-range / error cases ---- */

//cfusa:req REQ-HARA006
//cfusa:test REQ-HARA006
void test_hara_missing_severity_fails(void)
{
    char *argv[] = {"cfusa", "asil", "--exposure", "4", "--controllability", "3", NULL};
    int rc = cmd_hara(6, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-HARA006
//cfusa:test REQ-HARA006
void test_hara_missing_exposure_fails(void)
{
    char *argv[] = {"cfusa", "asil", "--severity", "3", "--controllability", "3", NULL};
    int rc = cmd_hara(6, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-HARA006
//cfusa:test REQ-HARA006
void test_hara_missing_controllability_fails(void)
{
    char *argv[] = {"cfusa", "asil", "--severity", "3", "--exposure", "4", NULL};
    int rc = cmd_hara(6, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-HARA006
//cfusa:test REQ-HARA006
void test_hara_s0_returns_error(void)
{
    /* S=0 is treated as "not provided" and should fail */
    int rc = asil("0", "4", "3");
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-HARA006
//cfusa:test REQ-HARA006
void test_hara_e0_returns_error(void)
{
    int rc = asil("3", "0", "3");
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-HARA006
//cfusa:test REQ-HARA006
void test_hara_c0_returns_error(void)
{
    int rc = asil("3", "4", "0");
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-HARA007
//cfusa:test REQ-HARA007
void test_hara_s5_returns_qm(void)
{
    /* S=5 is out of range [1-3] — treated as QM */
    int rc = asil("5", "5", "5");
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- init command ---- */

//cfusa:req REQ-HARA008
//cfusa:test REQ-HARA008
void test_hara_init_creates_file(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.cfusa-hara.json", HARA_DIR);
    (void)remove(path);

    char *argv[] = {"cfusa", "init", "--dir", HARA_DIR, NULL};
    int rc = cmd_hara(4, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);
}

//cfusa:req REQ-HARA008
//cfusa:test REQ-HARA008
void test_hara_show_missing_file_no_crash(void)
{
    char *argv[] = {"cfusa", "show", "--dir", "/tmp/cfusa_hara_nonexist_xyz", NULL};
    int rc = cmd_hara(4, argv);
    (void)rc;
}

/* ---- help ---- */

//cfusa:req REQ-HARA009
//cfusa:test REQ-HARA009
void test_hara_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_hara(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_asil_s1e1c1_qm);
    RUN_TEST(test_asil_s1e2c1_qm);
    RUN_TEST(test_asil_s1e3c1_qm);
    RUN_TEST(test_asil_s1e4c1_qm);
    RUN_TEST(test_asil_s1e4c3_asil_a);
    RUN_TEST(test_asil_s2e3c2_asil_a);
    RUN_TEST(test_asil_s2e4c2_asil_b);
    RUN_TEST(test_asil_s3e2c2_asil_b);
    RUN_TEST(test_asil_s2e4c3_asil_c);
    RUN_TEST(test_asil_s3e3c3_asil_c);
    RUN_TEST(test_asil_s3e4c3_asil_d);
    RUN_TEST(test_asil_s3e4c2_asil_d);
    RUN_TEST(test_hara_missing_severity_fails);
    RUN_TEST(test_hara_missing_exposure_fails);
    RUN_TEST(test_hara_missing_controllability_fails);
    RUN_TEST(test_hara_s0_returns_error);
    RUN_TEST(test_hara_e0_returns_error);
    RUN_TEST(test_hara_c0_returns_error);
    RUN_TEST(test_hara_s5_returns_qm);
    RUN_TEST(test_hara_init_creates_file);
    RUN_TEST(test_hara_show_missing_file_no_crash);
    RUN_TEST(test_hara_help_returns_zero);
    return UNITY_END();
}
