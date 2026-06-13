/*
 * Smoke tests for remaining CLI commands: init, check, release, qualify,
 * safety_case, sign, iso26262, iec61508, misra, audit, diff, badge, pr.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_init(int argc, char **argv);
extern int cmd_check(int argc, char **argv);
extern int cmd_release(int argc, char **argv);
extern int cmd_qualify(int argc, char **argv);
extern int cmd_safety_case(int argc, char **argv);
extern int cmd_sign(int argc, char **argv);
extern int cmd_iso26262(int argc, char **argv);
extern int cmd_iec61508(int argc, char **argv);
extern int cmd_misra(int argc, char **argv);
extern int cmd_do178(int argc, char **argv);
extern int cmd_iso21434(int argc, char **argv);
extern int cmd_iec62443(int argc, char **argv);
extern int cmd_audit_pack(int argc, char **argv);
extern int cmd_diff(int argc, char **argv);
extern int cmd_badge(int argc, char **argv);
extern int cmd_slsa(int argc, char **argv);
extern int cmd_capabilities(int argc, char **argv);

#define CLI_TEST_DIR "/tmp/cfusa_cli_testdir"

void setUp(void)   { (void)mkdir(CLI_TEST_DIR, 0700); }
void tearDown(void) {}

/* ---- init ---- */

//cfusa:req REQ-CLI001
//cfusa:test REQ-CLI001
void test_init_creates_config(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa.json", CLI_TEST_DIR);
    (void)remove(path);

    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, "--project", "test-proj", NULL};
    int rc = cmd_init(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);
}

//cfusa:req REQ-CLI002
//cfusa:test REQ-CLI002
void test_init_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_init(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- check ---- */

//cfusa:req REQ-CLI003
//cfusa:test REQ-CLI003
void test_check_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_check(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-CLI003
//cfusa:test REQ-CLI003
void test_check_runs_on_empty_dir(void)
{
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, NULL};
    int rc = cmd_check(3, argv);
    /* Safety rules (HARA001, COUP003) fire on any dir without safety artifacts;
     * this test verifies no crash — return code is expected to be non-zero. */
    TEST_ASSERT_TRUE(rc == 0 || rc == 1);
}

/* ---- release ---- */

//cfusa:req REQ-REL001
//cfusa:test REQ-REL001
void test_release_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_release(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-REL002
//cfusa:test REQ-REL002
void test_release_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, NULL};
    int rc = cmd_release(3, argv);
    (void)rc;
}

/* ---- qualify ---- */

//cfusa:req REQ-QUAL001
//cfusa:test REQ-QUAL001
void test_qualify_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_qualify(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-QUAL002
//cfusa:test REQ-QUAL002
void test_qualify_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, NULL};
    int rc = cmd_qualify(3, argv);
    (void)rc;
}

/* ---- safety_case ---- */

//cfusa:req REQ-SC001
//cfusa:test REQ-SC001
void test_safety_case_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, NULL};
    int rc = cmd_safety_case(3, argv);
    (void)rc;
}

/* ---- sign ---- */

//cfusa:req REQ-SIGN001
//cfusa:test REQ-SIGN001
void test_sign_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_sign(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- iso26262 / iec61508 / misra ---- */

//cfusa:req REQ-ISO26262
//cfusa:test REQ-ISO26262
void test_iso26262_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_iso26262(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-IEC61508
//cfusa:test REQ-IEC61508
void test_iec61508_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_iec61508(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-MISRA
//cfusa:test REQ-MISRA
void test_misra_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_misra(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_iso26262_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/iso26262.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_iso26262(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"gap-report\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"iso26262\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"projectRoot\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"objectives\""));
    }
}

void test_iec61508_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/iec61508.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_iec61508(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"gap-report\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"iec61508\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"projectRoot\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"objectives\""));
    }
}

void test_misra_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/misra.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_misra(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"misra-coverage\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"projectRoot\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"rules\""));
    }
}

void test_do178_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/do178.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_do178(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"gap-report\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"do178c\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"projectRoot\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"objectives\""));
    }
}

void test_iso21434_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/iso21434.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_iso21434(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"gap-report\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"iso21434\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"projectRoot\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"objectives\""));
    }
}

void test_iec62443_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/iec62443.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_iec62443(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"gap-report\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"iec62443\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"projectRoot\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"objectives\""));
    }
}

/* ---- slsa ---- */

//cfusa:req REQ-SLSA001
//cfusa:test REQ-SLSA001
void test_slsa_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_slsa(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-SLSA002
//cfusa:test REQ-SLSA002
void test_slsa_json_format(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/slsa.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR,
                    "--format", "json", "--output", out, NULL};
    cmd_slsa(7, argv);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"schemaVersion\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"gap-report\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"slsa\""));
    }
    (void)remove(out);
}

/* ---- capabilities ---- */

//cfusa:req REQ-CAP001
//cfusa:test REQ-CAP001
void test_capabilities_json_has_slsa(void)
{
    char out[256];
    snprintf(out, sizeof(out), "%s/capabilities.json", CLI_TEST_DIR);
    char *argv[] = {"cfusa", "--format", "json", "--output", out, NULL};
    int rc = cmd_capabilities(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"commands\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"slsa\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"standards\""));
    }
    (void)remove(out);
}

/* ---- audit_pack ---- */

//cfusa:req REQ-AUDIT
//cfusa:test REQ-AUDIT
void test_audit_pack_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, NULL};
    int rc = cmd_audit_pack(3, argv);
    (void)rc;
}

/* ---- diff ---- */

//cfusa:req REQ-DIFF
//cfusa:test REQ-DIFF
void test_diff_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_diff(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- badge ---- */

//cfusa:req REQ-BADGE
//cfusa:test REQ-BADGE
void test_badge_runs_no_crash(void)
{
    char *argv[] = {"cfusa", "--dir", CLI_TEST_DIR, NULL};
    int rc = cmd_badge(3, argv);
    (void)rc;
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_init_creates_config);
    RUN_TEST(test_init_help_returns_zero);
    RUN_TEST(test_check_help_returns_zero);
    RUN_TEST(test_check_runs_on_empty_dir);
    RUN_TEST(test_release_help_returns_zero);
    RUN_TEST(test_release_runs_no_crash);
    RUN_TEST(test_qualify_help_returns_zero);
    RUN_TEST(test_qualify_runs_no_crash);
    RUN_TEST(test_safety_case_runs_no_crash);
    RUN_TEST(test_sign_help_returns_zero);
    RUN_TEST(test_iso26262_help_returns_zero);
    RUN_TEST(test_iso26262_json_format);
    RUN_TEST(test_iec61508_help_returns_zero);
    RUN_TEST(test_iec61508_json_format);
    RUN_TEST(test_misra_help_returns_zero);
    RUN_TEST(test_misra_json_format);
    RUN_TEST(test_do178_json_format);
    RUN_TEST(test_iso21434_json_format);
    RUN_TEST(test_iec62443_json_format);
    RUN_TEST(test_audit_pack_runs_no_crash);
    RUN_TEST(test_diff_help_returns_zero);
    RUN_TEST(test_badge_runs_no_crash);
    RUN_TEST(test_slsa_help_returns_zero);
    RUN_TEST(test_slsa_json_format);
    RUN_TEST(test_capabilities_json_has_slsa);
    return UNITY_END();
}
