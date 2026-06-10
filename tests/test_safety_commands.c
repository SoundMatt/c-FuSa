/*
 * Smoke tests for safety analysis commands: TARA, FMEA, boundary, metrics.
 * These verify the commands don't crash and return expected exit codes.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_tara(int argc, char **argv);
extern int cmd_fmea(int argc, char **argv);
extern int cmd_boundary(int argc, char **argv);
extern int cmd_metrics(int argc, char **argv);
extern int cmd_version(int argc, char **argv);

#define SC_TEST_DIR "/tmp/cfusa_sc_testdir"

void setUp(void)   { (void)mkdir(SC_TEST_DIR, 0700); }
void tearDown(void) {}

/* ---- TARA ---- */

//cfusa:req REQ-TARA001
//cfusa:test REQ-TARA001
void test_tara_generates_json(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/tara.json", SC_TEST_DIR);
    (void)remove(path);

    /* cmd_tara with no subcommand defaults to generating tara.json + TARA.md */
    char *argv[] = {"cfusa", "--dir", SC_TEST_DIR, NULL};
    int rc = cmd_tara(3, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);

    char md_path[256];
    snprintf(md_path, sizeof(md_path), "%s/tara.md", SC_TEST_DIR);
    (void)remove(md_path);
}

//cfusa:req REQ-TARA002
//cfusa:test REQ-TARA002
void test_tara_show_no_crash_missing_file(void)
{
    char *argv[] = {"cfusa", "show", "--dir", SC_TEST_DIR, NULL};
    int rc = cmd_tara(4, argv);
    (void)rc;
}

//cfusa:req REQ-TARA003
//cfusa:test REQ-TARA003
void test_tara_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_tara(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- FMEA ---- */

//cfusa:req REQ-FMEA001
//cfusa:test REQ-FMEA001
void test_fmea_generates_json(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/fmea.json", SC_TEST_DIR);
    (void)remove(path);

    char *argv[] = {"cfusa", "--dir", SC_TEST_DIR, NULL};
    int rc = cmd_fmea(3, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);

    char csv_path[256];
    snprintf(csv_path, sizeof(csv_path), "%s/fmea.csv", SC_TEST_DIR);
    (void)remove(csv_path);
}

//cfusa:req REQ-FMEA002
//cfusa:test REQ-FMEA002
void test_fmea_show_no_crash_missing_file(void)
{
    char *argv[] = {"cfusa", "show", "--dir", SC_TEST_DIR, NULL};
    int rc = cmd_fmea(4, argv);
    (void)rc;
}

/* ---- Boundary ---- */

//cfusa:req REQ-BOU001
//cfusa:test REQ-BOU001
void test_boundary_help_no_crash(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_boundary(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- Metrics ---- */

//cfusa:req REQ-MET001
//cfusa:test REQ-MET001
void test_metrics_runs_on_empty_dir(void)
{
    char *argv[] = {"cfusa", "--dir", SC_TEST_DIR, NULL};
    int rc = cmd_metrics(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- Version ---- */

//cfusa:req REQ-CLI001
//cfusa:test REQ-CLI001
void test_version_returns_zero(void)
{
    char *argv[] = {"cfusa", NULL};
    int rc = cmd_version(1, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_tara_generates_json);
    RUN_TEST(test_tara_show_no_crash_missing_file);
    RUN_TEST(test_tara_help_returns_zero);
    RUN_TEST(test_fmea_generates_json);
    RUN_TEST(test_fmea_show_no_crash_missing_file);
    RUN_TEST(test_boundary_help_no_crash);
    RUN_TEST(test_metrics_runs_on_empty_dir);
    RUN_TEST(test_version_returns_zero);
    return UNITY_END();
}
