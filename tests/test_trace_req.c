/*
 * Tests for trace annotation scanning and req command.
 * Writes annotated source files to a temp dir and verifies traceability output.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_trace(int argc, char **argv);
extern int cmd_req(int argc, char **argv);
extern int cmd_disposition(int argc, char **argv);

#define TR_TEST_DIR "/tmp/cfusa_trace_testdir"

void setUp(void)   { (void)mkdir(TR_TEST_DIR, 0700); }
void tearDown(void) {}

static void write_src(const char *fname, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", TR_TEST_DIR, fname);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

/* ---- Trace ---- */

//cfusa:req REQ-TRA001
//cfusa:test REQ-TRA001
void test_trace_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_trace(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA002
//cfusa:test REQ-TRA002
void test_trace_scans_annotations_no_crash(void)
{
    write_src("annotated.c",
        "//cfusa:req REQ-LINT001\n"
        "void rule_l001(void) {}\n"
        "//cfusa:test REQ-LINT001\n"
        "void test_l001(void) {}\n");

    char *argv[] = {"cfusa", "--dir", TR_TEST_DIR, NULL};
    int rc = cmd_trace(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA003
//cfusa:test REQ-TRA003
void test_trace_no_annotations_no_crash(void)
{
    write_src("empty.c", "void fn(void) {}\n");

    char *argv[] = {"cfusa", "--dir", TR_TEST_DIR, NULL};
    int rc = cmd_trace(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA004
//cfusa:test REQ-TRA004
void test_trace_gaps_flag_no_crash(void)
{
    write_src("impl.c",
        "//cfusa:req REQ-ONLY001\n"
        "void impl(void) {}\n");

    char *argv[] = {"cfusa", "--dir", TR_TEST_DIR, "--gaps", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- Req command ---- */

//cfusa:req REQ-REQ001
//cfusa:test REQ-REQ001
void test_req_list_no_crash_no_file(void)
{
    char *argv[] = {"cfusa", "list", "--dir", TR_TEST_DIR, NULL};
    int rc = cmd_req(4, argv);
    (void)rc;
}

//cfusa:req REQ-REQ002
//cfusa:test REQ-REQ002
void test_req_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "--help", NULL};
    int rc = cmd_req(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- Disposition command ---- */

//cfusa:req REQ-DISP001
//cfusa:test REQ-DISP001
void test_disp_list_no_file_no_crash(void)
{
    char *argv[] = {"cfusa", "list", "--dir", TR_TEST_DIR, NULL};
    int rc = cmd_disposition(4, argv);
    (void)rc;
}

//cfusa:req REQ-DISP002
//cfusa:test REQ-DISP002
void test_disp_add_creates_entry(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.cfusa-dispositions.json", TR_TEST_DIR);
    (void)remove(path);

    char *argv[] = {"cfusa", "add",
                    "--rule", "CFUSA-L003",
                    "--action", "accept",
                    "--rationale", "host tool",
                    "--reviewer", "test",
                    "--dir", TR_TEST_DIR, NULL};
    int rc = cmd_disposition(12, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);
}

//cfusa:req REQ-DISP003
//cfusa:test REQ-DISP003
void test_disp_list_after_add(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.cfusa-dispositions.json", TR_TEST_DIR);
    (void)remove(path);

    /* add first */
    char *add_argv[] = {"cfusa", "add",
                        "--rule", "CFUSA-CY001",
                        "--action", "accept",
                        "--rationale", "bounded copies",
                        "--reviewer", "test",
                        "--dir", TR_TEST_DIR, NULL};
    (void)cmd_disposition(12, add_argv);

    /* list */
    char *list_argv[] = {"cfusa", "list", "--dir", TR_TEST_DIR, NULL};
    int rc = cmd_disposition(4, list_argv);
    TEST_ASSERT_EQUAL(0, rc);
    (void)remove(path);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_trace_help_returns_zero);
    RUN_TEST(test_trace_scans_annotations_no_crash);
    RUN_TEST(test_trace_no_annotations_no_crash);
    RUN_TEST(test_trace_gaps_flag_no_crash);
    RUN_TEST(test_req_list_no_crash_no_file);
    RUN_TEST(test_req_help_returns_zero);
    RUN_TEST(test_disp_list_no_file_no_crash);
    RUN_TEST(test_disp_add_creates_entry);
    RUN_TEST(test_disp_list_after_add);
    return UNITY_END();
}
