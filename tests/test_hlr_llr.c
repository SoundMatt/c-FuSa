/*
 * Tests for HLR/LLR hierarchical traceability (Feature 1).
 * Exercises cmd_trace --strict-hlr-llr and HLR/LLR validation.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_trace(int argc, char **argv);

#define HLR_TEST_DIR "/tmp/cfusa_hlr_llr_testdir"

void setUp(void)   { (void)mkdir(HLR_TEST_DIR, 0700); }
void tearDown(void) {}

static void write_file(const char *fname, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", HLR_TEST_DIR, fname);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE *f = (fd >= 0) ? fdopen(fd, "w") : NULL;
    if (f) { fputs(content, f); fclose(f); }
    else if (fd >= 0) { close(fd); }
}

static void remove_file(const char *fname)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", HLR_TEST_DIR, fname);
    (void)remove(path);
}

/* ── Feature 1 tests ─────────────────────────────────────────────────────── */

/* --strict-hlr-llr with no HLR/LLR levels → exit 0 + "no hierarchical" message */
//cfusa:req REQ-HLR001
//cfusa:test REQ-HLR001
void test_strict_hlr_llr_no_levels_returns_zero(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"REQ-001\",\"title\":\"Plain requirement\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--strict-hlr-llr", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
    remove_file(".fusa-reqs.json");
}

/* --strict-hlr-llr with well-formed HLR/LLR → exit 0 */
//cfusa:req REQ-HLR002
//cfusa:test REQ-HLR002
void test_strict_hlr_llr_well_formed_returns_zero(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"High-level\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Low-level\",\"level\":\"LLR\","
        " \"parentId\":\"HLR-001\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--strict-hlr-llr", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
    remove_file(".fusa-reqs.json");
}

/* --strict-hlr-llr with orphaned LLR (empty parentId) → exit 1 */
//cfusa:req REQ-HLR002
//cfusa:test REQ-HLR002
void test_strict_hlr_llr_orphaned_llr_returns_one(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"High-level\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Orphan\",\"level\":\"LLR\","
        " \"parentId\":\"\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--strict-hlr-llr", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
    remove_file(".fusa-reqs.json");
}

/* --strict-hlr-llr with LLR referencing nonexistent HLR → exit 1 */
//cfusa:req REQ-HLR002
//cfusa:test REQ-HLR002
void test_strict_hlr_llr_bad_parent_returns_one(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"High-level\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Bad parent\",\"level\":\"LLR\","
        " \"parentId\":\"NONEXISTENT\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--strict-hlr-llr", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
    remove_file(".fusa-reqs.json");
}

/* --strict-hlr-llr with uncovered HLR (no LLR children) → exit 1 */
//cfusa:req REQ-HLR003
//cfusa:test REQ-HLR003
void test_strict_hlr_llr_uncovered_hlr_returns_one(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"Has child\",\"level\":\"HLR\"},"
        "{\"id\":\"HLR-002\",\"title\":\"No child\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Low\",\"level\":\"LLR\","
        " \"parentId\":\"HLR-001\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--strict-hlr-llr", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
    remove_file(".fusa-reqs.json");
}

/* JSON output includes hlrllrSummary when HLR/LLR requirements present */
//cfusa:req REQ-HLR001
//cfusa:test REQ-HLR001
void test_json_output_has_hlrllr_summary(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"High-level\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Low-level\",\"level\":\"LLR\","
        " \"parentId\":\"HLR-001\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--format", "json",
                    "--output", "/tmp/cfusa_hlr_llr_trace.json", NULL};
    int rc = cmd_trace(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    /* Verify the output file contains hlrllrSummary */
    FILE *f = fopen("/tmp/cfusa_hlr_llr_trace.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "hlrllrSummary"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "hlrCount"));
        (void)remove("/tmp/cfusa_hlr_llr_trace.json");
    }
    remove_file(".fusa-reqs.json");
}

/* JSON output includes parentId field for LLR requirements */
//cfusa:req REQ-HLR001
//cfusa:test REQ-HLR001
void test_json_output_has_parent_id(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"High-level\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Low-level\",\"level\":\"LLR\","
        " \"parentId\":\"HLR-001\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--format", "json",
                    "--output", "/tmp/cfusa_hlr_llr_pid.json", NULL};
    int rc = cmd_trace(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_hlr_llr_pid.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "parentId"));
        (void)remove("/tmp/cfusa_hlr_llr_pid.json");
    }
    remove_file(".fusa-reqs.json");
}

/* Text output includes HLR/LLR summary when hierarchy present */
//cfusa:req REQ-HLR001
//cfusa:test REQ-HLR001
void test_text_output_has_hlrllr_line(void)
{
    write_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"HLR-001\",\"title\":\"High-level\",\"level\":\"HLR\"},"
        "{\"id\":\"LLR-001\",\"title\":\"Low-level\",\"level\":\"LLR\","
        " \"parentId\":\"HLR-001\"}"
        "]}");
    char *argv[] = {"cfusa", "--dir", HLR_TEST_DIR,
                    "--format", "text",
                    "--output", "/tmp/cfusa_hlr_llr_text.txt", NULL};
    int rc = cmd_trace(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_hlr_llr_text.txt", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "HLR/LLR"));
        (void)remove("/tmp/cfusa_hlr_llr_text.txt");
    }
    remove_file(".fusa-reqs.json");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_strict_hlr_llr_no_levels_returns_zero);
    RUN_TEST(test_strict_hlr_llr_well_formed_returns_zero);
    RUN_TEST(test_strict_hlr_llr_orphaned_llr_returns_one);
    RUN_TEST(test_strict_hlr_llr_bad_parent_returns_one);
    RUN_TEST(test_strict_hlr_llr_uncovered_hlr_returns_one);
    RUN_TEST(test_json_output_has_hlrllr_summary);
    RUN_TEST(test_json_output_has_parent_id);
    RUN_TEST(test_text_output_has_hlrllr_line);
    return UNITY_END();
}
