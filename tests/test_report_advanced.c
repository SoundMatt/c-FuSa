/*
 * Advanced report tests: add/count/score/format/severity/write.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"

#define RPT_DIR  "/tmp/cfusa_rptadv_testdir"

void setUp(void)   { (void)mkdir(RPT_DIR, 0700); }
void tearDown(void) {}

/* ---- init / free ---- */

//cfusa:req REQ-RPT001
//cfusa:test REQ-RPT001
void test_report_init_zero_count(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    TEST_ASSERT_EQUAL(0, rpt.count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT001
//cfusa:test REQ-RPT001
void test_report_init_zero_errors(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    TEST_ASSERT_EQUAL(0, rpt.error_count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT001
//cfusa:test REQ-RPT001
void test_report_free_twice_no_crash(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_free(&rpt);
    cfusa_report_free(&rpt); /* should not crash */
}

/* ---- add findings ---- */

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_increments_count(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "TEST-001", "lint", SEV_WARNING, "x.c", 1, "msg");
    TEST_ASSERT_EQUAL(1, rpt.count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_error_increments_error_count(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "TEST-001", "cyber", SEV_ERROR, "x.c", 1, "msg");
    TEST_ASSERT_EQUAL(1, rpt.error_count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_warning_increments_warning_count(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "TEST-001", "lint", SEV_WARNING, "x.c", 1, "msg");
    TEST_ASSERT_EQUAL(1, rpt.warning_count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_info_increments_info_count(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "TEST-001", "analyze", SEV_INFO, "x.c", 1, "msg");
    TEST_ASSERT_EQUAL(1, rpt.info_count);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_stores_rule_id(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "CFUSA-L001", "lint", SEV_WARNING, "x.c", 5, "long fn");
    TEST_ASSERT_EQUAL_STRING("CFUSA-L001", rpt.findings[0].rule_id);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_stores_file_and_line(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "TEST-001", "lint", SEV_WARNING, "src/main.c", 42, "msg");
    TEST_ASSERT_EQUAL_STRING("src/main.c", rpt.findings[0].file);
    TEST_ASSERT_EQUAL(42, rpt.findings[0].line);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_report_add_multiple_findings(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "A-001", "lint",    SEV_ERROR,   "a.c", 1, "e");
    cfusa_report_add(&rpt, "A-002", "cyber",   SEV_WARNING, "b.c", 2, "w");
    cfusa_report_add(&rpt, "A-003", "analyze", SEV_INFO,    "c.c", 3, "i");
    TEST_ASSERT_EQUAL(3, rpt.count);
    TEST_ASSERT_EQUAL(1, rpt.error_count);
    TEST_ASSERT_EQUAL(1, rpt.warning_count);
    TEST_ASSERT_EQUAL(1, rpt.info_count);
    cfusa_report_free(&rpt);
}

/* ---- score ---- */

//cfusa:req REQ-RPT003
//cfusa:test REQ-RPT003
void test_score_empty_is_100(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    double s = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(s >= 99.9);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT003
//cfusa:test REQ-RPT003
void test_score_with_errors_is_less_than_100(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "E-001", "cyber", SEV_ERROR, "x.c", 1, "bad");
    double s = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(s < 100.0);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT003
//cfusa:test REQ-RPT003
void test_score_warnings_only_less_than_100(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "W-001", "lint", SEV_WARNING, "x.c", 1, "warn");
    double s = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(s < 100.0);
    cfusa_report_free(&rpt);
}

/* ---- severity_str ---- */

//cfusa:req REQ-RPT004
//cfusa:test REQ-RPT004
void test_severity_str_error(void)
{
    TEST_ASSERT_EQUAL_STRING("ERROR", cfusa_severity_str(SEV_ERROR));
}

//cfusa:req REQ-RPT004
//cfusa:test REQ-RPT004
void test_severity_str_warning(void)
{
    TEST_ASSERT_EQUAL_STRING("WARNING", cfusa_severity_str(SEV_WARNING));
}

//cfusa:req REQ-RPT004
//cfusa:test REQ-RPT004
void test_severity_str_info(void)
{
    TEST_ASSERT_EQUAL_STRING("INFO", cfusa_severity_str(SEV_INFO));
}

/* ---- format_parse ---- */

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_format_parse_json(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_JSON, cfusa_format_parse("json"));
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_format_parse_sarif(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_SARIF, cfusa_format_parse("sarif"));
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_format_parse_text(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_TEXT, cfusa_format_parse("text"));
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_format_parse_html(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_HTML, cfusa_format_parse("html"));
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_format_parse_md(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_MD, cfusa_format_parse("md"));
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_format_parse_unknown_is_text(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_TEXT, cfusa_format_parse("unknown_fmt"));
}

/* ---- print no crash ---- */

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_print_text_no_crash(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "L-001", "lint", SEV_WARNING, "f.c", 1, "msg");
    cfusa_report_print(&rpt, stdout, FMT_TEXT);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_print_json_no_crash(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "C-001", "cyber", SEV_ERROR, "g.c", 2, "err");
    cfusa_report_print(&rpt, stdout, FMT_JSON);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_print_sarif_no_crash(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_report_print(&rpt, stdout, FMT_SARIF);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_print_md_no_crash(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_report_print(&rpt, stdout, FMT_MD);
    cfusa_report_free(&rpt);
}

/* ---- write to file ---- */

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_write_json_creates_file(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/out.json", RPT_DIR);
    (void)remove(path);

    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "L-001", "lint", SEV_WARNING, "x.c", 1, "msg");
    int rc = cfusa_report_write(&rpt, path, FMT_JSON);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);
    cfusa_report_free(&rpt);
}

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_write_text_creates_file(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/out.txt", RPT_DIR);
    (void)remove(path);

    cfusa_report_t rpt; cfusa_report_init(&rpt);
    int rc = cfusa_report_write(&rpt, path, FMT_TEXT);
    TEST_ASSERT_EQUAL(0, rc);
    (void)remove(path);
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_report_init_zero_count);
    RUN_TEST(test_report_init_zero_errors);
    RUN_TEST(test_report_free_twice_no_crash);
    RUN_TEST(test_report_add_increments_count);
    RUN_TEST(test_report_add_error_increments_error_count);
    RUN_TEST(test_report_add_warning_increments_warning_count);
    RUN_TEST(test_report_add_info_increments_info_count);
    RUN_TEST(test_report_add_stores_rule_id);
    RUN_TEST(test_report_add_stores_file_and_line);
    RUN_TEST(test_report_add_multiple_findings);
    RUN_TEST(test_score_empty_is_100);
    RUN_TEST(test_score_with_errors_is_less_than_100);
    RUN_TEST(test_score_warnings_only_less_than_100);
    RUN_TEST(test_severity_str_error);
    RUN_TEST(test_severity_str_warning);
    RUN_TEST(test_severity_str_info);
    RUN_TEST(test_format_parse_json);
    RUN_TEST(test_format_parse_sarif);
    RUN_TEST(test_format_parse_text);
    RUN_TEST(test_format_parse_html);
    RUN_TEST(test_format_parse_md);
    RUN_TEST(test_format_parse_unknown_is_text);
    RUN_TEST(test_print_text_no_crash);
    RUN_TEST(test_print_json_no_crash);
    RUN_TEST(test_print_sarif_no_crash);
    RUN_TEST(test_print_md_no_crash);
    RUN_TEST(test_write_json_creates_file);
    RUN_TEST(test_write_text_creates_file);
    return UNITY_END();
}
