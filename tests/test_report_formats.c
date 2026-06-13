/*
 * Tests for report output formats: text, JSON, SARIF, HTML, Markdown, CSV.
 * Each test writes to a temp file and checks structural content.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"

#define RPT_TMP "/tmp/cfusa_rpt_test.out"

static cfusa_report_t rpt;

void setUp(void)
{
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt, "CFUSA-L001", "lint", SEV_ERROR,   "foo.c", 10, "too long");
    cfusa_report_add(&rpt, "CFUSA-CY001","cyber",SEV_WARNING, "bar.c", 20, "strcpy");
    cfusa_report_add(&rpt, "CFUSA-A002", "analyze",SEV_INFO,  "baz.c",  5, "unchecked");
}

void tearDown(void)
{
    cfusa_report_free(&rpt);
    (void)remove(RPT_TMP);
}

static char *read_tmp(void)
{
    FILE *f = fopen(RPT_TMP, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    (void)fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* ---- JSON format ---- */

//cfusa:req REQ-RPT001
//cfusa:test REQ-RPT001
void test_json_has_findings_key(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_JSON);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "\"findings\"") != NULL);
    free(out);
}

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_json_has_rule_id(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_JSON);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "CFUSA-L001") != NULL);
    free(out);
}

//cfusa:req REQ-RPT003
//cfusa:test REQ-RPT003
void test_json_has_score(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_JSON);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "\"score\"") != NULL);
    free(out);
}

/* ---- SARIF format ---- */

//cfusa:req REQ-RPT004
//cfusa:test REQ-RPT004
void test_sarif_has_version(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_SARIF);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "\"version\"") != NULL);
    free(out);
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_sarif_has_runs(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_SARIF);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "\"runs\"") != NULL);
    free(out);
}

//cfusa:req REQ-RPT005
//cfusa:test REQ-RPT005
void test_sarif_has_results(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_SARIF);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "\"results\"") != NULL);
    free(out);
}

/* ---- CSV format (falls to text; dedicated CSV not yet implemented) ---- */

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_csv_has_rule_id(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_CSV);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "CFUSA-L001") != NULL);
    free(out);
}

/* ---- Text format ---- */

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_text_contains_rule_id(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "CFUSA-L001") != NULL);
    free(out);
}

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_text_contains_filename(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "foo.c") != NULL);
    free(out);
}

/* ---- Markdown format ---- */

//cfusa:req REQ-RPT008
//cfusa:test REQ-RPT008
void test_markdown_has_heading(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_MD);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_TRUE(strstr(out, "#") != NULL);
    free(out);
}

/* ---- Score ---- */

//cfusa:req REQ-RPT003
//cfusa:test REQ-RPT003
void test_score_with_errors_below_100(void)
{
    double score = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(score < 100.0);
    TEST_ASSERT_TRUE(score >= 0.0);
}

//cfusa:req REQ-RPT003
//cfusa:test REQ-RPT003
void test_score_empty_report_is_100(void)
{
    cfusa_report_t empty; cfusa_report_init(&empty);
    TEST_ASSERT_TRUE(cfusa_report_score(&empty) >= 99.9);
    cfusa_report_free(&empty);
}

/* ---- Severity strings ---- */

//cfusa:req REQ-RPT001
//cfusa:test REQ-RPT001
void test_severity_str_error(void)
{
    TEST_ASSERT_EQUAL_STRING("ERROR", cfusa_severity_str(SEV_ERROR));
}

void test_severity_str_warning(void)
{
    TEST_ASSERT_EQUAL_STRING("WARNING", cfusa_severity_str(SEV_WARNING));
}

void test_severity_str_info(void)
{
    TEST_ASSERT_EQUAL_STRING("INFO", cfusa_severity_str(SEV_INFO));
}

/* ---- §4 MAY: endLine / endColumn in location ---- */

//cfusa:req REQ-RPT-SPAN001
//cfusa:test REQ-RPT-SPAN001
void test_json_location_emits_end_line_end_column(void)
{
    cfusa_report_t rpt2;
    cfusa_report_init(&rpt2);
    cfusa_report_add(&rpt2, "CFUSA-L001", "lint", SEV_ERROR, "src/main.c", 10, "too long");
    /* Set span fields directly */
    rpt2.findings[0].end_line   = 12;
    rpt2.findings[0].end_column = 5;
    cfusa_report_write(&rpt2, RPT_TMP, FMT_JSON);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "\"endLine\""));
    TEST_ASSERT_NOT_NULL(strstr(out, "\"endColumn\""));
    free(out);
    cfusa_report_free(&rpt2);
}

//cfusa:req REQ-RPT-SPAN002
//cfusa:test REQ-RPT-SPAN002
void test_json_location_omits_span_when_zero(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_JSON);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    /* Default findings have end_line=0 — span fields must NOT appear */
    TEST_ASSERT_NULL(strstr(out, "\"endLine\""));
    TEST_ASSERT_NULL(strstr(out, "\"endColumn\""));
    free(out);
}

//cfusa:req REQ-RPT-SPAN003
//cfusa:test REQ-RPT-SPAN003
void test_sarif_region_includes_end_line(void)
{
    cfusa_report_t rpt2;
    cfusa_report_init(&rpt2);
    cfusa_report_add(&rpt2, "CFUSA-A002", "analyze", SEV_WARNING, "x.c", 3, "unchecked");
    rpt2.findings[0].end_line   = 5;
    rpt2.findings[0].end_column = 8;
    cfusa_report_write(&rpt2, RPT_TMP, FMT_SARIF);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "\"endLine\""));
    free(out);
    cfusa_report_free(&rpt2);
}

/* ---- §4 category enum conformance ---- */

//cfusa:req REQ-CAT001
//cfusa:test REQ-CAT001
void test_category_cyber_maps_to_security(void)
{
    cfusa_report_t r; cfusa_report_init(&r);
    cfusa_report_add(&r, "CFUSA-CY001", "cyber", SEV_WARNING, "x.c", 1, "test");
    TEST_ASSERT_EQUAL_STRING("security", r.findings[0].category);
    cfusa_report_free(&r);
}

void test_category_analyze_maps_to_safety(void)
{
    cfusa_report_t r; cfusa_report_init(&r);
    cfusa_report_add(&r, "CFUSA-A001", "analyze", SEV_WARNING, "x.c", 1, "test");
    TEST_ASSERT_EQUAL_STRING("safety", r.findings[0].category);
    cfusa_report_free(&r);
}

void test_category_lint_unchanged(void)
{
    cfusa_report_t r; cfusa_report_init(&r);
    cfusa_report_add(&r, "CFUSA-L001", "lint", SEV_WARNING, "x.c", 1, "test");
    TEST_ASSERT_EQUAL_STRING("lint", r.findings[0].category);
    cfusa_report_free(&r);
}

/* ---- Format parse ---- */

//cfusa:req REQ-RPT002
//cfusa:test REQ-RPT002
void test_format_parse_json(void)   { TEST_ASSERT_EQUAL(FMT_JSON, cfusa_format_parse("json")); }
void test_format_parse_sarif(void)  { TEST_ASSERT_EQUAL(FMT_SARIF, cfusa_format_parse("sarif")); }
void test_format_parse_csv(void)    { TEST_ASSERT_EQUAL(FMT_CSV, cfusa_format_parse("csv")); }
void test_format_parse_text(void)   { TEST_ASSERT_EQUAL(FMT_TEXT, cfusa_format_parse("text")); }
void test_format_parse_md(void)     { TEST_ASSERT_EQUAL(FMT_MD, cfusa_format_parse("md")); }
void test_format_parse_unknown(void){ TEST_ASSERT_EQUAL(FMT_TEXT, cfusa_format_parse("xyz")); }

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_json_has_findings_key);
    RUN_TEST(test_json_has_rule_id);
    RUN_TEST(test_json_has_score);
    RUN_TEST(test_sarif_has_version);
    RUN_TEST(test_sarif_has_runs);
    RUN_TEST(test_sarif_has_results);
    RUN_TEST(test_csv_has_rule_id);
    RUN_TEST(test_text_contains_rule_id);
    RUN_TEST(test_text_contains_filename);
    RUN_TEST(test_markdown_has_heading);
    RUN_TEST(test_score_with_errors_below_100);
    RUN_TEST(test_score_empty_report_is_100);
    RUN_TEST(test_severity_str_error);
    RUN_TEST(test_severity_str_warning);
    RUN_TEST(test_severity_str_info);
    RUN_TEST(test_format_parse_json);
    RUN_TEST(test_format_parse_sarif);
    RUN_TEST(test_format_parse_csv);
    RUN_TEST(test_format_parse_text);
    RUN_TEST(test_format_parse_md);
    RUN_TEST(test_format_parse_unknown);
    RUN_TEST(test_json_location_emits_end_line_end_column);
    RUN_TEST(test_json_location_omits_span_when_zero);
    RUN_TEST(test_sarif_region_includes_end_line);
    RUN_TEST(test_category_cyber_maps_to_security);
    RUN_TEST(test_category_analyze_maps_to_safety);
    RUN_TEST(test_category_lint_unchanged);
    return UNITY_END();
}
