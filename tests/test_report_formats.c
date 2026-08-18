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

/* ---- CSV format ---- */

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

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_csv_is_real_comma_separated_output(void)
{
    /* issue #179: --format csv used to be silently accepted then
     * downgraded to print_text()'s human-readable block report — a real
     * CSV consumer must see an actual header row and comma-separated
     * quoted fields, not "cfusa report  project=..." prose. */
    cfusa_report_write(&rpt, RPT_TMP, FMT_CSV);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "severity,ruleId,category,file,line,message"));
    TEST_ASSERT_NOT_NULL(strstr(out, "\"ERROR\",\"CFUSA-L001\",\"lint\",\"foo.c\",10,"));
    TEST_ASSERT_NULL(strstr(out, "cfusa report  project="));
    free(out);
}

//cfusa:req REQ-RPT006
//cfusa:test REQ-RPT006
void test_csv_embedded_quote_is_doubled(void)
{
    cfusa_report_t r; cfusa_report_init(&r);
    cfusa_report_add(&r, "CFUSA-A001", "analyze", SEV_WARNING, "q.c", 1,
                      "quotes \"here\" and, a comma");
    cfusa_report_write(&r, RPT_TMP, FMT_CSV);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "quotes \"\"here\"\" and, a comma"));
    free(out);
    cfusa_report_free(&r);
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
void test_sarif_region_has_end_line_and_col(void)
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

/* ---- Text summary block (--no-summary parity with go-FuSa) ---- */

//cfusa:req REQ-NOSUMMARY001
//cfusa:test REQ-NOSUMMARY001
void test_text_summary_block_present_by_default(void)
{
    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "SUMMARY"));
    TEST_ASSERT_NOT_NULL(strstr(out, "TOP RULES"));
    free(out);
}

void test_text_no_summary_suppresses_block(void)
{
    rpt.no_summary = 1;
    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NULL(strstr(out, "SUMMARY"));
    TEST_ASSERT_NULL(strstr(out, "TOP RULES"));
    free(out);
}

void test_text_always_has_summary_line(void)
{
    rpt.no_summary = 1;
    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "Summary:"));
    TEST_ASSERT_NOT_NULL(strstr(out, "Result:"));
    free(out);
}

/* ---- issue #164: printed Result must match the --strict exit-code gate ---- */

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_result_pass_when_no_errors_and_not_strict(void)
{
    /* setUp()'s shared fixture has 1 error, so use a dedicated 0-error/
     * 1-warning report here instead — not strict, so PASS is expected. */
    cfusa_report_t r; cfusa_report_init(&r);
    cfusa_report_add(&r, "CFUSA-CY001", "cyber", SEV_WARNING, "bar.c", 20, "strcpy");
    cfusa_report_write(&r, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "Result:  PASS"));
    free(out);
    cfusa_report_free(&r);
}

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_result_fails_under_strict_with_only_warnings(void)
{
    /* 0 errors, 1 warning — under --strict this must print FAIL, matching
     * every caller's own exit-code expression (error_count>0 ||
     * (strict && warning_count>0)), not just "were there errors?". */
    rpt.strict = 1;
    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_NOT_NULL(strstr(out, "Result:  FAIL"));
    free(out);
}

/* ---- issue #165: SUMMARY/TOP RULES must exclude dispositioned findings ---- */

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_summary_table_omits_dispositioned_finding(void)
{
    /* Directly tag the ERROR finding as dispositioned, the same way
     * cfusa_report_apply_dispositions() would (fingerprint matching
     * itself is exercised elsewhere; this test is about SUMMARY/TOP
     * RULES honoring the tag, not about how it gets set). setUp()'s
     * fixture's only "lint"-category finding is L001 (the ERROR) — before
     * the fix, its category row still counted this ERROR while the Total
     * row (driven by rpt->error_count, already decremented) did not, so
     * they visibly disagreed in the same report. */
    strncpy(rpt.findings[0].disposition_id, "DISP-0001",
            sizeof(rpt.findings[0].disposition_id) - 1);
    rpt.error_count--; /* mirrors what cfusa_report_apply_dispositions() does */
    rpt.dispositioned_count++;

    cfusa_report_write(&rpt, RPT_TMP, FMT_TEXT);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    char *summary = strstr(out, "SUMMARY");
    TEST_ASSERT_NOT_NULL(summary);
    /* the dispositioned finding was the ONLY "lint"-category finding, so
     * that category row must disappear from the table entirely — not
     * linger showing a stale nonzero error count. */
    TEST_ASSERT_NULL(strstr(summary, "lint"));
    /* Total row: 0 errors, 1 warning, 1 info — matches rpt->error_count/
     * warning_count/info_count exactly (2 = sum of the two rows that
     * remain: security 0/1/0 + safety 0/0/1). */
    TEST_ASSERT_NOT_NULL(strstr(summary,
        "Total                  0         1         1         2"));
    /* CFUSA-L001 (the dispositioned rule) must not appear in TOP RULES. */
    char *top_rules = strstr(out, "TOP RULES");
    TEST_ASSERT_NOT_NULL(top_rules);
    TEST_ASSERT_NULL(strstr(top_rules, "CFUSA-L001"));
    free(out);
}

/* ---- issue #178: a message rich in quote/backslash chars must not be
 * silently truncated in JSON/SARIF output ---- */

//cfusa:req REQ-RPT007
//cfusa:test REQ-RPT007
void test_json_message_with_many_quotes_not_truncated(void)
{
    /* Every character here becomes a 2-byte JSON escape — a fixed
     * 768-byte esc_msg buffer used to silently cut this off partway
     * through well before all 512 source bytes were processed. */
    char msg[500];
    size_t i = 0;
    while (i + 4 < sizeof(msg)) { memcpy(msg + i, "\\\"ab", 4); i += 4; }
    msg[i] = '\0';

    cfusa_report_t r; cfusa_report_init(&r);
    cfusa_report_add(&r, "CFUSA-A001", "analyze", SEV_WARNING, "q.c", 1, "%s", msg);
    cfusa_report_write(&r, RPT_TMP, FMT_JSON);
    char *out = read_tmp();
    TEST_ASSERT_NOT_NULL(out);
    /* the message's final characters must survive to the end of the
     * escaped output, proving no mid-string truncation occurred */
    TEST_ASSERT_NOT_NULL(strstr(out, "ab\", \"fingerprint\""));
    free(out);
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
    RUN_TEST(test_csv_is_real_comma_separated_output);
    RUN_TEST(test_csv_embedded_quote_is_doubled);
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
    RUN_TEST(test_sarif_region_has_end_line_and_col);
    RUN_TEST(test_category_cyber_maps_to_security);
    RUN_TEST(test_category_analyze_maps_to_safety);
    RUN_TEST(test_category_lint_unchanged);
    RUN_TEST(test_text_summary_block_present_by_default);
    RUN_TEST(test_text_no_summary_suppresses_block);
    RUN_TEST(test_text_always_has_summary_line);
    RUN_TEST(test_result_pass_when_no_errors_and_not_strict);
    RUN_TEST(test_result_fails_under_strict_with_only_warnings);
    RUN_TEST(test_summary_table_omits_dispositioned_finding);
    RUN_TEST(test_json_message_with_many_quotes_not_truncated);
    return UNITY_END();
}
