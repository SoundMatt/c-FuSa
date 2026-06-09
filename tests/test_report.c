#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void setUp(void)  {}
void tearDown(void) {}

void test_report_init(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    TEST_ASSERT_EQUAL_INT(0, rpt.count);
    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);
    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    TEST_ASSERT_EQUAL_INT(0, rpt.info_count);
    TEST_ASSERT_NOT_NULL(rpt.findings);
    cfusa_report_free(&rpt);
}

void test_report_add_error(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt,"CFUSA-L001","lint",SEV_ERROR,"main.c",10,"too long");
    TEST_ASSERT_EQUAL_INT(1, rpt.count);
    TEST_ASSERT_EQUAL_INT(1, rpt.error_count);
    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    TEST_ASSERT_EQUAL_STRING("CFUSA-L001", rpt.findings[0].rule_id);
    TEST_ASSERT_EQUAL_STRING("main.c",     rpt.findings[0].file);
    TEST_ASSERT_EQUAL_INT(10, rpt.findings[0].line);
    TEST_ASSERT_EQUAL_INT(SEV_ERROR, rpt.findings[0].severity);
    cfusa_report_free(&rpt);
}

void test_report_add_warning(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt,"CFUSA-A001","analyze",SEV_WARNING,"utils.c",42,
                     "unsafe %s", "strcpy");
    TEST_ASSERT_EQUAL_INT(1, rpt.warning_count);
    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);
    TEST_ASSERT_TRUE(strlen(rpt.findings[0].message) > 0);
    cfusa_report_free(&rpt);
}

void test_report_score_100(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    TEST_ASSERT_TRUE(cfusa_report_score(&rpt) >= 99.9);
    cfusa_report_free(&rpt);
}

void test_report_score_decreases_with_errors(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_report_add(&rpt,"R","t",SEV_ERROR,"f",1,"e1");
    cfusa_report_add(&rpt,"R","t",SEV_ERROR,"f",2,"e2");
    double score = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(score < 90.0);
    cfusa_report_free(&rpt);
}

void test_report_severity_str(void)
{
    TEST_ASSERT_EQUAL_STRING("ERROR",   cfusa_severity_str(SEV_ERROR));
    TEST_ASSERT_EQUAL_STRING("WARNING", cfusa_severity_str(SEV_WARNING));
    TEST_ASSERT_EQUAL_STRING("INFO",    cfusa_severity_str(SEV_INFO));
}

void test_format_parse(void)
{
    TEST_ASSERT_EQUAL_INT(FMT_TEXT,  cfusa_format_parse("text"));
    TEST_ASSERT_EQUAL_INT(FMT_JSON,  cfusa_format_parse("json"));
    TEST_ASSERT_EQUAL_INT(FMT_SARIF, cfusa_format_parse("sarif"));
    TEST_ASSERT_EQUAL_INT(FMT_HTML,  cfusa_format_parse("html"));
    TEST_ASSERT_EQUAL_INT(FMT_MD,    cfusa_format_parse("md"));
    TEST_ASSERT_EQUAL_INT(FMT_TEXT,  cfusa_format_parse(NULL));
}

void test_report_json_output(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    strncpy(rpt.project,"proj",sizeof(rpt.project)-1);
    strncpy(rpt.version,"1.0",sizeof(rpt.version)-1);
    cfusa_report_add(&rpt,"CFUSA-L001","lint",SEV_WARNING,"a.c",5,"msg");

    FILE *f = fopen("/tmp/cfusa_test_report.json","w");
    TEST_ASSERT_NOT_NULL(f);
    cfusa_report_print(&rpt, f, FMT_JSON);
    fclose(f);

    /* Read back and verify it contains expected keys */
    size_t len;
    char *json = cfusa_read_file("/tmp/cfusa_test_report.json", &len);
    TEST_ASSERT_NOT_NULL(json);
    TEST_ASSERT_TRUE(cfusa_str_contains(json,"\"project\""));
    TEST_ASSERT_TRUE(cfusa_str_contains(json,"\"findings\""));
    TEST_ASSERT_TRUE(cfusa_str_contains(json,"CFUSA-L001"));
    free(json);
    cfusa_report_free(&rpt);
}

void test_report_sarif_output(void)
{
    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    strncpy(rpt.version,"0.1.0",sizeof(rpt.version)-1);
    cfusa_report_add(&rpt,"CFUSA-A001","analyze",SEV_ERROR,"b.c",3,"boom");

    FILE *f = fopen("/tmp/cfusa_test.sarif","w");
    TEST_ASSERT_NOT_NULL(f);
    cfusa_report_print(&rpt, f, FMT_SARIF);
    fclose(f);

    size_t len;
    char *sarif = cfusa_read_file("/tmp/cfusa_test.sarif", &len);
    TEST_ASSERT_NOT_NULL(sarif);
    TEST_ASSERT_TRUE(cfusa_str_contains(sarif,"\"version\": \"2.1.0\""));
    TEST_ASSERT_TRUE(cfusa_str_contains(sarif,"CFUSA-A001"));
    free(sarif);
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_report_init);
    RUN_TEST(test_report_add_error);
    RUN_TEST(test_report_add_warning);
    RUN_TEST(test_report_score_100);
    RUN_TEST(test_report_score_decreases_with_errors);
    RUN_TEST(test_report_severity_str);
    RUN_TEST(test_format_parse);
    RUN_TEST(test_report_json_output);
    RUN_TEST(test_report_sarif_output);
    return UNITY_END();
}
