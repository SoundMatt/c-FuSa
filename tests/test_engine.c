#include "../vendor/unity/unity.h"
#include "../include/cfusa/engine.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"

/* ---- Test fixtures ---- */

static int dummy_rule_called = 0;

static int dummy_rule_run(const char *dir, const cfusa_config_t *cfg,
                            cfusa_report_t *rpt)
{
    (void)dir; (void)cfg;
    dummy_rule_called++;
    cfusa_report_add(rpt, "DUMMY-001", "test", SEV_INFO,
                     "test.c", 1, "dummy finding");
    return 0;
}

static const cfusa_rule_t dummy_rule = {
    "DUMMY-001", "test", "Dummy rule", "Test rule", "TEST", dummy_rule_run
};

static int dummy_lint_called = 0;

static int dummy_lint_run(const char *dir, const cfusa_config_t *cfg,
                            cfusa_report_t *rpt)
{
    (void)dir; (void)cfg; (void)rpt;
    dummy_lint_called++;
    return 0;
}

static const cfusa_rule_t dummy_lint_rule = {
    "LINT-T001", "lint", "Lint test rule", "Test", NULL, dummy_lint_run
};

/* ---- Tests ---- */

void setUp(void) { cfusa_engine_reset(); }
void tearDown(void) {}

void test_register_and_count(void)
{
    TEST_ASSERT_EQUAL(0, cfusa_engine_rule_count());
    cfusa_engine_register(&dummy_rule);
    TEST_ASSERT_EQUAL(1, cfusa_engine_rule_count());
    cfusa_engine_register(&dummy_lint_rule);
    TEST_ASSERT_EQUAL(2, cfusa_engine_rule_count());
}

void test_run_all_calls_rules(void)
{
    cfusa_engine_register(&dummy_rule);
    dummy_rule_called = 0;

    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    cfusa_engine_run_all(".", &cfg, &rpt);

    TEST_ASSERT_EQUAL(1, dummy_rule_called);
    TEST_ASSERT_EQUAL(1, rpt.count);
    TEST_ASSERT_EQUAL(0, rpt.error_count);
    TEST_ASSERT_EQUAL(0, rpt.warning_count);
    TEST_ASSERT_EQUAL(1, rpt.info_count);
    cfusa_report_free(&rpt);
}

void test_run_category_filters(void)
{
    cfusa_engine_register(&dummy_rule);      /* category: "test" */
    cfusa_engine_register(&dummy_lint_rule); /* category: "lint" */
    dummy_rule_called  = 0;
    dummy_lint_called = 0;

    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    cfusa_engine_run_category("lint", ".", &cfg, &rpt);

    TEST_ASSERT_EQUAL(0, dummy_rule_called);
    TEST_ASSERT_EQUAL(1, dummy_lint_called);
    cfusa_report_free(&rpt);
}

void test_reset_clears_rules(void)
{
    cfusa_engine_register(&dummy_rule);
    TEST_ASSERT_EQUAL(1, cfusa_engine_rule_count());
    cfusa_engine_reset();
    TEST_ASSERT_EQUAL(0, cfusa_engine_rule_count());
}

void test_report_score_perfect(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    double score = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(score >= 99.9);
    cfusa_report_free(&rpt);
}

void test_report_score_with_errors(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_report_add(&rpt,"R001","test",SEV_ERROR,"f.c",1,"error");
    double score = cfusa_report_score(&rpt);
    TEST_ASSERT_TRUE(score < 100.0);
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_register_and_count);
    RUN_TEST(test_run_all_calls_rules);
    RUN_TEST(test_run_category_filters);
    RUN_TEST(test_reset_clears_rules);
    RUN_TEST(test_report_score_perfect);
    RUN_TEST(test_report_score_with_errors);
    return UNITY_END();
}
