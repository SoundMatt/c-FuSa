/*
 * Tests for the shared DAL/ASIL ranking and gate-severity helper
 * (include/cfusa/severity.h, c-FuSa issue #104).
 */
#include <string.h>
#include "../vendor/unity/unity.h"
#include "cfusa/severity.h"

void setUp(void) {}
void tearDown(void) {}

/* ---- cfusa_dal_rank ---- */

//cfusa:req REQ-SEV001
//cfusa:test REQ-SEV001
void test_dal_rank_valid(void)
{
    TEST_ASSERT_EQUAL(4, cfusa_dal_rank("DAL-A"));
    TEST_ASSERT_EQUAL(3, cfusa_dal_rank("DAL-B"));
    TEST_ASSERT_EQUAL(2, cfusa_dal_rank("DAL-C"));
    TEST_ASSERT_EQUAL(1, cfusa_dal_rank("DAL-D"));
    TEST_ASSERT_EQUAL(0, cfusa_dal_rank("DAL-E"));
}

//cfusa:req REQ-SEV001
//cfusa:test REQ-SEV001
void test_dal_rank_case_insensitive(void)
{
    TEST_ASSERT_EQUAL(4, cfusa_dal_rank("dal-a"));
    TEST_ASSERT_EQUAL(4, cfusa_dal_rank("Dal-A"));
}

//cfusa:req REQ-SEV001
//cfusa:test REQ-SEV001
void test_dal_rank_invalid(void)
{
    TEST_ASSERT_EQUAL(-1, cfusa_dal_rank(NULL));
    TEST_ASSERT_EQUAL(-1, cfusa_dal_rank(""));
    TEST_ASSERT_EQUAL(-1, cfusa_dal_rank("DAL-F"));
    TEST_ASSERT_EQUAL(-1, cfusa_dal_rank("ASIL-D"));
}

/* ---- cfusa_asil_rank ---- */

//cfusa:req REQ-SEV002
//cfusa:test REQ-SEV002
void test_asil_rank_valid(void)
{
    TEST_ASSERT_EQUAL(0, cfusa_asil_rank("QM"));
    TEST_ASSERT_EQUAL(1, cfusa_asil_rank("ASIL-A"));
    TEST_ASSERT_EQUAL(2, cfusa_asil_rank("ASIL-B"));
    TEST_ASSERT_EQUAL(3, cfusa_asil_rank("ASIL-C"));
    TEST_ASSERT_EQUAL(4, cfusa_asil_rank("ASIL-D"));
}

//cfusa:req REQ-SEV002
//cfusa:test REQ-SEV002
void test_asil_rank_case_insensitive(void)
{
    TEST_ASSERT_EQUAL(4, cfusa_asil_rank("asil-d"));
    TEST_ASSERT_EQUAL(0, cfusa_asil_rank("qm"));
}

//cfusa:req REQ-SEV002
//cfusa:test REQ-SEV002
void test_asil_rank_invalid(void)
{
    TEST_ASSERT_EQUAL(-1, cfusa_asil_rank(NULL));
    TEST_ASSERT_EQUAL(-1, cfusa_asil_rank(""));
    TEST_ASSERT_EQUAL(-1, cfusa_asil_rank("ASIL-E"));
    TEST_ASSERT_EQUAL(-1, cfusa_asil_rank("DAL-A"));
}

/* ---- cfusa_required_severity: explicit --enforce overrides ---- */

//cfusa:req REQ-SEV003
//cfusa:test REQ-SEV003
void test_required_severity_explicit_off(void)
{
    cfusa_severity_t sev;
    /* "off" wins even against the most stringent declared level. */
    TEST_ASSERT_EQUAL(0, cfusa_required_severity("off", "DAL-A", "ASIL-D", &sev));
}

//cfusa:req REQ-SEV003
//cfusa:test REQ-SEV003
void test_required_severity_explicit_error(void)
{
    cfusa_severity_t sev;
    /* "error" wins even against QM/no declaration at all. */
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("error", NULL, "QM", &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
}

//cfusa:req REQ-SEV003
//cfusa:test REQ-SEV003
void test_required_severity_explicit_warn(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("warn", "DAL-A", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_WARNING, sev);
}

/* ---- cfusa_required_severity: "auto" derivation from DAL ---- */

//cfusa:req REQ-SEV004
//cfusa:test REQ-SEV004
void test_required_severity_auto_dal_error_tier(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", "DAL-A", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", "DAL-B", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
}

//cfusa:req REQ-SEV004
//cfusa:test REQ-SEV004
void test_required_severity_auto_dal_warn_tier(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", "DAL-C", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_WARNING, sev);
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", "DAL-D", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_WARNING, sev);
}

//cfusa:req REQ-SEV004
//cfusa:test REQ-SEV004
void test_required_severity_auto_dal_off_tier(void)
{
    cfusa_severity_t sev;
    /* DAL-E ("no safety effect") -> gate off, not a low-severity warning. */
    TEST_ASSERT_EQUAL(0, cfusa_required_severity("auto", "DAL-E", NULL, &sev));
}

/* ---- cfusa_required_severity: "auto" derivation from ASIL ---- */

//cfusa:req REQ-SEV005
//cfusa:test REQ-SEV005
void test_required_severity_auto_asil_error_tier(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", NULL, "ASIL-D", &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", NULL, "ASIL-C", &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
}

//cfusa:req REQ-SEV005
//cfusa:test REQ-SEV005
void test_required_severity_auto_asil_warn_tier(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", NULL, "ASIL-B", &sev));
    TEST_ASSERT_EQUAL(SEV_WARNING, sev);
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", NULL, "ASIL-A", &sev));
    TEST_ASSERT_EQUAL(SEV_WARNING, sev);
}

//cfusa:req REQ-SEV005
//cfusa:test REQ-SEV005
void test_required_severity_auto_asil_off_tier(void)
{
    cfusa_severity_t sev;
    /* QM -> gate off, not a low-severity warning. */
    TEST_ASSERT_EQUAL(0, cfusa_required_severity("auto", NULL, "QM", &sev));
}

/* ---- cfusa_required_severity: neither declared, NULL enforce, both declared ---- */

//cfusa:req REQ-SEV006
//cfusa:test REQ-SEV006
void test_required_severity_neither_declared_is_off(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(0, cfusa_required_severity("auto", NULL, NULL, &sev));
    TEST_ASSERT_EQUAL(0, cfusa_required_severity(NULL, NULL, NULL, &sev));
}

//cfusa:req REQ-SEV006
//cfusa:test REQ-SEV006
void test_required_severity_null_enforce_defaults_to_auto(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity(NULL, "DAL-A", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
}

//cfusa:req REQ-SEV006
//cfusa:test REQ-SEV006
void test_required_severity_unrecognized_enforce_defaults_to_auto(void)
{
    cfusa_severity_t sev;
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("bogus", "DAL-A", NULL, &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
}

//cfusa:req REQ-SEV006
//cfusa:test REQ-SEV006
void test_required_severity_both_declared_stricter_wins(void)
{
    cfusa_severity_t sev;
    /* DAL-D (warn tier) but ASIL-D (error tier) -> the more stringent of
     * the two (ASIL-D) determines the outcome. */
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", "DAL-D", "ASIL-D", &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
    /* And the reverse: DAL-A (error tier) with ASIL-A (warn tier). */
    TEST_ASSERT_EQUAL(1, cfusa_required_severity("auto", "DAL-A", "ASIL-A", &sev));
    TEST_ASSERT_EQUAL(SEV_ERROR, sev);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_dal_rank_valid);
    RUN_TEST(test_dal_rank_case_insensitive);
    RUN_TEST(test_dal_rank_invalid);
    RUN_TEST(test_asil_rank_valid);
    RUN_TEST(test_asil_rank_case_insensitive);
    RUN_TEST(test_asil_rank_invalid);
    RUN_TEST(test_required_severity_explicit_off);
    RUN_TEST(test_required_severity_explicit_error);
    RUN_TEST(test_required_severity_explicit_warn);
    RUN_TEST(test_required_severity_auto_dal_error_tier);
    RUN_TEST(test_required_severity_auto_dal_warn_tier);
    RUN_TEST(test_required_severity_auto_dal_off_tier);
    RUN_TEST(test_required_severity_auto_asil_error_tier);
    RUN_TEST(test_required_severity_auto_asil_warn_tier);
    RUN_TEST(test_required_severity_auto_asil_off_tier);
    RUN_TEST(test_required_severity_neither_declared_is_off);
    RUN_TEST(test_required_severity_null_enforce_defaults_to_auto);
    RUN_TEST(test_required_severity_unrecognized_enforce_defaults_to_auto);
    RUN_TEST(test_required_severity_both_declared_stricter_wins);
    return UNITY_END();
}
