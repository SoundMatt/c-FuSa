/*
 * Tests for tool qualification display (Feature 2) and V&V independence
 * (Feature 4) in cmd_qualify.
 */
#include <stdio.h>
#include <string.h>
#include "../vendor/unity/unity.h"

extern int cmd_qualify(int argc, char **argv);

void setUp(void)    {}
void tearDown(void) {}

/* ── Feature 2: Tool qualification display ────────────────────────────────── */

/* --qualification-method independent → badge "independently-qualified" */
//cfusa:req REQ-QUAL006
//cfusa:test REQ-QUAL006
void test_qualify_badge_independent(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--qualification-method", "independent",
                    "--output", "/tmp/cfusa_qualify_indep.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_indep.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "independently-qualified"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "qualificationBadge"));
        (void)remove("/tmp/cfusa_qualify_indep.json");
    }
}

/* --qualification-method self → badge "self-qualified" */
//cfusa:req REQ-QUAL006
//cfusa:test REQ-QUAL006
void test_qualify_badge_self(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--qualification-method", "self",
                    "--output", "/tmp/cfusa_qualify_self.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_self.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "self-qualified"));
        (void)remove("/tmp/cfusa_qualify_self.json");
    }
}

/* No --qualification-method → badge "unqualified" */
//cfusa:req REQ-QUAL006
//cfusa:test REQ-QUAL006
void test_qualify_badge_unqualified(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--output", "/tmp/cfusa_qualify_unq.json", NULL};
    int rc = cmd_qualify(4, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_unq.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"qualificationBadge\": \"unqualified\""));
        (void)remove("/tmp/cfusa_qualify_unq.json");
    }
}

/* --qualifier and --record-uri appear in JSON output */
//cfusa:req REQ-QUAL003
//cfusa:test REQ-QUAL003
void test_qualify_qualifier_and_record_uri_in_json(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--qualification-method", "independent",
                    "--qualifier", "Safety Labs Inc",
                    "--record-uri", "https://example.com/dossier",
                    "--output", "/tmp/cfusa_qualify_meta.json", NULL};
    int rc = cmd_qualify(10, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_meta.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "qualifierIdentity"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "qualificationRecordUri"));
        (void)remove("/tmp/cfusa_qualify_meta.json");
    }
}

/* ── Feature 4: V&V independence ─────────────────────────────────────────── */

/* Different author/reviewer → independence "independent" */
//cfusa:req REQ-VV004
//cfusa:test REQ-VV004
void test_qualify_independence_independent(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Bob",
                    "--output", "/tmp/cfusa_qualify_indep2.json", NULL};
    int rc = cmd_qualify(8, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_indep2.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"independenceStatus\": \"independent\""));
        (void)remove("/tmp/cfusa_qualify_indep2.json");
    }
}

/* Same author/reviewer → independence "self-reviewed" */
//cfusa:req REQ-VV004
//cfusa:test REQ-VV004
void test_qualify_independence_self_reviewed(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Alice",
                    "--output", "/tmp/cfusa_qualify_self2.json", NULL};
    int rc = cmd_qualify(8, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_self2.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"independenceStatus\": \"self-reviewed\""));
        (void)remove("/tmp/cfusa_qualify_self2.json");
    }
}

/* No reviewer → independence "unqualified" */
//cfusa:req REQ-VV004
//cfusa:test REQ-VV004
void test_qualify_independence_unqualified(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--output", "/tmp/cfusa_qualify_unq2.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_unq2.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"independenceStatus\": \"unqualified\""));
        (void)remove("/tmp/cfusa_qualify_unq2.json");
    }
}

/* All V&V independence fields appear in JSON output */
//cfusa:req REQ-VV001
//cfusa:test REQ-VV001
void test_qualify_vv_fields_in_json(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Bob",
                    "--independent-test-executor", "Carol",
                    "--achievable-asil", "ASIL-D",
                    "--output", "/tmp/cfusa_qualify_vv.json", NULL};
    int rc = cmd_qualify(12, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_vv.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "implementationAuthor"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "independentReviewer"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "independentTestExecutor"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "achievableAsil"));
        (void)remove("/tmp/cfusa_qualify_vv.json");
    }
}

/* --help returns 0 (covers new help text) */
//cfusa:req REQ-QUAL003
//cfusa:test REQ-QUAL003
void test_qualify_vv_help_returns_zero(void)
{
    char *argv[] = {"cfusa", "qualify", "--help", NULL};
    int rc = cmd_qualify(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_qualify_badge_independent);
    RUN_TEST(test_qualify_badge_self);
    RUN_TEST(test_qualify_badge_unqualified);
    RUN_TEST(test_qualify_qualifier_and_record_uri_in_json);
    RUN_TEST(test_qualify_independence_independent);
    RUN_TEST(test_qualify_independence_self_reviewed);
    RUN_TEST(test_qualify_independence_unqualified);
    RUN_TEST(test_qualify_vv_fields_in_json);
    RUN_TEST(test_qualify_vv_help_returns_zero);
    return UNITY_END();
}
