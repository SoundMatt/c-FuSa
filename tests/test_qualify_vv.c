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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"qualificationBadge\": \"unqualified\""));
        (void)remove("/tmp/cfusa_qualify_unq.json");
    }
}

/* issue #128: omitting --qualification-method must never produce
 * qualified=true alongside qualificationBadge="unqualified" — the two
 * fields must agree even though self-tests all pass. */
//cfusa:req REQ-QUAL007
//cfusa:test REQ-QUAL007
void test_qualify_json_qualified_false_without_method(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--output", "/tmp/cfusa_qualify_noqual.json", NULL};
    int rc = cmd_qualify(4, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_noqual.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"qualified\": false"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"qualificationBadge\": \"unqualified\""));
        (void)remove("/tmp/cfusa_qualify_noqual.json");
    }
}

/* Declaring --qualification-method (with self-tests passing) makes
 * qualified=true agree with the non-"unqualified" badge. */
//cfusa:req REQ-QUAL007
//cfusa:test REQ-QUAL007
void test_qualify_json_qualified_true_with_method(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--qualification-method", "self",
                    "--output", "/tmp/cfusa_qualify_withqual.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_withqual.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"qualified\": true"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"qualificationBadge\": \"self-qualified\""));
        (void)remove("/tmp/cfusa_qualify_withqual.json");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"independenceStatus\": \"unqualified\""));
        (void)remove("/tmp/cfusa_qualify_unq2.json");
    }
}

/* All V&V independence fields appear in JSON output; achievableAsil is
 * computed (issue #105) rather than accepted as free input — an
 * independent reviewer and independent test executor together yield the
 * ASIL-D ceiling. */
//cfusa:req REQ-VV001
//cfusa:test REQ-VV001
void test_qualify_vv_fields_in_json(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Bob",
                    "--independent-test-executor", "Carol",
                    "--output", "/tmp/cfusa_qualify_vv.json", NULL};
    int rc = cmd_qualify(10, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_vv.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "implementationAuthor"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "independentReviewer"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "independentTestExecutor"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"achievableAsil\": \"ASIL-D\""));
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

/* ---- achievableAsil computation (issue #105) ---- */

static void assert_achievable_asil(char **argv, int argc, const char *expect)
{
    int rc = cmd_qualify(argc, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen("/tmp/cfusa_qualify_vv2.json", "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        char expected_field[64];
        snprintf(expected_field, sizeof(expected_field),
                 "\"achievableAsil\": \"%s\"", expect);
        TEST_ASSERT_NOT_NULL(strstr(buf, expected_field));
        (void)remove("/tmp/cfusa_qualify_vv2.json");
    }
}

/* No independence declared at all -> ASIL-B floor, not empty/unqualified. */
//cfusa:req REQ-VV005
//cfusa:test REQ-VV005
void test_achievable_asil_no_independence_is_floor_b(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--output", "/tmp/cfusa_qualify_vv2.json", NULL};
    assert_achievable_asil(argv, 4, "ASIL-B");
}

/* Independent reviewer only (no independent test executor) -> ASIL-C. */
//cfusa:req REQ-VV005
//cfusa:test REQ-VV005
void test_achievable_asil_reviewer_only_is_c(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Bob",
                    "--output", "/tmp/cfusa_qualify_vv2.json", NULL};
    assert_achievable_asil(argv, 8, "ASIL-C");
}

/* Reviewer sharing the author's identity does not count as independent
 * (self-attestation guard) -> stays at the ASIL-B floor, not ASIL-C/D. */
//cfusa:req REQ-VV005
//cfusa:test REQ-VV005
void test_achievable_asil_self_attested_reviewer_is_floor_b(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Alice",
                    "--independent-test-executor", "Alice",
                    "--output", "/tmp/cfusa_qualify_vv2.json", NULL};
    assert_achievable_asil(argv, 10, "ASIL-B");
}

/* ---- independence gate: --project-asil / --enforce (issue #105) ---- */

/* Declaring project ASIL-D with zero independent review fails the gate. */
//cfusa:req REQ-VV006
//cfusa:test REQ-VV006
void test_independence_gate_fails_asil_d_with_no_independence(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--project-asil", "ASIL-D",
                    "--output", "/tmp/cfusa_qualify_gate1.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(1, rc);
    (void)remove("/tmp/cfusa_qualify_gate1.json");
}

/* Full independence (reviewer + test executor) satisfies an ASIL-D
 * project declaration. */
//cfusa:req REQ-VV006
//cfusa:test REQ-VV006
void test_independence_gate_passes_asil_d_with_full_independence(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--implementation-author", "Alice",
                    "--independent-reviewer", "Bob",
                    "--independent-test-executor", "Carol",
                    "--project-asil", "ASIL-D",
                    "--output", "/tmp/cfusa_qualify_gate2.json", NULL};
    int rc = cmd_qualify(12, argv);
    TEST_ASSERT_EQUAL(0, rc);
    (void)remove("/tmp/cfusa_qualify_gate2.json");
}

/* project-asil QM never gates, regardless of independence. */
//cfusa:req REQ-VV006
//cfusa:test REQ-VV006
void test_independence_gate_off_at_qm(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--project-asil", "QM",
                    "--output", "/tmp/cfusa_qualify_gate3.json", NULL};
    int rc = cmd_qualify(6, argv);
    TEST_ASSERT_EQUAL(0, rc);
    (void)remove("/tmp/cfusa_qualify_gate3.json");
}

/* --enforce warn downgrades an otherwise-failing gate to a non-fatal
 * warning. */
//cfusa:req REQ-VV006
//cfusa:test REQ-VV006
void test_independence_gate_enforce_warn_does_not_fail(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--project-asil", "ASIL-D", "--enforce", "warn",
                    "--output", "/tmp/cfusa_qualify_gate4.json", NULL};
    int rc = cmd_qualify(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
    (void)remove("/tmp/cfusa_qualify_gate4.json");
}

/* --enforce off disables the gate entirely, even at ASIL-D with zero
 * independence. */
//cfusa:req REQ-VV006
//cfusa:test REQ-VV006
void test_independence_gate_enforce_off_disables_gate(void)
{
    char *argv[] = {"cfusa", "qualify",
                    "--project-asil", "ASIL-D", "--enforce", "off",
                    "--output", "/tmp/cfusa_qualify_gate5.json", NULL};
    int rc = cmd_qualify(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
    (void)remove("/tmp/cfusa_qualify_gate5.json");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_qualify_badge_independent);
    RUN_TEST(test_qualify_badge_self);
    RUN_TEST(test_qualify_badge_unqualified);
    RUN_TEST(test_qualify_json_qualified_false_without_method);
    RUN_TEST(test_qualify_json_qualified_true_with_method);
    RUN_TEST(test_qualify_qualifier_and_record_uri_in_json);
    RUN_TEST(test_qualify_independence_independent);
    RUN_TEST(test_qualify_independence_self_reviewed);
    RUN_TEST(test_qualify_independence_unqualified);
    RUN_TEST(test_qualify_vv_fields_in_json);
    RUN_TEST(test_qualify_vv_help_returns_zero);
    RUN_TEST(test_achievable_asil_no_independence_is_floor_b);
    RUN_TEST(test_achievable_asil_reviewer_only_is_c);
    RUN_TEST(test_achievable_asil_self_attested_reviewer_is_floor_b);
    RUN_TEST(test_independence_gate_fails_asil_d_with_no_independence);
    RUN_TEST(test_independence_gate_passes_asil_d_with_full_independence);
    RUN_TEST(test_independence_gate_off_at_qm);
    RUN_TEST(test_independence_gate_enforce_warn_does_not_fail);
    RUN_TEST(test_independence_gate_enforce_off_disables_gate);
    return UNITY_END();
}
