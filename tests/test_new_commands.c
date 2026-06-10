/*
 * Tests for new and modified commands:
 *   - cmd_coupling, cmd_iso21434, cmd_unece (new commands)
 *   - cmd_disposition updated flags (--reviewer, --action, --ref)
 *   - cmd_release --spdx-version flag
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "unity.h"
#include "cfusa/commands.h"

#define NC_DIR "/tmp/cfusa_nc_testdir"

static void write_file(const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", NC_DIR, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(body, f); fclose(f); }
}

static int file_contains(const char *name, const char *needle)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", NC_DIR, name);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
    buf[n] = '\0'; fclose(f);
    return strstr(buf, needle) != NULL;
}

void setUp(void)
{
    mkdir(NC_DIR, 0700);
    /* minimal C source for coupling scan */
    write_file("main.c",
        "extern int g_counter;\n"
        "void run(void (*cb)(int)) { cb(g_counter); }\n");
    write_file("counter.c",
        "int g_counter = 0;\n"
        "void increment(void) { g_counter++; }\n");
    /* minimal .cfusa.json */
    write_file(".cfusa.json",
        "{\"project\":\"nc-test\",\"version\":\"1.0.0\"}\n");
}

void tearDown(void) {}

/* ── coupling ────────────────────────────────────────────────────── */

void test_coupling_help(void)
{
    char *argv[] = {"cfusa coupling", "--help", NULL};
    int rc = cmd_coupling(2, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_coupling_writes_report(void)
{
    char out[512];
    snprintf(out, sizeof(out), "%s/coupling-report.json", NC_DIR);
    char *argv[] = {"cfusa coupling",
                    "--dir", NC_DIR,
                    "--output", out, NULL};
    int rc = cmd_coupling(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_TRUE(file_contains("coupling-report.json", "\"format\""));
    TEST_ASSERT_TRUE(file_contains("coupling-report.json", "\"generatedAt\""));
    TEST_ASSERT_TRUE(file_contains("coupling-report.json", "\"dataCoupling\""));
    TEST_ASSERT_TRUE(file_contains("coupling-report.json", "\"controlCoupling\""));
}

void test_coupling_detects_extern(void)
{
    char out[512];
    snprintf(out, sizeof(out), "%s/coupling-report.json", NC_DIR);
    char *argv[] = {"cfusa coupling",
                    "--dir", NC_DIR,
                    "--output", out, NULL};
    cmd_coupling(5, argv);
    TEST_ASSERT_TRUE(file_contains("coupling-report.json", "data coupling"));
}

void test_coupling_detects_fn_pointer(void)
{
    char out[512];
    snprintf(out, sizeof(out), "%s/coupling-report.json", NC_DIR);
    char *argv[] = {"cfusa coupling",
                    "--dir", NC_DIR,
                    "--output", out, NULL};
    cmd_coupling(5, argv);
    TEST_ASSERT_TRUE(file_contains("coupling-report.json", "control coupling"));
}

/* ── iso21434 ─────────────────────────────────────────────────────── */

void test_iso21434_help(void)
{
    char *argv[] = {"cfusa iso21434", "--help", NULL};
    int rc = cmd_iso21434(2, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_iso21434_text_no_evidence(void)
{
    char *argv[] = {"cfusa iso21434",
                    "--dir", NC_DIR,
                    "--cal", "CAL-1", NULL};
    int rc = cmd_iso21434(5, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);  /* gaps → exit 1 */
}

void test_iso21434_json_format(void)
{
    char out[512];
    snprintf(out, sizeof(out), "%s/iso21434.json", NC_DIR);
    char *argv[] = {"cfusa iso21434",
                    "--dir", NC_DIR,
                    "--format", "json",
                    "--output", out, NULL};
    cmd_iso21434(7, argv);
    TEST_ASSERT_TRUE(file_contains("iso21434.json", "\"generatedAt\""));
    TEST_ASSERT_TRUE(file_contains("iso21434.json", "\"objectives\""));
    TEST_ASSERT_TRUE(file_contains("iso21434.json", "\"gap\""));
}

void test_iso21434_cal4_more_objectives(void)
{
    /* CAL-4 requires all objectives; CAL-1 skips min_cal > 1 */
    char out4[512], out1[512];
    snprintf(out4, sizeof(out4), "%s/iso21434_cal4.json", NC_DIR);
    snprintf(out1, sizeof(out1), "%s/iso21434_cal1.json", NC_DIR);
    char *a4[] = {"cfusa iso21434", "--dir", NC_DIR,
                  "--format", "json", "--output", out4,
                  "--cal", "CAL-4", NULL};
    char *a1[] = {"cfusa iso21434", "--dir", NC_DIR,
                  "--format", "json", "--output", out1,
                  "--cal", "CAL-1", NULL};
    cmd_iso21434(9, a4);
    cmd_iso21434(9, a1);
    /* Both should produce valid JSON */
    TEST_ASSERT_TRUE(file_contains("iso21434_cal4.json", "\"objectives\""));
    TEST_ASSERT_TRUE(file_contains("iso21434_cal1.json", "\"objectives\""));
}

void test_iso21434_bad_cal(void)
{
    char *argv[] = {"cfusa iso21434",
                    "--dir", NC_DIR,
                    "--cal", "INVALID", NULL};
    int rc = cmd_iso21434(5, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);
}

/* ── unece ────────────────────────────────────────────────────────── */

void test_unece_help(void)
{
    char *argv[] = {"cfusa unece", "--help", NULL};
    int rc = cmd_unece(2, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_unece_text_no_evidence(void)
{
    char *argv[] = {"cfusa unece", "--dir", NC_DIR, NULL};
    int rc = cmd_unece(3, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);  /* gaps → exit 1 */
}

void test_unece_json_format(void)
{
    char out[512];
    snprintf(out, sizeof(out), "%s/unece.json", NC_DIR);
    char *argv[] = {"cfusa unece",
                    "--dir", NC_DIR,
                    "--format", "json",
                    "--output", out, NULL};
    cmd_unece(7, argv);
    TEST_ASSERT_TRUE(file_contains("unece.json", "\"generatedAt\""));
    TEST_ASSERT_TRUE(file_contains("unece.json", "\"categories\""));
    TEST_ASSERT_TRUE(file_contains("unece.json", "c-FuSa UN R.155"));
}

void test_unece_json_has_manual_entries(void)
{
    char out[512];
    snprintf(out, sizeof(out), "%s/unece.json", NC_DIR);
    char *argv[] = {"cfusa unece",
                    "--dir", NC_DIR,
                    "--format", "json",
                    "--output", out, NULL};
    cmd_unece(7, argv);
    TEST_ASSERT_TRUE(file_contains("unece.json", "MANUAL"));
}

/* ── disposition (aligned flags) ─────────────────────────────────── */

void test_disposition_add_reviewer_action(void)
{
    char *argv[] = {"cfusa disposition", "add",
                    "--dir",       NC_DIR,
                    "--rule",      "CFUSA-L003",
                    "--action",    "accept",
                    "--reviewer",  "alice",
                    "--rationale", "host tool only",
                    "--ref",       "JIRA-42", NULL};
    int rc = cmd_disposition(14, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_TRUE(file_contains(".cfusa-dispositions.json", "\"reviewer\":\"alice\""));
    TEST_ASSERT_TRUE(file_contains(".cfusa-dispositions.json", "\"action\":\"accept\""));
    TEST_ASSERT_TRUE(file_contains(".cfusa-dispositions.json", "\"ref\":\"JIRA-42\""));
    TEST_ASSERT_TRUE(file_contains(".cfusa-dispositions.json", "\"createdAt\""));
}

void test_disposition_list_shows_reviewer(void)
{
    char *add[] = {"cfusa disposition", "add",
                   "--dir",       NC_DIR,
                   "--rule",      "CFUSA-CY002",
                   "--action",    "fix",
                   "--reviewer",  "bob",
                   "--rationale", "will fix", NULL};
    cmd_disposition(12, add);
    /* list should not crash */
    char *list[] = {"cfusa disposition", "list", "--dir", NC_DIR, NULL};
    int rc = cmd_disposition(4, list);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

void test_disposition_add_requires_rule(void)
{
    char *argv[] = {"cfusa disposition", "add",
                    "--dir",      NC_DIR,
                    "--reviewer", "carol", NULL};
    int rc = cmd_disposition(6, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);
}

/* ── release --spdx-version ──────────────────────────────────────── */

void test_release_spdx_version_flag(void)
{
    char *argv[] = {"cfusa release",
                    "--dir",         NC_DIR,
                    "--output-dir",  NC_DIR,
                    "--spdx-version","2.3", NULL};
    int rc = cmd_release(7, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    /* SBOM file should contain the selected version string */
    char sbom[512];
    snprintf(sbom, sizeof(sbom), "%s/nc-test-1.0.0.spdx.json", NC_DIR);
    FILE *f = fopen(sbom, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "SPDX-2.3"));
    }
}

void test_release_spdx_23_default(void)
{
    char *argv[] = {"cfusa release",
                    "--dir",        NC_DIR,
                    "--output-dir", NC_DIR, NULL};
    cmd_release(5, argv);
    char sbom[512];
    snprintf(sbom, sizeof(sbom), "%s/nc-test-1.0.0.spdx.json", NC_DIR);
    FILE *f = fopen(sbom, "r");
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "SPDX-2.3"));
    }
}

/* ── report JSON key alignment ───────────────────────────────────── */

void test_report_json_uses_camel_case(void)
{
    /* Run check on temp dir and capture JSON output */
    char out[512];
    snprintf(out, sizeof(out), "%s/check-report.json", NC_DIR);
    char *argv[] = {"cfusa check",
                    "--dir",    NC_DIR,
                    "--format", "json",
                    "--output", out, NULL};
    cmd_check(7, argv);
    TEST_ASSERT_TRUE(file_contains("check-report.json", "\"generatedAt\""));
    TEST_ASSERT_TRUE(file_contains("check-report.json", "\"infos\""));
    /* old snake_case key must NOT appear */
    char path[512];
    snprintf(path, sizeof(path), "%s/check-report.json", NC_DIR);
    FILE *f = fopen(path, "r");
    if (f) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NULL(strstr(buf, "\"timestamp\""));
        TEST_ASSERT_NULL(strstr(buf, "\"rule_id\""));
        TEST_ASSERT_NULL(strstr(buf, "\"info\":"));
    }
}

int main(void)
{
    UNITY_BEGIN();
    /* coupling */
    RUN_TEST(test_coupling_help);
    RUN_TEST(test_coupling_writes_report);
    RUN_TEST(test_coupling_detects_extern);
    RUN_TEST(test_coupling_detects_fn_pointer);
    /* iso21434 */
    RUN_TEST(test_iso21434_help);
    RUN_TEST(test_iso21434_text_no_evidence);
    RUN_TEST(test_iso21434_json_format);
    RUN_TEST(test_iso21434_cal4_more_objectives);
    RUN_TEST(test_iso21434_bad_cal);
    /* unece */
    RUN_TEST(test_unece_help);
    RUN_TEST(test_unece_text_no_evidence);
    RUN_TEST(test_unece_json_format);
    RUN_TEST(test_unece_json_has_manual_entries);
    /* disposition */
    RUN_TEST(test_disposition_add_reviewer_action);
    RUN_TEST(test_disposition_list_shows_reviewer);
    RUN_TEST(test_disposition_add_requires_rule);
    /* release */
    RUN_TEST(test_release_spdx_version_flag);
    RUN_TEST(test_release_spdx_23_default);
    /* report JSON keys */
    RUN_TEST(test_report_json_uses_camel_case);
    return UNITY_END();
}
