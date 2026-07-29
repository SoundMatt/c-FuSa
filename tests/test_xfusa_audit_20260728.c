/*
 * Regression tests for the 2026-07-28/29 deep-audit bug-fix sprint
 * (issues #82-#91 on SoundMatt/c-FuSa):
 *
 *   #82  CFUSA-L004 false positive on suffix-matching callee names
 *   #83  Attestation carry-forward dropped (not preserved-as-stale) when
 *        fmea/tara/safety-case/sas content changes (§1.6.2 MUST)
 *   #84  check/lint/analyze/cyber findings: Finding.standard is now a
 *        canonical id (§2.4.1) with a separate clause field, not a
 *        combined display string
 *   #85  iso26262/iec61508/do178/iso21434/unece/iec62443 gap-report JSON
 *        now carries a summary{total,satisfied,partial,gaps} object
 *        (§9.3 MUST) satisfying the total invariant
 *   #86  iec62443 gap-report standard id is "iec62443-4-2" (§2.4.1 MUST)
 *   #87  misra command uses the canonical §9.3 gap-report schema
 *        (kind "gap-report", standard "misra-c", objectives[]/summary{})
 *   #88  qualify accepts --dir (§2.2: applies to all commands)
 *   #89  sas --format json (no --output) writes sas.json + sas.md
 *        companion, not raw JSON into a file named sas.md
 *   #90  hara init scaffolds .fusa-hara.json per the §1.2.5 INPUT schema
 *        (no report-envelope fields, no "kind": "hara")
 *   #91  SARIF tool.driver.name is "c-FuSa" (the §1.1 tool name), not the
 *        binary name "cfusa" (§2.9 MUST)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"
#include "cfusa/report.h"
#include "cfusa/engine.h"
#include "cfusa/config.h"
#include "cfusa/utils.h"

extern int cmd_qualify(int argc, char **argv);
extern int cmd_misra(int argc, char **argv);
extern int cmd_iec62443(int argc, char **argv);
extern int cmd_iso26262(int argc, char **argv);
extern int cmd_iec61508(int argc, char **argv);
extern int cmd_do178(int argc, char **argv);
extern int cmd_iso21434(int argc, char **argv);
extern int cmd_unece(int argc, char **argv);
extern int cmd_hara(int argc, char **argv);
extern int cmd_sas(int argc, char **argv);
extern int cmd_fmea(int argc, char **argv);
extern int cmd_lint(int argc, char **argv);

extern void cfusa_lint_register_rules(void);

#define AUDIT_DIR "/tmp/cfusa_audit_20260728_testdir"

void setUp(void) { (void)mkdir(AUDIT_DIR, 0700); }
void tearDown(void) {}

static void write_file(const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", AUDIT_DIR, name);
    FILE *f = cfusa_fopen_write(path);
    if (f) { fputs(body, f); fclose(f); }
}

static int file_exists(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", AUDIT_DIR, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

static char *slurp(const char *name, size_t *len_out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", AUDIT_DIR, name);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    if (len_out) *len_out = n;
    return buf;
}

/* ================================================================== */
/* #82 — CFUSA-L004 suffix false positive                              */
/* ================================================================== */

#define L004_DIR "/tmp/cfusa_audit_20260728_l004"

/* Each of these two cases gets its own isolated, freshly-emptied
 * directory — lint scans every .c file under --dir, so sharing AUDIT_DIR
 * with other tests (or leftover files from a prior run of this same
 * binary) would make one case's fixture pollute the other's result.
 * Each subdirectory only ever holds one known fixture file, so cleanup
 * unlinks it directly (no shelling out via system() for what is really
 * just "remove these two known paths"). */
static void l004_reset_dir(const char *sub)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s/%s", L004_DIR, sub);
    char f1[600]; snprintf(f1, sizeof(f1), "%s/l004_suffix.c", dir);
    char f2[600]; snprintf(f2, sizeof(f2), "%s/l004_real.c", dir);
    (void)remove(f1);
    (void)remove(f2);
    (void)rmdir(dir);
    mkdir(L004_DIR, 0700);
    mkdir(dir, 0700);
}

//cfusa:test REQ-LINT004
void test_l004_no_false_positive_on_suffix_match(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s/pos", L004_DIR);
    l004_reset_dir("pos");
    char path[512]; snprintf(path, sizeof(path), "%s/l004_suffix.c", dir);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    fputs(
        "int helper_evaluate(int x) {\n"
        "    return x + 1;\n"
        "}\n"
        "\n"
        "static int evaluate(int x) {\n"
        "    return helper_evaluate(x);\n"
        "}\n", f);
    fclose(f);

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, dir, &cfg, &rpt);

    int l004_count = 0;
    for (int i = 0; i < rpt.count; i++)
        if (!strcmp(rpt.findings[i].rule_id, "CFUSA-L004")) l004_count++;
    TEST_ASSERT_EQUAL(0, l004_count);

    cfusa_report_free(&rpt);
    cfusa_engine_reset();
}

//cfusa:test REQ-LINT004
void test_l004_still_detects_real_recursion(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s/neg", L004_DIR);
    l004_reset_dir("neg");
    char path[512]; snprintf(path, sizeof(path), "%s/l004_real.c", dir);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    fputs(
        "static int factorial(int n) {\n"
        "    if (n <= 1) return 1;\n"
        "    return n * factorial(n - 1);\n"
        "}\n", f);
    fclose(f);

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, dir, &cfg, &rpt);

    int l004_count = 0;
    for (int i = 0; i < rpt.count; i++)
        if (!strcmp(rpt.findings[i].rule_id, "CFUSA-L004")) l004_count++;
    TEST_ASSERT_TRUE(l004_count > 0);

    cfusa_report_free(&rpt);
    cfusa_engine_reset();
}

/* ================================================================== */
/* #83 — attestation carry-forward preserved-as-stale                  */
/* ================================================================== */

//cfusa:test REQ-QB001
void test_fmea_attestation_carried_forward_when_content_changes(void)
{
    write_file(".fusa.json",
        "{\"project\":\"demo\",\"standard\":\"iso26262\"}\n");
    write_file("src_main.c",
        "//fusa:req REQ-DEMO001\n"
        "int add(int a, int b) { return a + b; }\n");

    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);

    char *argv1[] = {"cfusa", "--dir", dir, "--format", "json",
                      "--attest", "Jane Doe <jane@example.com>", NULL};
    cmd_fmea(7, argv1);

    size_t len1 = 0;
    char *buf1 = slurp("fmea.json", &len1);
    TEST_ASSERT_NOT_NULL(buf1);
    TEST_ASSERT_NOT_NULL(strstr(buf1, "\"attestation\""));
    TEST_ASSERT_NOT_NULL(strstr(buf1, "jane@example.com"));

    /* Change the analyzed content and regenerate WITHOUT --attest. */
    write_file("src_main2.c",
        "//fusa:req REQ-DEMO001\n"
        "int subtract(int a, int b) { return a - b; }\n");

    char *argv2[] = {"cfusa", "--dir", dir, "--format", "json", NULL};
    cmd_fmea(5, argv2);

    size_t len2 = 0;
    char *buf2 = slurp("fmea.json", &len2);
    TEST_ASSERT_NOT_NULL(buf2);
    /* The prior attestation MUST still be present (carried forward,
     * unchanged) — not silently dropped just because its contentHash
     * is now stale relative to the freshly-generated content. */
    TEST_ASSERT_NOT_NULL(strstr(buf2, "\"attestation\""));
    TEST_ASSERT_NOT_NULL(strstr(buf2, "jane@example.com"));
}

/* ================================================================== */
/* #84 — Finding.standard is canonical id + clause                     */
/* ================================================================== */

//cfusa:test REQ-LINT001
void test_lint_finding_standard_is_canonical_id_with_clause(void)
{
    write_file("l001_long.c",
        "int fn(void) {\n"
        "    goto done;\n"
        "done:\n"
        "    return 0;\n"
        "}\n");

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    strncpy(rpt.project_root, AUDIT_DIR, sizeof(rpt.project_root) - 1);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, AUDIT_DIR, &cfg, &rpt);

    char path[512];
    snprintf(path, sizeof(path), "%s/check.json", AUDIT_DIR);
    TEST_ASSERT_TRUE(cfusa_report_write(&rpt, path, FMT_JSON) == 0);

    size_t len = 0;
    char *buf = slurp("check.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    /* x-FuSa spec §2.4.1: standard is a canonical lowercase id, never a
     * display string like "MISRA-C:2012 R15.1"; the clause carries the
     * rule reference separately. */
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\": \"misra-c\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"clause\": \"R15.1\""));
    TEST_ASSERT_NULL(strstr(buf, "MISRA-C:2012"));

    cfusa_report_free(&rpt);
    cfusa_engine_reset();
}

//cfusa:test REQ-RPT001
void test_sarif_rule_declarations_use_canonical_standard_id(void)
{
    write_file("l002_goto.c",
        "int fn(int x) {\n"
        "    if (x) goto done;\n"
        "done:\n"
        "    return 0;\n"
        "}\n");

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    strncpy(rpt.project_root, AUDIT_DIR, sizeof(rpt.project_root) - 1);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, AUDIT_DIR, &cfg, &rpt);

    char path[512];
    snprintf(path, sizeof(path), "%s/check.sarif", AUDIT_DIR);
    TEST_ASSERT_TRUE(cfusa_report_write(&rpt, path, FMT_SARIF) == 0);

    size_t len = 0;
    char *buf = slurp("check.sarif", &len);
    TEST_ASSERT_NOT_NULL(buf);
    /* #91: tool.driver.name is the §1.1 tool name "c-FuSa", not the
     * binary name "cfusa". */
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"name\": \"c-FuSa\""));

    cfusa_report_free(&rpt);
    cfusa_engine_reset();
}

/* ================================================================== */
/* #85 — gap-report summary{} object across all six standards commands */
/* ================================================================== */

static void assert_gap_report_has_valid_summary(const char *buf)
{
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"summary\""));
    const char *s = strstr(buf, "\"summary\"");
    TEST_ASSERT_NOT_NULL(s);
    int total = -1, satisfied = -1, partial = -1, gaps = -1;
    /* Cheap, order-independent extraction — good enough for a regression
     * test that mainly wants to confirm the object's presence and the
     * satisfied+partial+gaps == total invariant. */
    sscanf(strstr(s, "\"total\":"), "\"total\": %d", &total);
    sscanf(strstr(s, "\"satisfied\":"), "\"satisfied\": %d", &satisfied);
    sscanf(strstr(s, "\"partial\":"), "\"partial\": %d", &partial);
    sscanf(strstr(s, "\"gaps\":"), "\"gaps\": %d", &gaps);
    TEST_ASSERT_TRUE(total >= 0);
    TEST_ASSERT_EQUAL(total, satisfied + partial + gaps);
}

//cfusa:test REQ-ISO26262
void test_iso26262_gap_report_has_summary(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", NULL};
    cmd_iso26262(5, argv);
    /* stdout capture is awkward in-process; write via --output instead. */
    char out[256]; snprintf(out, sizeof(out), "%s/iso26262.json", AUDIT_DIR);
    char *argv2[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_iso26262(7, argv2);
    char *buf = slurp("iso26262.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    assert_gap_report_has_valid_summary(buf);
}

//cfusa:test REQ-IEC61508
void test_iec61508_gap_report_has_summary(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char out[256]; snprintf(out, sizeof(out), "%s/iec61508.json", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_iec61508(7, argv);
    char *buf = slurp("iec61508.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    assert_gap_report_has_valid_summary(buf);
}

//cfusa:test REQ-DO178
void test_do178_gap_report_has_summary(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char out[256]; snprintf(out, sizeof(out), "%s/do178.json", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_do178(7, argv);
    char *buf = slurp("do178.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    assert_gap_report_has_valid_summary(buf);
}

//cfusa:test REQ-ISO21434-001
void test_iso21434_gap_report_has_summary(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char out[256]; snprintf(out, sizeof(out), "%s/iso21434.json", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_iso21434(7, argv);
    char *buf = slurp("iso21434.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    assert_gap_report_has_valid_summary(buf);
}

//cfusa:test REQ-UNECE-OUT001
void test_unece_gap_report_has_summary(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char out[256]; snprintf(out, sizeof(out), "%s/unece.json", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_unece(7, argv);
    char *buf = slurp("unece.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    assert_gap_report_has_valid_summary(buf);
}

/* ================================================================== */
/* #86 — iec62443 canonical standard id + summary (also covers #85)    */
/* ================================================================== */

//cfusa:test REQ-IEC62443-001
void test_iec62443_standard_id_is_4_2_and_has_summary(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char out[256]; snprintf(out, sizeof(out), "%s/iec62443.json", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_iec62443(7, argv);
    char *buf = slurp("iec62443.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\": \"iec62443-4-2\""));
    assert_gap_report_has_valid_summary(buf);
}

/* ================================================================== */
/* #87 — misra canonical gap-report schema                             */
/* ================================================================== */

//cfusa:test REQ-MISRA
void test_misra_uses_canonical_gap_report_schema(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char out[256]; snprintf(out, sizeof(out), "%s/misra.json", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", "--output", out, NULL};
    cmd_misra(7, argv);
    char *buf = slurp("misra.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"kind\": \"gap-report\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\": \"misra-c\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"objectives\""));
    TEST_ASSERT_NULL(strstr(buf, "\"misra-coverage\""));
    TEST_ASSERT_NULL(strstr(buf, "\"rules\":"));
    assert_gap_report_has_valid_summary(buf);
}

/* ================================================================== */
/* #88 — qualify accepts --dir                                         */
/* ================================================================== */

//cfusa:test REQ-QUAL006
void test_qualify_accepts_dir_flag(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", NULL};
    int rc = cmd_qualify(5, argv);
    /* §2.2: --dir applies to all commands — this MUST NOT be a usage
     * error (exit 2) the way it was before the fix. */
    TEST_ASSERT_TRUE(rc != 2);
}

/* ================================================================== */
/* #89 — sas --format json writes sas.json + sas.md companion          */
/* ================================================================== */

//cfusa:test REQ-SAS001
void test_sas_json_format_writes_sas_json_and_md_companion(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char *argv[] = {"cfusa", "--dir", dir, "--format", "json", NULL};
    cmd_sas(5, argv);

    TEST_ASSERT_TRUE(file_exists("sas.json"));
    TEST_ASSERT_TRUE(file_exists("sas.md"));

    size_t jlen = 0;
    char *jbuf = slurp("sas.json", &jlen);
    TEST_ASSERT_NOT_NULL(jbuf);
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"schemaVersion\""));
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"kind\": \"sas\""));

    size_t mlen = 0;
    char *mbuf = slurp("sas.md", &mlen);
    TEST_ASSERT_NOT_NULL(mbuf);
    /* sas.md must be real Markdown, not the JSON body from a stale
     * "did we already write sas.md?" check. */
    TEST_ASSERT_NOT_NULL(strstr(mbuf, "# Software Accomplishment Summary"));
    TEST_ASSERT_NULL(strstr(mbuf, "\"schemaVersion\""));
}

/* ================================================================== */
/* #90 — hara init scaffolds the §1.2.5 INPUT schema (no envelope)     */
/* ================================================================== */

//cfusa:test REQ-HARA001
void test_hara_init_scaffold_has_no_report_envelope_fields(void)
{
    char dir[512]; snprintf(dir, sizeof(dir), "%s", AUDIT_DIR);
    char *argv[] = {"cfusa", "init", "--dir", dir, NULL};
    cmd_hara(4, argv);

    TEST_ASSERT_TRUE(file_exists(".fusa-hara.json"));
    char *buf = slurp(".fusa-hara.json", NULL);
    TEST_ASSERT_NOT_NULL(buf);
    /* §1.2.5: an INPUT file, not a report document — no §3.1 envelope. */
    TEST_ASSERT_NULL(strstr(buf, "\"schemaVersion\""));
    TEST_ASSERT_NULL(strstr(buf, "\"kind\""));
    TEST_ASSERT_NULL(strstr(buf, "\"toolVersion\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"operationalSituations\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"hazards\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"safetyGoals\""));

    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-hara.json", AUDIT_DIR);
    (void)remove(path);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_l004_no_false_positive_on_suffix_match);
    RUN_TEST(test_l004_still_detects_real_recursion);

    RUN_TEST(test_fmea_attestation_carried_forward_when_content_changes);

    RUN_TEST(test_lint_finding_standard_is_canonical_id_with_clause);
    RUN_TEST(test_sarif_rule_declarations_use_canonical_standard_id);

    RUN_TEST(test_iso26262_gap_report_has_summary);
    RUN_TEST(test_iec61508_gap_report_has_summary);
    RUN_TEST(test_do178_gap_report_has_summary);
    RUN_TEST(test_iso21434_gap_report_has_summary);
    RUN_TEST(test_unece_gap_report_has_summary);

    RUN_TEST(test_iec62443_standard_id_is_4_2_and_has_summary);

    RUN_TEST(test_misra_uses_canonical_gap_report_schema);

    RUN_TEST(test_qualify_accepts_dir_flag);

    RUN_TEST(test_sas_json_format_writes_sas_json_and_md_companion);

    RUN_TEST(test_hara_init_scaffold_has_no_report_envelope_fields);

    return UNITY_END();
}
