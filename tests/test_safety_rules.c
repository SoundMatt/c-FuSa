/*
 * Tests for safety engine rules:
 *   HARA001-005, ISO26262001-003, DUPREQ001, COUP001-003, DISP001, COMP001
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "unity.h"
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"

//cfusa:req REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005 REQ-HARA010
//cfusa:req REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
//cfusa:req REQ-DISP001 REQ-COMP001 REQ-DUPREQ001
//cfusa:test REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005 REQ-HARA010
//cfusa:test REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
//cfusa:test REQ-DISP001 REQ-COMP001 REQ-DUPREQ001

#define SR_DIR "/tmp/cfusa_sr_testdir"

static void write_file(const char *path, const char *body)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    size_t n = strlen(body);
    if (n) { (void)write(fd, body, n); }
    close(fd);
}

static void make_dir(void)
{
    mkdir(SR_DIR, 0700);
}

static void rm_file(const char *name)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", SR_DIR, name);
    remove(path);
}

static void make_file(const char *name, const char *body)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", SR_DIR, name);
    write_file(path, body);
}

void setUp(void)   { make_dir(); }
void tearDown(void) {}

/* ── HARA001 ────────────────────────────────────────────────────────── */

void test_hara001_fires_when_no_file(void)
{
    rm_file(".fusa-hara.json");
    rm_file(".cfusa-hara.json");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    /* Run only HARA001 */
    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.error_count > 0);
    cfusa_report_free(&rpt);
}

void test_hara001_passes_when_file_present(void)
{
    make_file(".fusa-hara.json",
        "{\"schemaVersion\":\"1.14.0\",\"kind\":\"hara\",\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-1\",\"description\":\"Unintended acceleration\","
        "\"situations\":[],\"risk\":{\"severity\":\"S3\",\"exposure\":\"E3\","
        "\"controllability\":\"C2\",\"asil\":\"ASIL-C\"},"
        "\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Prevent unintended acceleration\","
        "\"hazards\":[\"H-1\"],\"asil\":\"ASIL-C\",\"safeState\":\"Engine off\","
        "\"fssrRefs\":[\"REQ-1\"]}]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);
    cfusa_report_free(&rpt);
    rm_file(".fusa-hara.json");
}

/* ── HARA002 ────────────────────────────────────────────────────────── */

void test_hara002_fires_on_incomplete_rating(void)
{
    make_file(".fusa-hara.json",
        "{\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-1\",\"description\":\"Test hazard\","
        "\"risk\":{\"severity\":\"S1\",\"exposure\":\"E2\"},"
        "\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Goal\","
        "\"asil\":\"QM\",\"safeState\":\"Safe\",\"fssrRefs\":[\"REQ-1\"]}]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA002") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.error_count > 0);
    cfusa_report_free(&rpt);
    rm_file(".fusa-hara.json");
}

/* ── HARA003 ────────────────────────────────────────────────────────── */

void test_hara003_fires_when_no_safety_goal(void)
{
    make_file(".fusa-hara.json",
        "{\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-2\",\"description\":\"Test hazard\","
        "\"risk\":{\"severity\":\"S2\",\"exposure\":\"E2\",\"controllability\":\"C2\","
        "\"asil\":\"ASIL-A\"},\"safetyGoals\":[]}],"
        "\"safetyGoals\":[]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA003") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.error_count > 0);
    cfusa_report_free(&rpt);
    rm_file(".fusa-hara.json");
}

/* ── HARA004 ────────────────────────────────────────────────────────── */

void test_hara004_fires_on_tbd_asil(void)
{
    make_file(".fusa-hara.json",
        "{\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-3\",\"description\":\"Test hazard\","
        "\"risk\":{\"severity\":\"S2\",\"exposure\":\"E3\",\"controllability\":\"C2\","
        "\"asil\":\"TBD\"},\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Defined goal\","
        "\"asil\":\"ASIL-B\",\"safeState\":\"Safe\",\"fssrRefs\":[\"REQ-1\"]}]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA004") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    rm_file(".fusa-hara.json");
}

/* ── HARA006 ────────────────────────────────────────────────────────── */

void test_hara006_fires_on_asil_mismatch(void)
{
    /* S3/E4/C2 derives to ASIL-C per ISO 26262-3 Table 4 (3+4+2=9) — stored
     * ASIL-A is wrong and must be caught even though it's a well-formed value
     * (not TBD/empty, so HARA004 alone would not catch it). */
    make_file(".fusa-hara.json",
        "{\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-9\",\"description\":\"Test hazard\","
        "\"risk\":{\"severity\":\"S3\",\"exposure\":\"E4\",\"controllability\":\"C2\","
        "\"asil\":\"ASIL-A\"},\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Goal\","
        "\"asil\":\"ASIL-A\",\"safeState\":\"Safe\",\"fssrRefs\":[\"REQ-1\"]}]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA006") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.error_count > 0);
    cfusa_report_free(&rpt);
    rm_file(".fusa-hara.json");
}

void test_hara006_passes_when_asil_matches(void)
{
    /* S3/E4/C2 correctly stored as ASIL-C (3+4+2=9 → ASIL-C per ISO 26262-3
     * Table 4 additive derivation). */
    make_file(".fusa-hara.json",
        "{\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-10\",\"description\":\"Test hazard\","
        "\"risk\":{\"severity\":\"S3\",\"exposure\":\"E4\",\"controllability\":\"C2\","
        "\"asil\":\"ASIL-C\"},\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Goal\","
        "\"asil\":\"ASIL-C\",\"safeState\":\"Safe\",\"fssrRefs\":[\"REQ-1\"]}]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "HARA006") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);
    cfusa_report_free(&rpt);
    rm_file(".fusa-hara.json");
}

/* ── ISO26262001 ────────────────────────────────────────────────────── */

void test_iso26262001_fires_when_no_report(void)
{
    rm_file("iso26262-gap-report.json");
    rm_file("iso26262.json");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "ISO26262001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.warning_count > 0);
    cfusa_report_free(&rpt);
}

void test_iso26262001_passes_when_report_present(void)
{
    make_file("iso26262-gap-report.json", "{\"kind\":\"iso26262-gap\"}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "ISO26262001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("iso26262-gap-report.json");
}

/* ── DUPREQ001 ──────────────────────────────────────────────────────── */

void test_dupreq001_fires_on_duplicate_id(void)
{
    make_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"REQ-DUP001\",\"title\":\"first\"},"
        "{\"id\":\"REQ-DUP002\",\"title\":\"unique\"},"
        "{\"id\":\"REQ-DUP001\",\"title\":\"second, same id\"}"
        "]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "DUPREQ001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL_INT(1, rpt.error_count);
    TEST_ASSERT_EQUAL_STRING("DUPREQ001", rpt.findings[0].rule_id);
    TEST_ASSERT_TRUE(strstr(rpt.findings[0].fingerprint, "sha256:") == rpt.findings[0].fingerprint);
    cfusa_report_free(&rpt);
    rm_file(".fusa-reqs.json");
}

void test_dupreq001_passes_when_ids_unique(void)
{
    make_file(".fusa-reqs.json",
        "{\"requirements\":["
        "{\"id\":\"REQ-DUP010\",\"title\":\"first\"},"
        "{\"id\":\"REQ-DUP011\",\"title\":\"second\"}"
        "]}");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "DUPREQ001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL_INT(0, rpt.error_count);
    cfusa_report_free(&rpt);
    rm_file(".fusa-reqs.json");
}

/* ── COUP003 ────────────────────────────────────────────────────────── */

void test_coup003_fires_when_no_coupling_report(void)
{
    rm_file("coupling-report.json");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP003") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.info_count > 0);
    cfusa_report_free(&rpt);
}

/* ── DISP001 ────────────────────────────────────────────────────────── */

static int run_disp001(void)
{
    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "DISP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    int n = rpt.warning_count;
    cfusa_report_free(&rpt);
    return n;
}

void test_disp001_fires_for_undispositioned_error(void)
{
    make_file("check-report.json",
        "{\"findings\":[\n"
        "  {\"ruleId\": \"HARA002\", \"severity\": \"error\", \"message\": \"m\"}\n"
        "]}\n");

    TEST_ASSERT_TRUE(run_disp001() > 0);
    rm_file("check-report.json");
}

//cfusa:req REQ-DISP001
//cfusa:test REQ-DISP001
void test_disp001_silent_when_finding_carries_dispositionid(void)
{
    /* mirrors src/report.c print_json(): "dispositionId" is stamped only
     * onto findings cfusa_report_apply_dispositions() actually matched by
     * fingerprint — the one authoritative suppression mechanism. */
    make_file("check-report.json",
        "{\"findings\":[\n"
        "  {\"ruleId\": \"HARA002\", \"severity\": \"error\", \"message\": \"m\","
        "\"dispositionId\": \"DISP-0001\", \"dispositionAction\": \"accept\"}\n"
        "]}\n");

    TEST_ASSERT_EQUAL_INT(0, run_disp001());
    rm_file("check-report.json");
}

//cfusa:req REQ-DISP001
//cfusa:test REQ-DISP001
void test_disp001_not_fooled_by_unrelated_rationale_mentioning_rule_id(void)
{
    /* issue #148: DISP001 used to decide "dispositioned" via a raw
     * strstr() of the rule id over the ENTIRE .fusa-dispositions.json
     * text, so an unrelated disposition whose free-text rationale merely
     * *mentions* the undispositioned rule's id used to silently suppress
     * DISP001 — even though cfusa_report_apply_dispositions() never
     * actually matched (and never would, since rule-only text mentions
     * aren't a fingerprint). The fixed rule no longer reads
     * .fusa-dispositions.json at all, so its mere presence — or its
     * content — cannot affect the outcome. */
    make_file("check-report.json",
        "{\"findings\":[\n"
        "  {\"ruleId\": \"HARA002\", \"severity\": \"error\", \"message\": \"m\"}\n"
        "]}\n");
    make_file(".fusa-dispositions.json",
        "{\"dispositions\":[\n"
        "  {\"id\":\"DISP-0001\",\"rule\":\"COMP001\",\"action\":\"accept\","
        "\"rationale\":\"threshold change related to HARA002 review\"}\n"
        "]}\n");

    TEST_ASSERT_TRUE(run_disp001() > 0);
    rm_file("check-report.json");
    rm_file(".fusa-dispositions.json");
}

/* ── COUP001 / COUP002 ──────────────────────────────────────────────── */

void test_coup001_detects_extern_mutable(void)
{
    make_file("sample.c",
        "extern int g_state;\n"
        "void foo(void) { g_state = 1; }\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    rm_file("sample.c");
}

/* issue #181: a multi-line block comment's continuation lines (a legal,
 * common C style with no leading '*') must not be scanned as code -- the
 * original bare "first char is '/' or '*'" check only recognized the
 * FIRST line of such a comment. */
void test_coup001_ignores_extern_in_block_comment_continuation(void)
{
    make_file("sample2.c",
        "/* This module intentionally has no globals.\n"
        " see also extern char legacy_buf[10]; for context\n"
        " end of comment */\n"
        "void foo(void) { }\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL(0, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("sample2.c");
}

/* issue #181: the match must be anchored to the start of the trimmed
 * line (matching cmd_coupling.c's scan_line()) -- an unanchored
 * strstr() previously matched "extern " text appearing after other
 * real code earlier on the same line too, not just inside comments. */
void test_coup001_ignores_extern_after_other_code_same_line(void)
{
    make_file("sample3.c",
        "int dummy = 0; /* not extern */\n"
        "void foo(void) { (void)dummy; }\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL(0, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("sample3.c");
}

/* issue #182: rule_coup001()'s return value must equal the number of
 * findings it actually added to the report, matching every other
 * rule's run()-returns-finding-count contract in this file. */
void test_coup001_run_return_value_matches_findings_added(void)
{
    make_file("multi_extern.c",
        "extern int g_a;\n"
        "extern int g_b;\n"
        "extern int g_c;\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int rc = 0;
    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP001") == 0) rc = r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL(3, rc);
    TEST_ASSERT_EQUAL(3, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("multi_extern.c");
}

/* issue #182: same contract check for rule_coup002(). */
void test_coup002_run_return_value_matches_findings_added(void)
{
    make_file("multi_fn_ptr.c",
        "void dispatch1(void (*handler)(int), int val) { handler(val); }\n"
        "void dispatch2(void (*handler)(int), int val) { handler(val); }\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int rc = 0;
    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP002") == 0) rc = r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL(2, rc);
    TEST_ASSERT_EQUAL(2, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("multi_fn_ptr.c");
}

void test_coup002_detects_fn_pointer_param(void)
{
    make_file("fn_ptr.c",
        "void dispatch(void (*handler)(int), int val) { handler(val); }\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COUP002") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    rm_file("fn_ptr.c");
}

/* ── COMP001 ────────────────────────────────────────────────────────── */

void test_comp001_detects_complex_function(void)
{
    /* Write a function with V(G) well above 10 */
    make_file("complex.c",
        "int big(int a, int b, int c, int d, int e) {\n"
        "  if (a > 0) {\n"
        "    if (b > 0) {\n"
        "      for (int i = 0; i < c; i++) {\n"
        "        while (d > 0) {\n"
        "          switch (e) {\n"
        "            case 1: d--; break;\n"
        "            case 2: d -= 2; break;\n"
        "            case 3: d -= 3; break;\n"
        "            default: d = 0; break;\n"
        "          }\n"
        "        }\n"
        "      }\n"
        "    } else if (b < 0) {\n"
        "      return -1;\n"
        "    }\n"
        "  }\n"
        "  return (a && b) || (c && d) ? 1 : 0;\n"
        "}\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COMP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_TRUE(rpt.warning_count > 0);
    cfusa_report_free(&rpt);
    rm_file("complex.c");
}

/* issue #182: rule_comp001()'s return value must equal the number of
 * findings it actually added, matching every other rule's
 * run()-returns-finding-count contract in this file. */
void test_comp001_run_return_value_matches_findings_added(void)
{
    /* Two independently-complex functions in one file, each above the
     * default threshold, so COMP001 must add exactly 2 findings. */
    make_file("two_complex.c",
        "int big1(int a, int b, int c, int d, int e) {\n"
        "  if (a > 0) {\n"
        "    if (b > 0) {\n"
        "      for (int i = 0; i < c; i++) {\n"
        "        while (d > 0) {\n"
        "          switch (e) {\n"
        "            case 1: d--; break;\n"
        "            case 2: d -= 2; break;\n"
        "            case 3: d -= 3; break;\n"
        "            default: d = 0; break;\n"
        "          }\n"
        "        }\n"
        "      }\n"
        "    } else if (b < 0) {\n"
        "      return -1;\n"
        "    }\n"
        "  }\n"
        "  return (a && b) || (c && d) ? 1 : 0;\n"
        "}\n"
        "int big2(int a, int b, int c, int d, int e) {\n"
        "  if (a > 0) {\n"
        "    if (b > 0) {\n"
        "      for (int i = 0; i < c; i++) {\n"
        "        while (d > 0) {\n"
        "          switch (e) {\n"
        "            case 1: d--; break;\n"
        "            case 2: d -= 2; break;\n"
        "            case 3: d -= 3; break;\n"
        "            default: d = 0; break;\n"
        "          }\n"
        "        }\n"
        "      }\n"
        "    } else if (b < 0) {\n"
        "      return -1;\n"
        "    }\n"
        "  }\n"
        "  return (a && b) || (c && d) ? 1 : 0;\n"
        "}\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int rc = -1;
    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COMP001") == 0) rc = r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL(2, rc);
    TEST_ASSERT_EQUAL(2, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("two_complex.c");
}

void test_comp001_passes_simple_function(void)
{
    make_file("simple.c",
        "int add(int a, int b) { return a + b; }\n");

    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COMP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    TEST_ASSERT_EQUAL_INT(0, rpt.warning_count);
    cfusa_report_free(&rpt);
    rm_file("simple.c");
}

/* ── COMP001/COMP002: ASIL-scaled threshold via .fusa.json (issue #107) ── */

/* V(G)=5 (1 base + 4 "if" decisions): above ASIL-D's threshold (4), at or
 * below the unscaled default (10) and DAL-D's threshold (20) — a probe
 * that only fires when the ASIL-D threshold is actually the one in
 * effect. */
static void make_vg5_function(void)
{
    make_file("vg5.c",
        "int mid(int a, int b, int c, int d) {\n"
        "  if (a > 0) { return 1; }\n"
        "  if (b > 0) { return 2; }\n"
        "  if (c > 0) { return 3; }\n"
        "  if (d > 0) { return 4; }\n"
        "  return 0;\n"
        "}\n");
}

static int run_comp001_warning_count(void)
{
    cfusa_engine_reset();
    cfusa_safety_register_rules();

    cfusa_config_t cfg; cfusa_config_load(SR_DIR, &cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);

    int count = cfusa_engine_rule_count();
    for (int i = 0; i < count; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->id, "COMP001") == 0) r->run(SR_DIR, &cfg, &rpt);
    }
    int n = rpt.warning_count;
    cfusa_report_free(&rpt);
    return n;
}

//cfusa:req REQ-COMPTHR001
//cfusa:test REQ-COMPTHR001
void test_comp_threshold_default_passes_vg5(void)
{
    /* No .fusa.json -> unscaled default threshold (10) -> V(G)=5 is clean. */
    make_vg5_function();
    TEST_ASSERT_EQUAL_INT(0, run_comp001_warning_count());
    rm_file("vg5.c");
}

//cfusa:req REQ-COMPTHR001
//cfusa:test REQ-COMPTHR001
void test_comp_threshold_iso26262_asil_d_fails_vg5(void)
{
    /* standards[] declares ISO 26262 ASIL-D (threshold 4, same as
     * cfusa comp --asil-d) -> V(G)=5 exceeds it -> warns. Previously this
     * gate only recognized DO-178C DAL tags and would have silently used
     * the unscaled default (10) instead. */
    make_file(".fusa.json",
        "{\"configVersion\":\"1.0\",\"standards\":[\"iso26262:ASIL-D\"]}\n");
    make_vg5_function();
    TEST_ASSERT_TRUE(run_comp001_warning_count() > 0);
    rm_file("vg5.c");
    rm_file(".fusa.json");
}

//cfusa:req REQ-COMPTHR001
//cfusa:test REQ-COMPTHR001
void test_comp_threshold_dal_and_asil_combine_to_stricter(void)
{
    /* Both DO-178C DAL-D (threshold 20, would alone pass V(G)=5) and ISO
     * 26262 ASIL-D (threshold 4) declared together -> the stricter of the
     * two (ASIL-D) must win, not DAL-D silently suppressing it. */
    make_file(".fusa.json",
        "{\"configVersion\":\"1.0\","
        "\"standards\":[\"do178:DAL-D\",\"iso26262:ASIL-D\"]}\n");
    make_vg5_function();
    TEST_ASSERT_TRUE(run_comp001_warning_count() > 0);
    rm_file("vg5.c");
    rm_file(".fusa.json");
}

//cfusa:req REQ-COMPTHR001
//cfusa:test REQ-COMPTHR001
void test_comp_threshold_asil_d_matches_comp_command_asil_d(void)
{
    /* cfusa comp --asil-d already uses threshold 4 (aliased to
     * THRESHOLD_DAL_A) -- this proves check's automatic gate now derives
     * the identical threshold from an ISO 26262 ASIL-D declaration
     * without needing a separate `cfusa comp --asil-d` invocation. */
    make_file(".fusa.json",
        "{\"configVersion\":\"1.0\",\"standards\":[\"iso26262:ASIL-D\"]}\n");
    /* V(G)=4 exactly at the ASIL-D/threshold=4 boundary: COMP001 only
     * warns when complexity strictly exceeds the threshold, so this one
     * function must NOT warn while the vg5 (V(G)=5) case above does. */
    make_file("vg4.c",
        "int lo(int a, int b, int c) {\n"
        "  if (a > 0) { return 1; }\n"
        "  if (b > 0) { return 2; }\n"
        "  if (c > 0) { return 3; }\n"
        "  return 0;\n"
        "}\n");
    TEST_ASSERT_EQUAL_INT(0, run_comp001_warning_count());
    rm_file("vg4.c");
    rm_file(".fusa.json");
}

/* ── Rule count sanity ──────────────────────────────────────────────── */

void test_safety_rules_register_count(void)
{
    cfusa_engine_reset();
    cfusa_safety_register_rules();
    TEST_ASSERT_EQUAL_INT(cfusa_safety_rule_count(), cfusa_engine_rule_count());
    TEST_ASSERT_TRUE(cfusa_engine_rule_count() >= 13);
}

int main(void)
{
    UNITY_BEGIN();
    /* HARA rules */
    RUN_TEST(test_hara001_fires_when_no_file);
    RUN_TEST(test_hara001_passes_when_file_present);
    RUN_TEST(test_hara002_fires_on_incomplete_rating);
    RUN_TEST(test_hara003_fires_when_no_safety_goal);
    RUN_TEST(test_hara004_fires_on_tbd_asil);
    RUN_TEST(test_hara006_fires_on_asil_mismatch);
    RUN_TEST(test_hara006_passes_when_asil_matches);
    /* ISO 26262 rules */
    RUN_TEST(test_iso26262001_fires_when_no_report);
    RUN_TEST(test_iso26262001_passes_when_report_present);
    /* Duplicate requirement id rule */
    RUN_TEST(test_dupreq001_fires_on_duplicate_id);
    RUN_TEST(test_dupreq001_passes_when_ids_unique);
    /* Coupling rules */
    RUN_TEST(test_disp001_fires_for_undispositioned_error);
    RUN_TEST(test_disp001_silent_when_finding_carries_dispositionid);
    RUN_TEST(test_disp001_not_fooled_by_unrelated_rationale_mentioning_rule_id);

    RUN_TEST(test_coup003_fires_when_no_coupling_report);
    RUN_TEST(test_coup001_detects_extern_mutable);
    RUN_TEST(test_coup001_ignores_extern_in_block_comment_continuation);
    RUN_TEST(test_coup001_ignores_extern_after_other_code_same_line);
    RUN_TEST(test_coup001_run_return_value_matches_findings_added);
    RUN_TEST(test_coup002_detects_fn_pointer_param);
    RUN_TEST(test_coup002_run_return_value_matches_findings_added);
    /* Complexity rule */
    RUN_TEST(test_comp001_detects_complex_function);
    RUN_TEST(test_comp001_run_return_value_matches_findings_added);
    RUN_TEST(test_comp001_passes_simple_function);
    RUN_TEST(test_comp_threshold_default_passes_vg5);
    RUN_TEST(test_comp_threshold_iso26262_asil_d_fails_vg5);
    RUN_TEST(test_comp_threshold_dal_and_asil_combine_to_stricter);
    RUN_TEST(test_comp_threshold_asil_d_matches_comp_command_asil_d);
    /* Sanity */
    RUN_TEST(test_safety_rules_register_count);
    return UNITY_END();
}
