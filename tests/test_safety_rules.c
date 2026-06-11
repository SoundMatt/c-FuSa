/*
 * Tests for safety engine rules:
 *   HARA001-005, ISO26262001-003, COUP001-003, DISP001, COMP001
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

//cfusa:req REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005
//cfusa:req REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
//cfusa:req REQ-DISP001 REQ-COMP001
//cfusa:test REQ-HARA001 REQ-HARA002 REQ-HARA003 REQ-HARA004 REQ-HARA005
//cfusa:test REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
//cfusa:test REQ-DISP001 REQ-COMP001

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
        "{\"schemaVersion\":\"1.9\",\"kind\":\"hara\","
        "\"hazards\":[{\"id\":\"H-1\",\"severity\":3,"
        "\"exposure\":3,\"controllability\":2,\"asil\":\"ASIL-C\","
        "\"safety_goal\":\"Prevent unintended acceleration\","
        "\"safe_state\":\"Engine off\",\"ftti_ms\":100}]}");

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
        "{\"hazards\":[{\"id\":\"H-1\",\"severity\":0,"
        "\"exposure\":0,\"controllability\":0,\"asil\":\"QM\","
        "\"safety_goal\":\"Goal\",\"safe_state\":\"Safe\"}]}");

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
        "{\"hazards\":[{\"id\":\"H-2\",\"severity\":2,"
        "\"exposure\":2,\"controllability\":2,"
        "\"asil\":\"ASIL-A\","
        "\"safety_goal\":\"[derive safety goal]\","
        "\"safe_state\":\"Safe\"}]}");

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
        "{\"hazards\":[{\"id\":\"H-3\",\"severity\":2,"
        "\"exposure\":3,\"controllability\":2,"
        "\"asil\":\"TBD\","
        "\"safety_goal\":\"Defined goal\","
        "\"safe_state\":\"Safe\"}]}");

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
    /* ISO 26262 rules */
    RUN_TEST(test_iso26262001_fires_when_no_report);
    RUN_TEST(test_iso26262001_passes_when_report_present);
    /* Coupling rules */
    RUN_TEST(test_coup003_fires_when_no_coupling_report);
    RUN_TEST(test_coup001_detects_extern_mutable);
    RUN_TEST(test_coup002_detects_fn_pointer_param);
    /* Complexity rule */
    RUN_TEST(test_comp001_detects_complex_function);
    RUN_TEST(test_comp001_passes_simple_function);
    /* Sanity */
    RUN_TEST(test_safety_rules_register_count);
    return UNITY_END();
}
