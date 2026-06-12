/*
 * Tests for FUSA001-005 project-structure engine rules.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "unity.h"
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"

extern void cfusa_safety_register_rules(void);

#define FR_DIR "/tmp/cfusa_fusa_rules_testdir"

static void fr_mkdirp(const char *path)
{
    char tmp[512]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
    for (char *p = tmp+1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    }
    mkdir(tmp, 0700);
}

static void fr_write(const char *relpath, const char *body)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", FR_DIR, relpath);
    /* recursively create all parent directories */
    char parent[512]; strncpy(parent, path, sizeof(parent)-1);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; fr_mkdirp(parent); }
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return;
    size_t n = strlen(body); if (n) (void)write(fd, body, n);
    close(fd);
}

static void fr_rm(const char *relpath)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", FR_DIR, relpath);
    remove(path);
}

static int fr_count(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

static void run_safety(cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_safety_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_engine_run_all(FR_DIR, &cfg, rpt);
}

void setUp(void)
{
    /* Clean slate then build minimal base (no CI files — FUSA005 tests manage those) */
    (void)system("rm -rf " FR_DIR);
    mkdir(FR_DIR, 0700);
    fr_write(".fusa.json",     "{\"configVersion\":\"1.0\"}\n");
    fr_write("CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    fr_write("LICENSE",        "MIT License\n");
    fr_write("README.md",      "# test\n");
}

void tearDown(void) {}

/* ── FUSA001 ─────────────────────────────────────────────────────────── */

void test_fusa001_fires_when_no_config(void)
{
    fr_rm(".fusa.json");
    fr_rm(".cfusa.json");
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_TRUE(fr_count(&rpt, "FUSA001") > 0);
    cfusa_report_free(&rpt);
}

void test_fusa001_silent_when_config_present(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_EQUAL(0, fr_count(&rpt, "FUSA001"));
    cfusa_report_free(&rpt);
}

/* ── FUSA002 ─────────────────────────────────────────────────────────── */

void test_fusa002_fires_when_no_build_system(void)
{
    fr_rm("CMakeLists.txt");
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_TRUE(fr_count(&rpt, "FUSA002") > 0);
    cfusa_report_free(&rpt);
}

void test_fusa002_silent_with_cmake(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_EQUAL(0, fr_count(&rpt, "FUSA002"));
    cfusa_report_free(&rpt);
}

/* ── FUSA003 ─────────────────────────────────────────────────────────── */

void test_fusa003_fires_when_no_license(void)
{
    fr_rm("LICENSE");
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_TRUE(fr_count(&rpt, "FUSA003") > 0);
    cfusa_report_free(&rpt);
}

void test_fusa003_silent_when_license_present(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_EQUAL(0, fr_count(&rpt, "FUSA003"));
    cfusa_report_free(&rpt);
}

/* ── FUSA004 ─────────────────────────────────────────────────────────── */

void test_fusa004_fires_when_no_readme(void)
{
    fr_rm("README.md");
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_TRUE(fr_count(&rpt, "FUSA004") > 0);
    cfusa_report_free(&rpt);
}

void test_fusa004_silent_when_readme_present(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_EQUAL(0, fr_count(&rpt, "FUSA004"));
    cfusa_report_free(&rpt);
}

/* ── FUSA005 ─────────────────────────────────────────────────────────── */

void test_fusa005_fires_when_no_ci(void)
{
    /* setUp gives a clean dir with no CI config — FUSA005 must fire */
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_TRUE(fr_count(&rpt, "FUSA005") > 0);
    cfusa_report_free(&rpt);
}

void test_fusa005_silent_with_github_actions(void)
{
    fr_write(".github/workflows/ci.yml", "name: CI\n");
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_EQUAL(0, fr_count(&rpt, "FUSA005"));
    cfusa_report_free(&rpt);
}

void test_fusa005_silent_with_gitlab_ci(void)
{
    fr_write(".gitlab-ci.yml", "stages: [build]\n");
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_safety(&rpt);
    TEST_ASSERT_EQUAL(0, fr_count(&rpt, "FUSA005"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_fusa001_fires_when_no_config);
    RUN_TEST(test_fusa001_silent_when_config_present);
    RUN_TEST(test_fusa002_fires_when_no_build_system);
    RUN_TEST(test_fusa002_silent_with_cmake);
    RUN_TEST(test_fusa003_fires_when_no_license);
    RUN_TEST(test_fusa003_silent_when_license_present);
    RUN_TEST(test_fusa004_fires_when_no_readme);
    RUN_TEST(test_fusa004_silent_when_readme_present);
    RUN_TEST(test_fusa005_fires_when_no_ci);
    RUN_TEST(test_fusa005_silent_with_github_actions);
    RUN_TEST(test_fusa005_silent_with_gitlab_ci);
    return UNITY_END();
}
