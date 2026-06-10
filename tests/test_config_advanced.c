/*
 * Advanced config tests: defaults, load, save, exclude logic.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/config.h"

#define CFG_DIR "/tmp/cfusa_cfgadv_testdir"

void setUp(void)   { (void)mkdir(CFG_DIR, 0700); }
void tearDown(void) {}

/* ---- defaults ---- */

//cfusa:req REQ-CFG001
//cfusa:test REQ-CFG001
void test_defaults_project_not_empty(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    TEST_ASSERT_TRUE(strlen(cfg.project) > 0);
}

//cfusa:req REQ-CFG001
//cfusa:test REQ-CFG001
void test_defaults_version_not_empty(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    TEST_ASSERT_TRUE(strlen(cfg.version) > 0);
}

//cfusa:req REQ-CFG001
//cfusa:test REQ-CFG001
void test_defaults_max_function_lines_positive(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    TEST_ASSERT_TRUE(cfg.max_function_lines > 0);
}

//cfusa:req REQ-CFG001
//cfusa:test REQ-CFG001
void test_defaults_standards_count_nonnegative(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    TEST_ASSERT_TRUE(cfg.standards_count >= 0);
}

//cfusa:req REQ-CFG001
//cfusa:test REQ-CFG001
void test_defaults_exclude_count_nonnegative(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    TEST_ASSERT_TRUE(cfg.exclude_count >= 0);
}

//cfusa:req REQ-CFG001
//cfusa:test REQ-CFG001
void test_defaults_two_calls_equal(void)
{
    cfusa_config_t a, b;
    cfusa_config_defaults(&a);
    cfusa_config_defaults(&b);
    TEST_ASSERT_EQUAL_INT(a.max_function_lines, b.max_function_lines);
    TEST_ASSERT_EQUAL_INT(a.standards_count, b.standards_count);
}

/* ---- save and load ---- */

//cfusa:req REQ-CFG002
//cfusa:test REQ-CFG002
void test_save_creates_file(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa.json", CFG_DIR);
    (void)remove(path);

    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    int rc = cfusa_config_save(CFG_DIR, &cfg);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);
}

//cfusa:req REQ-CFG002
//cfusa:test REQ-CFG002
void test_save_then_load_roundtrip(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa.json", CFG_DIR);
    (void)remove(path);

    cfusa_config_t orig, loaded;
    cfusa_config_defaults(&orig);
    orig.max_function_lines = 42;

    int rc_save = cfusa_config_save(CFG_DIR, &orig);
    TEST_ASSERT_EQUAL(0, rc_save);

    cfusa_config_defaults(&loaded);
    int rc_load = cfusa_config_load(CFG_DIR, &loaded);
    TEST_ASSERT_EQUAL(0, rc_load);
    TEST_ASSERT_EQUAL_INT(42, loaded.max_function_lines);
    (void)remove(path);
}

//cfusa:req REQ-CFG003
//cfusa:test REQ-CFG003
void test_load_no_file_returns_nonzero(void)
{
    char nodir[] = "/tmp/cfusa_nonexistent_xyz987";
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    int rc = cfusa_config_load(nodir, &cfg);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-CFG004
//cfusa:test REQ-CFG004
void test_load_malformed_json_graceful(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa.json", CFG_DIR);

    FILE *f = fopen(path, "w");
    TEST_ASSERT_NOT_NULL(f);
    if (f) { fputs("{not valid json!!!\n", f); fclose(f); }

    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    /* Should not crash; return value may be error */
    (void)cfusa_config_load(CFG_DIR, &cfg);
    (void)remove(path);
}

/* ---- exclusion ---- */

//cfusa:req REQ-CFG005
//cfusa:test REQ-CFG005
void test_exclude_empty_config_not_excluded(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    cfg.exclude_count = 0;
    int rc = cfusa_config_is_excluded(&cfg, "src/main.c");
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-CFG005
//cfusa:test REQ-CFG005
void test_exclude_matching_dir_excluded(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    cfg.exclude_count = 1;
    strncpy(cfg.exclude_dirs[0], "vendor", sizeof(cfg.exclude_dirs[0]));
    int rc = cfusa_config_is_excluded(&cfg, "vendor/lib.c");
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-CFG005
//cfusa:test REQ-CFG005
void test_exclude_non_matching_dir_not_excluded(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    cfg.exclude_count = 1;
    strncpy(cfg.exclude_dirs[0], "vendor", sizeof(cfg.exclude_dirs[0]));
    int rc = cfusa_config_is_excluded(&cfg, "src/main.c");
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-CFG005
//cfusa:test REQ-CFG005
void test_exclude_multiple_dirs(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    cfg.exclude_count = 2;
    strncpy(cfg.exclude_dirs[0], "vendor", sizeof(cfg.exclude_dirs[0]));
    strncpy(cfg.exclude_dirs[1], "build",  sizeof(cfg.exclude_dirs[1]));

    TEST_ASSERT_TRUE(cfusa_config_is_excluded(&cfg, "build/output.c") != 0);
    TEST_ASSERT_EQUAL(0, cfusa_config_is_excluded(&cfg, "src/foo.c"));
}

//cfusa:req REQ-CFG005
//cfusa:test REQ-CFG005
void test_exclude_nested_path_excluded(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    cfg.exclude_count = 1;
    strncpy(cfg.exclude_dirs[0], "third_party", sizeof(cfg.exclude_dirs[0]));
    int rc = cfusa_config_is_excluded(&cfg, "third_party/json/cJSON.c");
    TEST_ASSERT_TRUE(rc != 0);
}

/* ---- strict flag ---- */

//cfusa:req REQ-CFG006
//cfusa:test REQ-CFG006
void test_strict_defaults_value(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);
    /* strict is 0 or 1 — just verify it's a valid bool value */
    TEST_ASSERT_TRUE(cfg.strict == 0 || cfg.strict == 1);
}

//cfusa:req REQ-CFG006
//cfusa:test REQ-CFG006
void test_strict_roundtrip(void)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa.json", CFG_DIR);
    (void)remove(path);

    cfusa_config_t orig, loaded;
    cfusa_config_defaults(&orig);
    orig.strict = 1;

    int rc_save = cfusa_config_save(CFG_DIR, &orig);
    TEST_ASSERT_EQUAL(0, rc_save);

    cfusa_config_defaults(&loaded);
    int rc_load = cfusa_config_load(CFG_DIR, &loaded);
    TEST_ASSERT_EQUAL(0, rc_load);
    TEST_ASSERT_EQUAL_INT(1, loaded.strict);
    (void)remove(path);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_defaults_project_not_empty);
    RUN_TEST(test_defaults_version_not_empty);
    RUN_TEST(test_defaults_max_function_lines_positive);
    RUN_TEST(test_defaults_standards_count_nonnegative);
    RUN_TEST(test_defaults_exclude_count_nonnegative);
    RUN_TEST(test_defaults_two_calls_equal);
    RUN_TEST(test_save_creates_file);
    RUN_TEST(test_save_then_load_roundtrip);
    RUN_TEST(test_load_no_file_returns_nonzero);
    RUN_TEST(test_load_malformed_json_graceful);
    RUN_TEST(test_exclude_empty_config_not_excluded);
    RUN_TEST(test_exclude_matching_dir_excluded);
    RUN_TEST(test_exclude_non_matching_dir_not_excluded);
    RUN_TEST(test_exclude_multiple_dirs);
    RUN_TEST(test_exclude_nested_path_excluded);
    RUN_TEST(test_strict_defaults_value);
    RUN_TEST(test_strict_roundtrip);
    return UNITY_END();
}
