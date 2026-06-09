#include "../vendor/unity/unity.h"
#include "../include/cfusa/config.h"
#include <string.h>

void setUp(void)  {}
void tearDown(void) {}

void test_config_defaults(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);

    TEST_ASSERT_TRUE(strlen(cfg.project) > 0);
    TEST_ASSERT_TRUE(strlen(cfg.version) > 0);
    TEST_ASSERT_TRUE(cfg.max_function_lines > 0);
    TEST_ASSERT_TRUE(cfg.standards_count > 0);
    TEST_ASSERT_TRUE(cfg.exclude_count > 0);
    TEST_ASSERT_TRUE(cfg.ext_count >= 2);
    TEST_ASSERT_EQUAL_INT(0, cfg.strict);
}

void test_config_defaults_extensions(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);

    int has_c = 0, has_h = 0;
    for (int i=0; i<cfg.ext_count; i++) {
        if (!strcmp(cfg.src_exts[i],".c")) has_c=1;
        if (!strcmp(cfg.src_exts[i],".h")) has_h=1;
    }
    TEST_ASSERT_TRUE(has_c);
    TEST_ASSERT_TRUE(has_h);
}

void test_config_save_and_load(void)
{
    cfusa_config_t orig, loaded;
    cfusa_config_defaults(&orig);
    strncpy(orig.project, "test-project", sizeof(orig.project)-1);
    strncpy(orig.version, "2.3.4",        sizeof(orig.version)-1);
    orig.max_function_lines = 75;
    orig.strict = 1;

    /* Save to /tmp */
    int rc = cfusa_config_save("/tmp", &orig);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Load back */
    rc = cfusa_config_load("/tmp", &loaded);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_STRING("test-project", loaded.project);
    TEST_ASSERT_EQUAL_STRING("2.3.4",        loaded.version);
    TEST_ASSERT_EQUAL_INT(75,  loaded.max_function_lines);
    TEST_ASSERT_EQUAL_INT(1,   loaded.strict);
}

void test_config_is_excluded(void)
{
    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);

    TEST_ASSERT_TRUE(cfusa_config_is_excluded(&cfg, "build/main.o"));
    TEST_ASSERT_TRUE(cfusa_config_is_excluded(&cfg, "vendor/lib.c"));
    TEST_ASSERT_FALSE(cfusa_config_is_excluded(&cfg, "src/main.c"));
}

void test_config_missing_file_uses_defaults(void)
{
    cfusa_config_t cfg;
    /* Load from a directory with no .cfusa.json — should use defaults */
    cfusa_config_load("/tmp/no_such_dir_xyz", &cfg);
    TEST_ASSERT_TRUE(strlen(cfg.project) > 0);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_config_defaults);
    RUN_TEST(test_config_defaults_extensions);
    RUN_TEST(test_config_save_and_load);
    RUN_TEST(test_config_is_excluded);
    RUN_TEST(test_config_missing_file_uses_defaults);
    return UNITY_END();
}
