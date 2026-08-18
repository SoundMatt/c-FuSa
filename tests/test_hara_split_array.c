/*
 * Regression tests for issue #124: cmd_hara.c's split_array() used to copy
 * each JSON array element into a fixed 512-byte stack buffer and silently
 * drop (skip — count not incremented, nothing logged) any element whose
 * raw text was >=511 bytes. A real hazard/safety-goal object with normal
 * prose description fields, plus the source file's own pretty-print
 * indentation, easily exceeds that — these tests pin the fix: such
 * entries are no longer dropped.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/utils.h"

extern int cmd_hara(int argc, char **argv);

#define HSA_DIR "/tmp/cfusa_hara_splitarray_testdir"

void setUp(void)    { (void)mkdir(HSA_DIR, 0700); }
void tearDown(void) {}

/* Writes a .fusa-hara.json whose single hazard object's raw JSON text is
 * deliberately >=511 bytes (a long "description" field), then runs
 * `cfusa hara show` and returns its text output. */
static void write_oversized_hazard_doc(void)
{
    (void)mkdir(HSA_DIR, 0700);
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-hara.json", HSA_DIR);

    /* 600 'x' characters — pushes the hazard object's raw length past the
     * old 511-byte cap even before accounting for the surrounding keys. */
    char padding[601];
    memset(padding, 'x', sizeof(padding) - 1);
    padding[sizeof(padding) - 1] = '\0';

    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    if (!f) return;
    fprintf(f,
        "{\n"
        "  \"project\": \"split-array-regression\",\n"
        "  \"standard\": \"ISO 26262\",\n"
        "  \"operationalSituations\": [],\n"
        "  \"hazards\": [\n"
        "    {\"id\": \"H-001\", \"description\": \"%s\", \"source\": \"test\",\n"
        "     \"situations\": [],\n"
        "     \"risk\": {\"severity\": \"S1\", \"exposure\": \"E1\", "
        "\"controllability\": \"C1\", \"asil\": \"QM\"},\n"
        "     \"safetyGoals\": []}\n"
        "  ],\n"
        "  \"safetyGoals\": []\n"
        "}\n",
        padding);
    if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
}

/* issue #124: a hazard whose raw JSON text is >=511 bytes must still be
 * parsed and counted, not silently dropped. */
//cfusa:req REQ-HARA011
//cfusa:test REQ-HARA011
void test_hara_show_does_not_drop_oversized_hazard(void)
{
    write_oversized_hazard_doc();

    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/show_out.txt", HSA_DIR);
    char *argv[] = {"cfusa", "show", "--dir", HSA_DIR,
                     "--output", outpath, NULL};
    cmd_hara(6, argv);

    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        /* Before the fix: "Hazards (0):" and no H-001 line at all. */
        TEST_ASSERT_NOT_NULL(strstr(buf, "Hazards (1):"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "H-001"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "totalHazards:            1"));
        (void)remove(outpath);
    }
}

/* issue #124: same guarantee in JSON output mode. */
//cfusa:req REQ-HARA011
//cfusa:test REQ-HARA011
void test_hara_show_json_does_not_drop_oversized_hazard(void)
{
    write_oversized_hazard_doc();

    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/show_out.json", HSA_DIR);
    char *argv[] = {"cfusa", "show", "--dir", HSA_DIR,
                     "--format", "json", "--output", outpath, NULL};
    cmd_hara(8, argv);

    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"H-001\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"totalHazards\": 1"));
        (void)remove(outpath);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hara_show_does_not_drop_oversized_hazard);
    RUN_TEST(test_hara_show_json_does_not_drop_oversized_hazard);
    return UNITY_END();
}
