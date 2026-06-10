/*
 * Coverage-focused tests for cmd_req and cmd_trace.
 * Exercises JSON/MD/text output, req-coverage gate, sec-tested gate,
 * export/import subcommands, filter args, and annotation fallback paths.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

extern int cmd_req(int argc, char **argv);
extern int cmd_trace(int argc, char **argv);

#define RTC_DIR "/tmp/cfusa_rtc_testdir"

static void write_file(const char *fname, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", RTC_DIR, fname);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

static void rm_file(const char *fname)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", RTC_DIR, fname);
    remove(path);
}

void setUp(void)
{
    mkdir(RTC_DIR, 0700);
    write_file(".cfusa-reqs.json",
        "{\n"
        "  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"The tool shall do alpha.\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"The tool shall do beta.\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n"
        "}\n");
    write_file("impl.c",
        "//cfusa:req REQ-A001\n"
        "void alpha(void) {}\n"
        "//cfusa:req REQ-A002\n"
        "void beta(void) {}\n");
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\n"
        "void test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\n"
        "void test_beta(void) {}\n");
}

void tearDown(void) {}

/* ============================================================
 * cmd_trace — text format with reqs (exercises matrix output)
 * ============================================================ */

//cfusa:req REQ-TRA003
//cfusa:test REQ-TRA003
void test_trace_text_with_reqs(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, NULL};
    int rc = cmd_trace(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA004
//cfusa:test REQ-TRA004
void test_trace_json_format(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--format", "json", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA005
//cfusa:test REQ-TRA005
void test_trace_md_format(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--format", "md", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA006
//cfusa:test REQ-TRA006
void test_trace_output_to_file(void)
{
    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/trace_out.txt", RTC_DIR);
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--output", outpath, NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    remove(outpath);
}

//cfusa:req REQ-TRA007
//cfusa:test REQ-TRA007
void test_trace_req_coverage_gate_pass(void)
{
    /* Both reqs are traced — 100% >= 80% → pass */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "80", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA008
//cfusa:test REQ-TRA008
void test_trace_req_coverage_gate_fail(void)
{
    /* Remove impl so req-coverage drops to 0% < 100% → fail */
    rm_file("impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "100", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_TRUE(rc != 0);
    /* Restore */
    write_file("impl.c",
        "//cfusa:req REQ-A001\nvoid alpha(void) {}\n"
        "//cfusa:req REQ-A002\nvoid beta(void) {}\n");
}

//cfusa:req REQ-TRA009
//cfusa:test REQ-TRA009
void test_trace_sec_tested_gate_pass(void)
{
    /* Both reqs are tested — 100% >= 80% → pass */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--sec-tested", "80", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA010
//cfusa:test REQ-TRA010
void test_trace_sec_tested_gate_fail(void)
{
    /* Remove test file so sec-tested drops to 0% < 100% → fail */
    rm_file("test_impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--sec-tested", "100", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_TRUE(rc != 0);
    /* Restore */
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
}

//cfusa:req REQ-TRA011
//cfusa:test REQ-TRA011
void test_trace_gaps_with_reqs(void)
{
    /* Both reqs tested → 0 gaps → rc = 0 */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--gaps", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA012
//cfusa:test REQ-TRA012
void test_trace_gaps_with_untested(void)
{
    rm_file("test_impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--gaps", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_TRUE(rc != 0);
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
}

//cfusa:req REQ-TRA013
//cfusa:test REQ-TRA013
void test_trace_no_legacy_flag(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--no-legacy", NULL};
    int rc = cmd_trace(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-TRA014
//cfusa:test REQ-TRA014
void test_trace_md_no_reqs(void)
{
    /* Remove reqs file — falls through to annotation-only path */
    rm_file(".cfusa-reqs.json");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--format", "md", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
    write_file(".cfusa-reqs.json",
        "{\n  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"The tool shall do alpha.\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"The tool shall do beta.\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n}\n");
}

//cfusa:req REQ-TRA015
//cfusa:test REQ-TRA015
void test_trace_json_no_reqs(void)
{
    rm_file(".cfusa-reqs.json");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--format", "json", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
    write_file(".cfusa-reqs.json",
        "{\n  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"The tool shall do alpha.\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"The tool shall do beta.\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n}\n");
}

/* ============================================================
 * cmd_req — various paths
 * ============================================================ */

//cfusa:req REQ-REQ001
//cfusa:test REQ-REQ001
void test_req_list_with_reqs_present(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, NULL};
    int rc = cmd_req(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-REQ002
//cfusa:test REQ-REQ002
void test_req_filter_known_id(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "REQ-A001", NULL};
    int rc = cmd_req(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-REQ003
//cfusa:test REQ-REQ003
void test_req_filter_unknown_id(void)
{
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "REQ-ZZNOTFOUND", NULL};
    int rc = cmd_req(4, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-REQ004
//cfusa:test REQ-REQ004
void test_req_annotations_fallback(void)
{
    rm_file(".cfusa-reqs.json");
    /* annotated files present — falls through to annotation list */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, NULL};
    int rc = cmd_req(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
    write_file(".cfusa-reqs.json",
        "{\n  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"The tool shall do alpha.\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"The tool shall do beta.\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n}\n");
}

//cfusa:req REQ-REQ005
//cfusa:test REQ-REQ005
void test_req_no_reqs_no_annotations(void)
{
    rm_file(".cfusa-reqs.json");
    rm_file("impl.c");
    rm_file("test_impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, NULL};
    int rc = cmd_req(3, argv);
    TEST_ASSERT_TRUE(rc != 0);
    /* Restore all files */
    write_file(".cfusa-reqs.json",
        "{\n  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"The tool shall do alpha.\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"The tool shall do beta.\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n}\n");
    write_file("impl.c",
        "//cfusa:req REQ-A001\nvoid alpha(void) {}\n"
        "//cfusa:req REQ-A002\nvoid beta(void) {}\n");
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
}

//cfusa:req REQ-REQ006
//cfusa:test REQ-REQ006
void test_req_export_to_stdout(void)
{
    char *argv[] = {"cfusa", "export", "--dir", RTC_DIR, NULL};
    int rc = cmd_req(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-REQ007
//cfusa:test REQ-REQ007
void test_req_export_to_file(void)
{
    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/reqs.csv", RTC_DIR);
    char *argv[] = {"cfusa", "export", "--dir", RTC_DIR, "--output", outpath, NULL};
    int rc = cmd_req(6, argv);
    TEST_ASSERT_EQUAL(0, rc);
    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    /* Leave CSV for import test */
}

//cfusa:req REQ-REQ008
//cfusa:test REQ-REQ008
void test_req_import_no_csv_arg(void)
{
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR, NULL};
    int rc = cmd_req(4, argv);
    TEST_ASSERT_TRUE(rc != 0);
}

//cfusa:req REQ-REQ009
//cfusa:test REQ-REQ009
void test_req_import_valid_csv(void)
{
    /* Write a small CSV to import */
    char csvpath[256];
    snprintf(csvpath, sizeof(csvpath), "%s/import.csv", RTC_DIR);
    FILE *f = fopen(csvpath, "w");
    if (f) {
        fputs("id,title,text,standard,level\n", f);
        fputs("\"REQ-IMP001\",\"Import test\",\"The tool shall import.\",\"CERT-C\",\"SHALL\"\n", f);
        fclose(f);
    }
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR, csvpath, NULL};
    int rc = cmd_req(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
    remove(csvpath);
}

//cfusa:req REQ-REQ010
//cfusa:test REQ-REQ010
void test_req_export_no_reqs_file(void)
{
    rm_file(".cfusa-reqs.json");
    char *argv[] = {"cfusa", "export", "--dir", RTC_DIR, NULL};
    int rc = cmd_req(4, argv);
    /* No reqs found — should not crash */
    (void)rc;
    write_file(".cfusa-reqs.json",
        "{\n  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"The tool shall do alpha.\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"The tool shall do beta.\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n}\n");
}

extern int cmd_coverage(int argc, char **argv);

//cfusa:req REQ-REQ011
//cfusa:test REQ-REQ011
void test_req_import_codebeamer_csv(void)
{
    char csvpath[256];
    snprintf(csvpath, sizeof(csvpath), "%s/cb_import.csv", RTC_DIR);
    FILE *f = fopen(csvpath, "w");
    if (f) {
        fputs("\"tracker item id\",\"summary\",\"description\",\"category\"\n", f);
        fputs("\"101\",\"CB summary\",\"CB description\",\"Software\"\n", f);
        fclose(f);
    }
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "codebeamer", csvpath, NULL};
    int rc = cmd_req(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    /* verify the id was prefixed CB- */
    char reqs_path[256];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);
    FILE *jf = fopen(reqs_path, "r");
    if (jf) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0'; fclose(jf);
        TEST_ASSERT_NOT_NULL(strstr(buf, "CB-101"));
    }
    remove(csvpath);
}

//cfusa:req REQ-REQ012
//cfusa:test REQ-REQ012
void test_req_import_jama_csv(void)
{
    char csvpath[256];
    snprintf(csvpath, sizeof(csvpath), "%s/jama_import.csv", RTC_DIR);
    FILE *f = fopen(csvpath, "w");
    if (f) {
        fputs("ID,Name,Description,Status\n", f);
        fputs("202,Jama item,Jama description text,Active\n", f);
        fclose(f);
    }
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "jama", csvpath, NULL};
    int rc = cmd_req(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    char reqs_path[256];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);
    FILE *jf = fopen(reqs_path, "r");
    if (jf) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0'; fclose(jf);
        TEST_ASSERT_NOT_NULL(strstr(buf, "JAMA-202"));
    }
    remove(csvpath);
}

//cfusa:req REQ-REQ013
//cfusa:test REQ-REQ013
void test_req_import_reqif_xml(void)
{
    char xmlpath[256];
    snprintf(xmlpath, sizeof(xmlpath), "%s/reqs.reqif", RTC_DIR);
    FILE *f = fopen(xmlpath, "w");
    if (f) {
        fputs("<?xml version=\"1.0\"?>\n"
              "<REQ-IF>\n"
              "  <CORE-CONTENT>\n"
              "    <SPEC-OBJECTS>\n"
              "      <SPEC-OBJECT LONG-NAME=\"Safety requirement\">\n"
              "        <VALUES>\n"
              "          <ATTRIBUTE-VALUE-XHTML>\n"
              "            <THE-VALUE>Shall detect overflow</THE-VALUE>\n"
              "          </ATTRIBUTE-VALUE-XHTML>\n"
              "        </VALUES>\n"
              "      </SPEC-OBJECT>\n"
              "    </SPEC-OBJECTS>\n"
              "  </CORE-CONTENT>\n"
              "</REQ-IF>\n", f);
        fclose(f);
    }
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "doors", xmlpath, NULL};
    int rc = cmd_req(7, argv);
    /* May return 0 or non-zero depending on parse; must not crash */
    (void)rc;
    remove(xmlpath);
}

//cfusa:req REQ-COV001
//cfusa:test REQ-COV001
void test_coverage_mutate_score_flag(void)
{
    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/cov-mutate.json", RTC_DIR);
    char *argv[] = {"cfusa coverage",
                    "--dir",         RTC_DIR,
                    "--format",      "json",
                    "--output",      outpath,
                    "--mutate",
                    "--mutate-score","75.0", NULL};
    int rc = cmd_coverage(9, argv);
    /* mutate_score < 100 => exit 1 */
    TEST_ASSERT_EQUAL(1, rc);
    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f); buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"mutation_score\""));
        TEST_ASSERT_NOT_NULL(strstr(buf, "75.00"));
    }
    remove(outpath);
}

//cfusa:req REQ-COV002
//cfusa:test REQ-COV002
void test_coverage_mutate_100_pass(void)
{
    char outpath[256];
    snprintf(outpath, sizeof(outpath), "%s/cov-mutate100.json", RTC_DIR);
    char *argv[] = {"cfusa coverage",
                    "--dir",          RTC_DIR,
                    "--format",       "json",
                    "--output",       outpath,
                    "--mutate-score", "100.0", NULL};
    int rc = cmd_coverage(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
    remove(outpath);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_trace_text_with_reqs);
    RUN_TEST(test_trace_json_format);
    RUN_TEST(test_trace_md_format);
    RUN_TEST(test_trace_output_to_file);
    RUN_TEST(test_trace_req_coverage_gate_pass);
    RUN_TEST(test_trace_req_coverage_gate_fail);
    RUN_TEST(test_trace_sec_tested_gate_pass);
    RUN_TEST(test_trace_sec_tested_gate_fail);
    RUN_TEST(test_trace_gaps_with_reqs);
    RUN_TEST(test_trace_gaps_with_untested);
    RUN_TEST(test_trace_no_legacy_flag);
    RUN_TEST(test_trace_md_no_reqs);
    RUN_TEST(test_trace_json_no_reqs);
    RUN_TEST(test_req_list_with_reqs_present);
    RUN_TEST(test_req_filter_known_id);
    RUN_TEST(test_req_filter_unknown_id);
    RUN_TEST(test_req_annotations_fallback);
    RUN_TEST(test_req_no_reqs_no_annotations);
    RUN_TEST(test_req_export_to_stdout);
    RUN_TEST(test_req_export_to_file);
    RUN_TEST(test_req_import_no_csv_arg);
    RUN_TEST(test_req_import_valid_csv);
    RUN_TEST(test_req_export_no_reqs_file);
    RUN_TEST(test_req_import_codebeamer_csv);
    RUN_TEST(test_req_import_jama_csv);
    RUN_TEST(test_req_import_reqif_xml);
    RUN_TEST(test_coverage_mutate_score_flag);
    RUN_TEST(test_coverage_mutate_100_pass);
    return UNITY_END();
}
