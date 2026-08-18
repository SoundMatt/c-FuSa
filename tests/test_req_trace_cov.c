/*
 * Coverage-focused tests for cmd_req and cmd_trace.
 * Exercises JSON/MD/text output, req-coverage gate, sec-tested gate,
 * export/import subcommands, filter args, and annotation fallback paths.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"
#include "cfusa/utils.h"

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
    /* Remove both source files so tracedRequirements = 0 < 100% → fail */
    rm_file("impl.c");
    rm_file("test_impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "100", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_TRUE(rc != 0);
    /* Restore */
    write_file("impl.c",
        "//cfusa:req REQ-A001\nvoid alpha(void) {}\n"
        "//cfusa:req REQ-A002\nvoid beta(void) {}\n");
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
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
//cfusa:req REQ-REQXML001
//cfusa:test REQ-REQ013
//cfusa:test REQ-REQXML001
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
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
    /* DOORS ReqIF XML (REQ-REQXML001): --format doors parses <SPEC-OBJECT>
     * elements, using LONG-NAME as title and <THE-VALUE> as text. */
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "doors", xmlpath, NULL};
    int rc = cmd_req(7, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);

    char reqs_path[256];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);
    FILE *jf = fopen(reqs_path, "r");
    if (jf) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0'; fclose(jf);
        TEST_ASSERT_NOT_NULL(strstr(buf, "Safety requirement"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Shall detect overflow"));
    }
    remove(xmlpath);
}

//cfusa:test REQ-REQXML002
void test_req_import_codebeamer_xml(void)
{
    char xmlpath[256];
    snprintf(xmlpath, sizeof(xmlpath), "%s/cb_import.xml", RTC_DIR);
    FILE *f = fopen(xmlpath, "w");
    if (f) {
        fputs("<tracker>\n"
              "  <item id=\"301\">\n"
              "    <summary>CB XML summary</summary>\n"
              "    <description>CB XML description</description>\n"
              "  </item>\n"
              "</tracker>\n", f);
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
    /* Codebeamer XML (REQ-REQXML002): --format codebeamer + .xml extension
     * parses <item id=\"...\"><summary>/<description> elements. */
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "codebeamer", xmlpath, NULL};
    int rc = cmd_req(7, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);

    char reqs_path[256];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);
    FILE *jf = fopen(reqs_path, "r");
    if (jf) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0'; fclose(jf);
        TEST_ASSERT_NOT_NULL(strstr(buf, "CB-301"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "CB XML summary"));
    }
    remove(xmlpath);
}

//cfusa:test REQ-REQXML003
void test_req_import_jama_xml(void)
{
    char xmlpath[256];
    snprintf(xmlpath, sizeof(xmlpath), "%s/jama_import.xml", RTC_DIR);
    FILE *f = fopen(xmlpath, "w");
    if (f) {
        fputs("<items>\n"
              "  <item id=\"402\" itemType=\"Requirement\">\n"
              "    <name>Jama XML item</name>\n"
              "    <description>Jama XML description</description>\n"
              "  </item>\n"
              "</items>\n", f);
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
    /* Jama XML (REQ-REQXML003): --format jama + .xml extension parses
     * <item id=\"...\"><name>/<description> elements. */
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "jama", xmlpath, NULL};
    int rc = cmd_req(7, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);

    char reqs_path[256];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);
    FILE *jf = fopen(reqs_path, "r");
    if (jf) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0'; fclose(jf);
        TEST_ASSERT_NOT_NULL(strstr(buf, "JAMA-402"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Jama XML item"));
    }
    remove(xmlpath);
}

//cfusa:test REQ-REQXML004
void test_req_import_polarion_xml(void)
{
    char xmlpath[256];
    snprintf(xmlpath, sizeof(xmlpath), "%s/polarion_import.xml", RTC_DIR);
    FILE *f = fopen(xmlpath, "w");
    if (f) {
        fputs("<workitems>\n"
              "  <workitem id=\"REQ-POL-501\">\n"
              "    <title>Polarion item</title>\n"
              "    <description>Polarion description</description>\n"
              "  </workitem>\n"
              "</workitems>\n", f);
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
    /* Polarion XML (REQ-REQXML004): --format polarion + .xml extension (no
     * "reqif" substring in the format string) parses <workitem id=\"...\">
     * <title>/<description> elements. */
    char *argv[] = {"cfusa", "import", "--dir", RTC_DIR,
                    "--format", "polarion", xmlpath, NULL};
    int rc = cmd_req(7, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);

    char reqs_path[256];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);
    FILE *jf = fopen(reqs_path, "r");
    if (jf) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof(buf)-1, jf); buf[n] = '\0'; fclose(jf);
        TEST_ASSERT_NOT_NULL(strstr(buf, "REQ-POL-501"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "Polarion item"));
    }
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
    int rc = cmd_coverage(10, argv);
    /* mutate_score < 100 => exit 1 */
    TEST_ASSERT_EQUAL(1, rc);
    FILE *f = fopen(outpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f); buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "\"mutationScore\""));
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
    int rc = cmd_coverage(9, argv);
    TEST_ASSERT_EQUAL(0, rc);
    remove(outpath);
}

/* ── req-coverage parity tests (go-FuSa TestRunTraceReqCoverage_*) ─── */

//cfusa:req REQ-REQCOV-M2-001
//cfusa:test REQ-REQCOV-M2-001
void test_trace_req_coverage_metric2_fail(void)
{
    /* extra.c has 5 unannotated functions → 2/(2+5)=28% < 80% → metric 2 fails */
    write_file("extra.c",
        "void fn1(void) {}\nvoid fn2(void) {}\nvoid fn3(void) {}\n"
        "void fn4(void) {}\nvoid fn5(void) {}\n");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "80", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);
    rm_file("extra.c");
}

//cfusa:req REQ-REQCOV-NA-001
//cfusa:test REQ-REQCOV-NA-001
void test_trace_req_coverage_na_empty(void)
{
    /* no reqs, no .c files → both N/A → exit 0 */
    rm_file("impl.c");
    rm_file("test_impl.c");
    rm_file(".cfusa-reqs.json");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "80", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    /* restore */
    write_file(".cfusa-reqs.json",
        "{\n  \"requirements\": [\n"
        "    {\"id\":\"REQ-A001\",\"title\":\"Alpha\",\"text\":\"a\","
        "\"standard\":\"ISO 26262\",\"level\":\"SHALL\"},\n"
        "    {\"id\":\"REQ-A002\",\"title\":\"Beta\",\"text\":\"b\","
        "\"standard\":\"MISRA-C\",\"level\":\"SHOULD\"}\n"
        "  ]\n}\n");
    write_file("impl.c",
        "//cfusa:req REQ-A001\nvoid alpha(void) {}\n"
        "//cfusa:req REQ-A002\nvoid beta(void) {}\n");
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
}

//cfusa:req REQ-REQCOV-ZERO-001
//cfusa:test REQ-REQCOV-ZERO-001
void test_trace_req_coverage_zero_disabled(void)
{
    /* --req-coverage 0 disables the gate → exit 0, shows regular matrix */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "0", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

//cfusa:req REQ-REQCOV-TRUNC-001
//cfusa:test REQ-REQCOV-TRUNC-001
void test_trace_req_coverage_truncated(void)
{
    /* 25 unannotated functions → output truncated at 20 with "... and N more" */
    FILE *f = fopen(RTC_DIR "/many.c", "w");
    if (f) {
        for (int i = 0; i < 25; i++) fprintf(f, "void Fn%d(void) {}\n", i);
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
    }
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--req-coverage", "80", NULL};
    /* exit code may be 0 or 1 — we only care it doesn't crash */
    cmd_trace(5, argv);
    rm_file("many.c");
}

/* ---- --func-coverage (REQ-FUNCCOV001, x-FuSa spec §1.4.1) ---- */

//cfusa:req REQ-FUNCCOV001
//cfusa:test REQ-FUNCCOV001
void test_trace_func_coverage_gate_pass(void)
{
    /* impl.c has 2 functions, both in a file carrying //cfusa:req -> 100% */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage", "80", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

//cfusa:req REQ-FUNCCOV001
//cfusa:test REQ-FUNCCOV001
void test_trace_func_coverage_gate_fail(void)
{
    /* extra.c has 5 unannotated functions -> 2/(2+5)=28% < 80% -> gate fails */
    write_file("extra.c",
        "void fn1(void) {}\nvoid fn2(void) {}\nvoid fn3(void) {}\n"
        "void fn4(void) {}\nvoid fn5(void) {}\n");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage", "80", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(1, rc);
    rm_file("extra.c");
}

//cfusa:req REQ-FUNCCOV001
//cfusa:test REQ-FUNCCOV001
void test_trace_func_coverage_zero_disabled(void)
{
    /* --func-coverage 0 disables the gate -> exit 0 even with poor coverage */
    write_file("extra.c",
        "void fn1(void) {}\nvoid fn2(void) {}\nvoid fn3(void) {}\n");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage", "0", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    rm_file("extra.c");
}

//cfusa:req REQ-FUNCCOV001
//cfusa:test REQ-FUNCCOV001
void test_trace_func_coverage_na_empty(void)
{
    /* no .c files at all -> N/A -> exit 0 */
    rm_file("impl.c");
    rm_file("test_impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage", "90", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    /* restore for subsequent tests */
    write_file("impl.c",
        "//cfusa:req REQ-A001\nvoid alpha(void) {}\n"
        "//cfusa:req REQ-A002\nvoid beta(void) {}\n");
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
}

/* ---- --func-coverage-strict (REQ-FUNCCOV002, issue #125) ---- */

//cfusa:req REQ-FUNCCOV002
//cfusa:test REQ-FUNCCOV002
void test_trace_func_coverage_strict_gate_pass(void)
{
    /* impl.c: both alpha and beta are individually tagged directly above
     * their own definition -> 100% under the strict metric too. */
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage-strict", "100", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
}

/* This is the issue's core repro: a file where every function sits
 * "in a file carrying >=1 //cfusa:req tag" (so --func-coverage reports
 * 100%), but one function has no tag of its own directly above it. The
 * plain --func-coverage gate must still pass (unchanged, file-level
 * contract); --func-coverage-strict must correctly fail. */
//cfusa:req REQ-FUNCCOV002
//cfusa:test REQ-FUNCCOV002
void test_trace_func_coverage_strict_catches_untagged_helper_in_tagged_file(void)
{
    write_file("mixed.c",
        "//cfusa:req REQ-A001\n"
        "void tagged_one(void) {}\n"
        "\n"
        "int untagged_helper(int x) { return x + 1; }\n"
        "\n"
        "//cfusa:req REQ-A002\n"
        "void tagged_two(void) {}\n");

    char *file_level[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage", "100", NULL};
    TEST_ASSERT_EQUAL_INT(0, cmd_trace(5, file_level));

    char *strict[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage-strict", "100", NULL};
    TEST_ASSERT_EQUAL_INT(1, cmd_trace(5, strict));

    rm_file("mixed.c");
}

//cfusa:req REQ-FUNCCOV002
//cfusa:test REQ-FUNCCOV002
void test_trace_func_coverage_strict_zero_disabled(void)
{
    write_file("extra.c",
        "void fn1(void) {}\nvoid fn2(void) {}\nvoid fn3(void) {}\n");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage-strict", "0", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    rm_file("extra.c");
}

//cfusa:req REQ-FUNCCOV002
//cfusa:test REQ-FUNCCOV002
void test_trace_func_coverage_strict_na_empty(void)
{
    rm_file("impl.c");
    rm_file("test_impl.c");
    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--func-coverage-strict", "90", NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL_INT(0, rc);
    write_file("impl.c",
        "//cfusa:req REQ-A001\nvoid alpha(void) {}\n"
        "//cfusa:req REQ-A002\nvoid beta(void) {}\n");
    write_file("test_impl.c",
        "//cfusa:test REQ-A001\nvoid test_alpha(void) {}\n"
        "//cfusa:test REQ-A002\nvoid test_beta(void) {}\n");
}

/* ---- dangling test-tag reference (REQ-TESTDANGLE001, x-FuSa spec §1.4.1) ---- */

//cfusa:req REQ-TESTDANGLE001
//cfusa:test REQ-TESTDANGLE001
void test_trace_dangling_test_tag_warning(void)
{
    /* //cfusa:test REQ-GHOST999 has no matching entry in .cfusa-reqs.json ->
     * cmd_trace must emit a WARNING to stderr (never silently accepted),
     * and must NOT crash or otherwise treat it as fatal. */
    write_file("dangling.c",
        "//cfusa:test REQ-GHOST999\nvoid test_ghost(void) {}\n");

    char errpath[256];
    snprintf(errpath, sizeof(errpath), "%s/stderr_capture.txt", RTC_DIR);
    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *redirected = freopen(errpath, "w", stderr);
    TEST_ASSERT_NOT_NULL(redirected);

    char *argv[] = {"cfusa", "--dir", RTC_DIR, NULL};
    int rc = cmd_trace(3, argv);

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    TEST_ASSERT_TRUE(rc == 0 || rc == 1);

    FILE *f = fopen(errpath, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[4096]; size_t n = fread(buf, 1, sizeof(buf)-1, f);
        buf[n] = '\0'; fclose(f);
        TEST_ASSERT_NOT_NULL(strstr(buf, "WARNING"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "dangling"));
        TEST_ASSERT_NOT_NULL(strstr(buf, "REQ-GHOST999"));
    }
    remove(errpath);
    rm_file("dangling.c");
}

/* ---- catalogs larger than the old fixed-array caps (issue #100) ---- */

//cfusa:req REQ-REQCAP001
//cfusa:test REQ-REQCAP001
void test_trace_more_than_1024_reqs_not_truncated(void)
{
    /* Regression for issue #100: g_reqs used to be a fixed 1024-entry
     * array, and load_reqs() silently stopped parsing once it was full —
     * so a catalog with more than 1024 entries reported false 100%
     * coverage while the tail past the cap was never loaded at all. Write
     * 1030 requirements, each traced and tested, and confirm cmd_trace
     * reports all 1030 rather than capping at 1024. */
    const int n = 1030;
    char reqs_path[300], impl_path[300], out_path[300];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.fusa-reqs.json", RTC_DIR);
    snprintf(impl_path, sizeof(impl_path), "%s/big_impl.c", RTC_DIR);
    snprintf(out_path,  sizeof(out_path),  "%s/big_trace_out.txt", RTC_DIR);

    FILE *rf = cfusa_fopen_write(reqs_path);
    TEST_ASSERT_NOT_NULL(rf);
    fprintf(rf, "{\n  \"requirements\": [\n");
    for (int i = 1; i <= n; i++)
        fprintf(rf, "    {\"id\":\"REQ-BIG-%04d\",\"title\":\"r%d\"}%s\n",
                i, i, (i < n) ? "," : "");
    fprintf(rf, "  ]\n}\n");
    if (fclose(rf) != 0) TEST_FAIL_MESSAGE("fclose failed");

    FILE *cf = cfusa_fopen_write(impl_path);
    TEST_ASSERT_NOT_NULL(cf);
    for (int i = 1; i <= n; i++)
        fprintf(cf,
                "//cfusa:req REQ-BIG-%04d\n//cfusa:test REQ-BIG-%04d\n"
                "void f%d(void) {}\n", i, i, i);
    if (fclose(cf) != 0) TEST_FAIL_MESSAGE("fclose failed");

    char *argv[] = {"cfusa", "--dir", RTC_DIR, "--output", out_path, NULL};
    int rc = cmd_trace(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *of = fopen(out_path, "r");
    TEST_ASSERT_NOT_NULL(of);
    fseek(of, 0, SEEK_END);
    long sz = ftell(of);
    fseek(of, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    TEST_ASSERT_NOT_NULL(buf);
    size_t nread = fread(buf, 1, (size_t)sz, of);
    buf[nread] = '\0';
    if (fclose(of) != 0) TEST_FAIL_MESSAGE("fclose failed");

    TEST_ASSERT_NOT_NULL(strstr(buf,
        "Coverage: 1030/1030 requirements traced, 1030/1030 tested"));
    /* the tail entry, past the old 1024-entry cap, must be present */
    TEST_ASSERT_NOT_NULL(strstr(buf, "REQ-BIG-1030"));
    free(buf);

    remove(reqs_path);
    remove(impl_path);
    remove(out_path);
}

//cfusa:req REQ-REQCAP001
//cfusa:test REQ-REQCAP001
void test_req_more_than_1024_reqs_not_truncated(void)
{
    /* Regression for issue #100: cmd_req's requirements array was capped
     * at a fixed 1024 entries; entries past the cap were silently dropped
     * by load_reqs() and could never be found via 'cfusa req <id>'. */
    const int n = 1030;
    char reqs_path[300];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.cfusa-reqs.json", RTC_DIR);

    FILE *rf = cfusa_fopen_write(reqs_path);
    TEST_ASSERT_NOT_NULL(rf);
    fprintf(rf, "{\n  \"requirements\": [\n");
    for (int i = 1; i <= n; i++)
        fprintf(rf, "    {\"id\":\"REQ-BIG-%04d\",\"title\":\"r%d\"}%s\n",
                i, i, (i < n) ? "," : "");
    fprintf(rf, "  ]\n}\n");
    if (fclose(rf) != 0) TEST_FAIL_MESSAGE("fclose failed");

    char *argv[] = {"cfusa", "--dir", RTC_DIR, "REQ-BIG-1030", NULL};
    int rc = cmd_req(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
    /* setUp() rewrites .cfusa-reqs.json to its standard 2-entry fixture
     * before the next test runs, so no explicit cleanup is required here. */
}

//cfusa:req REQ-REQCAP001
//cfusa:test REQ-REQCAP001
void test_trace_more_than_4096_tags_not_truncated(void)
{
    /* Regression for issue #100 follow-up: g_tags used to be a fixed
     * 4096-entry array in both cmd_req and cmd_trace, and add_tag()
     * silently stopped appending once full — so a source tree with many
     * annotations could under-report traced coverage even when every
     * requirement itself loaded fine. Tag 500 requirements with 10
     * duplicate impl tags each (5000 tags total, past the old 4096 cap)
     * and confirm cmd_trace still reports full traced coverage for all of
     * them. */
    const int n = 500;
    char reqs_path[300], impl_path[300], out_path[300];
    snprintf(reqs_path, sizeof(reqs_path), "%s/.fusa-reqs.json", RTC_DIR);
    snprintf(impl_path, sizeof(impl_path), "%s/tagcap_impl.c", RTC_DIR);
    snprintf(out_path,  sizeof(out_path),  "%s/tagcap_trace_out.txt", RTC_DIR);

    FILE *rf = cfusa_fopen_write(reqs_path);
    TEST_ASSERT_NOT_NULL(rf);
    fprintf(rf, "{\n  \"requirements\": [\n");
    for (int i = 1; i <= n; i++)
        fprintf(rf, "    {\"id\":\"REQ-TAG-%04d\",\"title\":\"r%d\"}%s\n",
                i, i, (i < n) ? "," : "");
    fprintf(rf, "  ]\n}\n");
    if (fclose(rf) != 0) TEST_FAIL_MESSAGE("fclose failed");

    FILE *cf = cfusa_fopen_write(impl_path);
    TEST_ASSERT_NOT_NULL(cf);
    for (int i = 1; i <= n; i++) {
        for (int d = 0; d < 10; d++)
            fprintf(cf, "//cfusa:req REQ-TAG-%04d\n", i);
        fprintf(cf, "void f%d(void) {}\n", i);
    }
    if (fclose(cf) != 0) TEST_FAIL_MESSAGE("fclose failed");

    char *argv2[] = {"cfusa", "--dir", RTC_DIR, "--output", out_path, NULL};
    int rc = cmd_trace(5, argv2);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *of = fopen(out_path, "r");
    TEST_ASSERT_NOT_NULL(of);
    fseek(of, 0, SEEK_END);
    long sz = ftell(of);
    fseek(of, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    TEST_ASSERT_NOT_NULL(buf);
    size_t nread = fread(buf, 1, (size_t)sz, of);
    buf[nread] = '\0';
    if (fclose(of) != 0) TEST_FAIL_MESSAGE("fclose failed");

    /* Only impl tags were written (no test tags), so traced==n, tested==0 */
    char expect[128];
    snprintf(expect, sizeof(expect),
             "Coverage: %d/%d requirements traced, 0/%d tested", n, n, n);
    TEST_ASSERT_NOT_NULL(strstr(buf, expect));
    free(buf);

    remove(reqs_path);
    remove(impl_path);
    remove(out_path);
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
    RUN_TEST(test_req_import_codebeamer_xml);
    RUN_TEST(test_req_import_jama_xml);
    RUN_TEST(test_req_import_polarion_xml);
    RUN_TEST(test_coverage_mutate_score_flag);
    RUN_TEST(test_coverage_mutate_100_pass);
    RUN_TEST(test_trace_req_coverage_metric2_fail);
    RUN_TEST(test_trace_req_coverage_na_empty);
    RUN_TEST(test_trace_req_coverage_zero_disabled);
    RUN_TEST(test_trace_req_coverage_truncated);
    RUN_TEST(test_trace_func_coverage_gate_pass);
    RUN_TEST(test_trace_func_coverage_gate_fail);
    RUN_TEST(test_trace_func_coverage_zero_disabled);
    RUN_TEST(test_trace_func_coverage_na_empty);
    RUN_TEST(test_trace_func_coverage_strict_gate_pass);
    RUN_TEST(test_trace_func_coverage_strict_catches_untagged_helper_in_tagged_file);
    RUN_TEST(test_trace_func_coverage_strict_zero_disabled);
    RUN_TEST(test_trace_func_coverage_strict_na_empty);
    RUN_TEST(test_trace_dangling_test_tag_warning);
    RUN_TEST(test_trace_more_than_1024_reqs_not_truncated);
    RUN_TEST(test_req_more_than_1024_reqs_not_truncated);
    RUN_TEST(test_trace_more_than_4096_tags_not_truncated);
    return UNITY_END();
}
