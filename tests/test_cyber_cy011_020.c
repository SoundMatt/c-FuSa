/*
 * Tests for cyber rules CY011-CY020.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"
#include "../include/cfusa/report.h"
#include "../include/cfusa/config.h"
#include "../include/cfusa/engine.h"

extern void cfusa_cyber_register_rules(void);

#define CTDIR  "/tmp/cfusa_cy11_testdir"
#define CTFILE CTDIR "/t.c"

static void run_cyber_on(const char *code, cfusa_report_t *rpt)
{
    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    (void)mkdir(CTDIR, 0700);
    FILE *f = fopen(CTFILE, "w");
    if (!f) { TEST_FAIL_MESSAGE("could not create temp file"); return; }
    fputs(code, f);
    fclose(f);
    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, CTDIR, &cfg, rpt);
}

static int count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

void setUp(void)  {}
void tearDown(void) {}

/* ---- CY011: SSRF ---- */

//cfusa:req REQ-CYB019
//cfusa:test REQ-CYB019
void test_cy011_curl_variable_url_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(CURL *h, const char *url) {\n"
        "    curl_easy_setopt(h, CURLOPT_URL, url);\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY011") > 0);
    cfusa_report_free(&rpt);
}

void test_cy011_curl_literal_url_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(CURL *h) {\n"
        "    curl_easy_setopt(h, CURLOPT_URL, \"https://api.example.com\");\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY011"));
    cfusa_report_free(&rpt);
}

/* ---- CY012: SO_DEBUG ---- */

//cfusa:req REQ-CYB020
//cfusa:test REQ-CYB020
void test_cy012_so_debug_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(int fd) {\n"
        "    int v=1; setsockopt(fd, SOL_SOCKET, SO_DEBUG, &v, sizeof(v));\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY012") > 0);
    cfusa_report_free(&rpt);
}

void test_cy012_so_keepalive_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(int fd) {\n"
        "    int v=1; setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof(v));\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY012"));
    cfusa_report_free(&rpt);
}

/* ---- CY013: zip-slip ---- */

//cfusa:req REQ-CYB021
//cfusa:test REQ-CYB021
void test_cy013_archive_entry_pathname_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(struct archive_entry *e) {\n"
        "    const char *name = archive_entry_pathname(e);\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY013") > 0);
    cfusa_report_free(&rpt);
}

void test_cy013_no_archive_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on("void fn(void) { int x = 1; }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY013"));
    cfusa_report_free(&rpt);
}

/* ---- CY014: weak TLS ---- */

//cfusa:req REQ-CYB022
//cfusa:test REQ-CYB022
void test_cy014_sslv3_method_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) {\n"
        "    SSL_CTX *ctx = SSL_CTX_new(SSLv3_method());\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY014") > 0);
    cfusa_report_free(&rpt);
}

void test_cy014_tlsv1_client_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) {\n"
        "    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY014") > 0);
    cfusa_report_free(&rpt);
}

void test_cy014_tls_method_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) {\n"
        "    SSL_CTX *ctx = SSL_CTX_new(TLS_method());\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY014"));
    cfusa_report_free(&rpt);
}

/* ---- CY015: SQL injection via sprintf ---- */

//cfusa:req REQ-CYB023
//cfusa:test REQ-CYB023
void test_cy015_sql_sprintf_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(char *buf, const char *name) {\n"
        "    snprintf(buf, 256, \"SELECT * FROM users WHERE name='%s'\", name);\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY015") > 0);
    cfusa_report_free(&rpt);
}

void test_cy015_sprintf_no_sql_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(char *buf, const char *name) {\n"
        "    snprintf(buf, 256, \"Hello, %s!\", name);\n"
        "}\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY015"));
    cfusa_report_free(&rpt);
}

/* ---- CY016: permissive mkdir mode ---- */

//cfusa:req REQ-CYB024
//cfusa:test REQ-CYB024
void test_cy016_mkdir_0777_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) { mkdir(\"/tmp/test\", 0777); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY016") > 0);
    cfusa_report_free(&rpt);
}

void test_cy016_mkdir_0700_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) { mkdir(\"/tmp/test\", 0700); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY016"));
    cfusa_report_free(&rpt);
}

/* ---- CY017: permissive file mode ---- */

//cfusa:req REQ-CYB025
//cfusa:test REQ-CYB025
void test_cy017_open_0666_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "#include <fcntl.h>\n"
        "void fn(void) { open(\"/tmp/f\", O_CREAT|O_WRONLY, 0666); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY017") > 0);
    cfusa_report_free(&rpt);
}

void test_cy017_open_0600_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "#include <fcntl.h>\n"
        "void fn(void) { open(\"/tmp/f\", O_CREAT|O_WRONLY, 0600); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY017"));
    cfusa_report_free(&rpt);
}

/* ---- CY018: path from argv/getenv ---- */

//cfusa:req REQ-CYB026
//cfusa:test REQ-CYB026
void test_cy018_fopen_argv_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(int argc, char **argv) { FILE *f = fopen(argv[1], \"r\"); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY018") > 0);
    cfusa_report_free(&rpt);
}

void test_cy018_fopen_literal_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) { FILE *f = fopen(\"/etc/config\", \"r\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY018"));
    cfusa_report_free(&rpt);
}

/* ---- CY019: TOCTOU via access() ---- */

//cfusa:req REQ-CYB027
//cfusa:test REQ-CYB027
void test_cy019_access_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(const char *p) {\n"
        "    if (access(p, R_OK) == 0) { FILE *f = fopen(p, \"r\"); }\n"
        "}\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY019") > 0);
    cfusa_report_free(&rpt);
}

void test_cy019_no_access_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(const char *p) { FILE *f = fopen(p, \"r\"); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY019"));
    cfusa_report_free(&rpt);
}

/* ---- CY020: predictable /tmp path ---- */

//cfusa:req REQ-CYB028
//cfusa:test REQ-CYB028
void test_cy020_hardcoded_tmp_fires(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) { FILE *f = fopen(\"/tmp/myapp_lock\", \"w\"); }\n", &rpt);
    TEST_ASSERT_TRUE(count_rule(&rpt, "CFUSA-CY020") > 0);
    cfusa_report_free(&rpt);
}

void test_cy020_mkstemp_silent(void)
{
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    run_cyber_on(
        "void fn(void) { char t[]=\"/tmp/XXXXXX\"; int fd = mkstemp(t); }\n", &rpt);
    TEST_ASSERT_EQUAL(0, count_rule(&rpt, "CFUSA-CY020"));
    cfusa_report_free(&rpt);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cy011_curl_variable_url_fires);
    RUN_TEST(test_cy011_curl_literal_url_silent);
    RUN_TEST(test_cy012_so_debug_fires);
    RUN_TEST(test_cy012_so_keepalive_silent);
    RUN_TEST(test_cy013_archive_entry_pathname_fires);
    RUN_TEST(test_cy013_no_archive_silent);
    RUN_TEST(test_cy014_sslv3_method_fires);
    RUN_TEST(test_cy014_tlsv1_client_fires);
    RUN_TEST(test_cy014_tls_method_silent);
    RUN_TEST(test_cy015_sql_sprintf_fires);
    RUN_TEST(test_cy015_sprintf_no_sql_silent);
    RUN_TEST(test_cy016_mkdir_0777_fires);
    RUN_TEST(test_cy016_mkdir_0700_silent);
    RUN_TEST(test_cy017_open_0666_fires);
    RUN_TEST(test_cy017_open_0600_silent);
    RUN_TEST(test_cy018_fopen_argv_fires);
    RUN_TEST(test_cy018_fopen_literal_silent);
    RUN_TEST(test_cy019_access_fires);
    RUN_TEST(test_cy019_no_access_silent);
    RUN_TEST(test_cy020_hardcoded_tmp_fires);
    RUN_TEST(test_cy020_mkstemp_silent);
    return UNITY_END();
}
