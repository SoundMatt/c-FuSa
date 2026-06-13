/*
 * Tests for cmd_comp — cyclomatic complexity report command.
 * Covers: basic output, DAL thresholds, JSON format, output file,
 *         violations exit code, clean exit code, verbose, help.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "unity.h"

extern int cmd_comp(int argc, char **argv);

#define CTDIR "/tmp/cfusa_comp_testdir"

/* ── helpers ──────────────────────────────────────────────────────────── */

static void ct_write(const char *relpath, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", CTDIR, relpath);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return;
    size_t n = strlen(body); if (n) (void)write(fd, body, n);
    close(fd);
}

/* Simple C function with V(G)=1 (no branches) */
static const char *SIMPLE_C =
    "int add(int a, int b) {\n"
    "    return a + b;\n"
    "}\n";

/* Complex C function with V(G)=12 (exceeds DAL-B threshold of 10) */
static const char *COMPLEX_C =
    "int complex_fn(int x, int y) {\n"
    "    if (x > 0) {\n"
    "        if (y > 0) {\n"
    "            while (x > y) {\n"
    "                x--;\n"
    "            }\n"
    "        } else if (y < 0) {\n"
    "            for (int i = 0; i < 5; i++) {\n"
    "                if (i % 2 == 0) {\n"
    "                    y++;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    } else if (x < 0) {\n"
    "        x = x > -10 ? x : -10;\n"
    "        if (y && x) {\n"
    "            return y || x;\n"
    "        }\n"
    "    }\n"
    "    return x + y;\n"
    "}\n";

/* Mixed: one simple (V(G)=1), one complex (V(G)=12, exceeds threshold 10) */
static const char *MIXED_C =
    "int simple(int a) {\n"
    "    return a * 2;\n"
    "}\n"
    "\n"
    "int branchy(int x, int y, int z) {\n"
    "    if (x > 0 && y > 0) {\n"
    "        for (int i = 0; i < z; i++) {\n"
    "            if (i % 2 == 0) {\n"
    "                x += y;\n"
    "            } else if (i % 3 == 0) {\n"
    "                y += z;\n"
    "            } else if (i % 5 == 0) {\n"
    "                z += x;\n"
    "            }\n"
    "        }\n"
    "    } else if (x < 0 || z < 0) {\n"
    "        while (x < 0) x++;\n"
    "        if (z > 5 && z < 20) z = 5;\n"
    "    }\n"
    "    return x + y + z;\n"
    "}\n";

void setUp(void)
{
    (void)system("rm -rf " CTDIR);
    mkdir(CTDIR, 0700);
}

void tearDown(void) {}

/* ── tests ────────────────────────────────────────────────────────────── */

void test_comp_help(void)
{
    char *argv[] = {"cfusa comp", "--help", NULL};
    int rc = cmd_comp(2, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_empty_dir_clean(void)
{
    /* No .c files → no functions → no violations → exit 0 */
    char *argv[] = {"cfusa comp", "--dir", CTDIR, NULL};
    int rc = cmd_comp(3, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_simple_function_clean(void)
{
    ct_write("simple.c", SIMPLE_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--verbose", NULL};
    int rc = cmd_comp(4, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_complex_function_violation(void)
{
    ct_write("complex.c", COMPLEX_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--verbose", NULL};
    int rc = cmd_comp(4, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

void test_comp_dal_a_threshold(void)
{
    /* Simple function has V(G)=1, DAL-A threshold=4 → clean */
    ct_write("simple.c", SIMPLE_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--dal-a", "--verbose", NULL};
    int rc = cmd_comp(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_custom_threshold_passes(void)
{
    /* Complex function; with threshold=20 no violation */
    ct_write("complex.c", COMPLEX_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--threshold", "20", "--verbose", NULL};
    int rc = cmd_comp(6, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_dal_d_threshold_passes(void)
{
    /* DAL-D threshold=20; complex fn with V(G)≤20 → clean */
    ct_write("complex.c", COMPLEX_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--dal-d", "--verbose", NULL};
    int rc = cmd_comp(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_json_format_clean(void)
{
    ct_write("simple.c", SIMPLE_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "json", NULL};
    int rc = cmd_comp(5, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

void test_comp_json_format_violation(void)
{
    ct_write("complex.c", COMPLEX_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "json", NULL};
    int rc = cmd_comp(5, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

void test_comp_md_format(void)
{
    ct_write("mixed.c", MIXED_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "md", "--verbose", NULL};
    int rc = cmd_comp(6, argv);
    /* Mixed file has violations (branchy > 10), so exits 1 */
    TEST_ASSERT_EQUAL(1, rc);
}

void test_comp_output_file_json(void)
{
    ct_write("simple.c", SIMPLE_C);
    const char *out = "/tmp/cfusa_comp_out.json";
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "json",
                    "--output", (char *)out, NULL};
    int rc = cmd_comp(7, argv);
    TEST_ASSERT_EQUAL(0, rc);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    char buf[64] = "";
    if (f) { (void)fread(buf, 1, sizeof(buf)-1, f); fclose(f); }
    TEST_ASSERT_NOT_NULL(strstr(buf, "comp-report"));
    remove(out);
}

void test_comp_output_file_text(void)
{
    ct_write("simple.c", SIMPLE_C);
    const char *out = "/tmp/cfusa_comp_out.txt";
    char *argv[] = {"cfusa comp", "--dir", CTDIR,
                    "--output", (char *)out, "--verbose", NULL};
    int rc = cmd_comp(6, argv);
    TEST_ASSERT_EQUAL(0, rc);
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    remove(out);
}

void test_comp_verbose_shows_clean_functions(void)
{
    ct_write("mixed.c", MIXED_C);
    /* verbose JSON should include all functions, not just violations */
    const char *out = "/tmp/cfusa_comp_verbose.json";
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "json",
                    "--output", (char *)out, NULL};
    int rc = cmd_comp(7, argv);
    TEST_ASSERT_EQUAL(1, rc); /* violations exist */
    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    /* JSON should contain both "simple" and "branchy" */
    char buf[4096] = "";
    if (f) { (void)fread(buf, 1, sizeof(buf)-1, f); fclose(f); }
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"simple\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"branchy\""));
    remove(out);
}

void test_comp_summary_fields_in_json(void)
{
    ct_write("simple.c", SIMPLE_C);
    const char *out = "/tmp/cfusa_comp_summary.json";
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "json",
                    "--output", (char *)out, NULL};
    int rc = cmd_comp(7, argv);
    TEST_ASSERT_EQUAL(0, rc);
    FILE *f = fopen(out, "r");
    char buf[4096] = "";
    if (f) { (void)fread(buf, 1, sizeof(buf)-1, f); fclose(f); }
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"totalFunctions\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"violations\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"maxComplexity\""));
    remove(out);
}

void test_comp_dal_b_is_default(void)
{
    /* The complex function has V(G)>10 → exit 1 without specifying threshold */
    ct_write("complex.c", COMPLEX_C);
    char *argv[] = {"cfusa comp", "--dir", CTDIR, NULL};
    int rc = cmd_comp(3, argv);
    TEST_ASSERT_EQUAL(1, rc);
}

//cfusa:req REQ-FMTERR001
//cfusa:test REQ-FMTERR001
void test_comp_bad_format_returns_2(void)
{
    char *argv[] = {"cfusa comp", "--dir", CTDIR, "--format", "html", NULL};
    int rc = cmd_comp(5, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_comp_help);
    RUN_TEST(test_comp_empty_dir_clean);
    RUN_TEST(test_comp_simple_function_clean);
    RUN_TEST(test_comp_complex_function_violation);
    RUN_TEST(test_comp_dal_a_threshold);
    RUN_TEST(test_comp_custom_threshold_passes);
    RUN_TEST(test_comp_dal_d_threshold_passes);
    RUN_TEST(test_comp_json_format_clean);
    RUN_TEST(test_comp_json_format_violation);
    RUN_TEST(test_comp_md_format);
    RUN_TEST(test_comp_output_file_json);
    RUN_TEST(test_comp_output_file_text);
    RUN_TEST(test_comp_verbose_shows_clean_functions);
    RUN_TEST(test_comp_summary_fields_in_json);
    RUN_TEST(test_comp_dal_b_is_default);
    RUN_TEST(test_comp_bad_format_returns_2);
    return UNITY_END();
}
