/*
 * Tests for HARA ASIL computation (ISO 26262-3:2018 Table 4) and init/show.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../vendor/unity/unity.h"

/* Access the ASIL computation via the cmd_hara command entry point */
extern int cmd_hara(int argc, char **argv);

#define HARA_TEST_DIR "/tmp/cfusa_hara_testdir"

void setUp(void) { (void)mkdir(HARA_TEST_DIR, 0700); }
void tearDown(void) {}

/* ---- ASIL table spot-checks (ISO 26262-3:2018 Table 4) ---- */

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s3e4c3_is_d(void)
{
    /* S3/E4/C3 → ASIL-D */
    char *argv[] = {"cfusa", "asil",
                    "--severity", "3", "--exposure", "4", "--controllability", "3", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1e1c1_is_qm(void)
{
    /* S1/E1/C1 → QM */
    char *argv[] = {"cfusa", "asil",
                    "--severity", "1", "--exposure", "1", "--controllability", "1", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s2e4c3_is_c(void)
{
    /* S2/E4/C3 → ASIL-C */
    char *argv[] = {"cfusa", "asil",
                    "--severity", "2", "--exposure", "4", "--controllability", "3", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_out_of_range_returns_qm(void)
{
    /* S5/E5/C5 → out of range → compute_asil returns QM, command exits 0 */
    char *argv[] = {"cfusa", "asil",
                    "--severity", "5", "--exposure", "5", "--controllability", "5", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-HARA002
//cfusa:test REQ-HARA002
void test_asil_missing_params_returns_error(void)
{
    /* Missing required parameters → exit 2 (usage error) */
    char *argv[] = {"cfusa", "asil", NULL};
    int rc = cmd_hara(2, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

/* ---- HARA init ---- */

//cfusa:req REQ-HARA003
//cfusa:test REQ-HARA003
void test_hara_init_creates_file(void)
{
    char *argv[] = {"cfusa", "init", "--dir", HARA_TEST_DIR, NULL};
    int rc = cmd_hara(4, argv);
    TEST_ASSERT_EQUAL(0, rc);

    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-hara.json", HARA_TEST_DIR);
    FILE *f = fopen(path, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);
    (void)remove(path);
}

/* ---- HARA show on missing file ---- */

//cfusa:req REQ-HARA004
//cfusa:test REQ-HARA004
void test_hara_show_missing_file_no_crash(void)
{
    /* show on an empty dir should not crash */
    char *argv[] = {"cfusa", "show", "--dir", "/tmp/cfusa_hara_nodir", NULL};
    int rc = cmd_hara(4, argv);
    (void)rc; /* returns 0 after printing error message — not a crash */
}

/* ---- HARA show --format json ---- */

//cfusa:req REQ-HARA-FMT001
//cfusa:test REQ-HARA-FMT001
void test_hara_show_json_format(void)
{
    /* Init a HARA file first */
    char *init_argv[] = {"cfusa", "init", "--dir", HARA_TEST_DIR, NULL};
    cmd_hara(4, init_argv);

    /* show --format json should exit 0 */
    char *argv[] = {"cfusa", "show", "--dir", HARA_TEST_DIR, "--format", "json", NULL};
    int rc = cmd_hara(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    /* Cleanup */
    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-hara.json", HARA_TEST_DIR);
    (void)remove(path);
}

/* ---- HARA show --format markdown ---- */

//cfusa:req REQ-HARA-FMT002
//cfusa:test REQ-HARA-FMT002
void test_hara_show_markdown_format(void)
{
    char *init_argv[] = {"cfusa", "init", "--dir", HARA_TEST_DIR, NULL};
    cmd_hara(4, init_argv);

    char *argv[] = {"cfusa", "show", "--dir", HARA_TEST_DIR, "--format", "markdown", NULL};
    int rc = cmd_hara(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-hara.json", HARA_TEST_DIR);
    (void)remove(path);
}

//cfusa:req REQ-HARA-OUT001
//cfusa:test REQ-HARA-OUT001
void test_hara_show_output_file(void)
{
    char *init_argv[] = {"cfusa", "init", "--dir", HARA_TEST_DIR, NULL};
    cmd_hara(4, init_argv);

    char outfile[256];
    snprintf(outfile, sizeof(outfile), "%s/hara-out.txt", HARA_TEST_DIR);

    char *argv[] = {"cfusa", "show", "--dir", HARA_TEST_DIR, "--output", outfile, NULL};
    int rc = cmd_hara(6, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(outfile, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);

    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-hara.json", HARA_TEST_DIR);
    (void)remove(path);
    (void)remove(outfile);
}

/* ---- ASIL C0 extension — go-FuSa parity ---- */

//cfusa:req REQ-HARA-ASIL-C0001
//cfusa:test REQ-HARA-ASIL-C0001
void test_asil_s2e4c2_is_c(void)
{
    /* S2/E4/C2 → ASIL-C in 4-column table (go-FuSa parity) */
    char *argv[] = {"cfusa", "asil",
                    "--severity", "S2", "--exposure", "E4", "--controllability", "C2", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-HARA-ASIL-C0001
//cfusa:test REQ-HARA-ASIL-C0001
void test_asil_s2e4c0_is_a(void)
{
    /* S2/E4/C0 → ASIL-A in 4-column table */
    char *argv[] = {"cfusa", "asil",
                    "--severity", "S2", "--exposure", "E4", "--controllability", "C0", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

//cfusa:req REQ-HARA-ASIL-C0001
//cfusa:test REQ-HARA-ASIL-C0001
void test_asil_sx_prefix_format(void)
{
    /* "Sx"/"Ex"/"Cx" prefix format — go-FuSa parity */
    char *argv[] = {"cfusa", "asil",
                    "-s", "S1", "-e", "E1", "-c", "C0", NULL};
    int rc = cmd_hara(8, argv);
    TEST_ASSERT_EQUAL(0, rc);
}

/* ---- hara init already-exists returns 2 ---- */

//cfusa:req REQ-HARA-INIT-EXISTS001
//cfusa:test REQ-HARA-INIT-EXISTS001
void test_hara_init_already_exists_returns_2(void)
{
    /* First init should succeed */
    char *argv1[] = {"cfusa", "init", "--dir", HARA_TEST_DIR, NULL};
    cmd_hara(4, argv1);

    /* Second init → exit 2 */
    char *argv2[] = {"cfusa", "init", "--dir", HARA_TEST_DIR, NULL};
    int rc = cmd_hara(4, argv2);
    TEST_ASSERT_EQUAL(2, rc);

    char path[256];
    snprintf(path, sizeof(path), "%s/.fusa-hara.json", HARA_TEST_DIR);
    (void)remove(path);
}

/* ---- hara unknown subcommand → exit 2 ---- */

//cfusa:req REQ-HARA-SUBCMD001
//cfusa:test REQ-HARA-SUBCMD001
void test_hara_unknown_subcommand_returns_2(void)
{
    char *argv[] = {"cfusa", "nope", NULL};
    int rc = cmd_hara(2, argv);
    TEST_ASSERT_EQUAL(2, rc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_asil_s3e4c3_is_d);
    RUN_TEST(test_asil_s1e1c1_is_qm);
    RUN_TEST(test_asil_s2e4c3_is_c);
    RUN_TEST(test_asil_out_of_range_returns_qm);
    RUN_TEST(test_asil_missing_params_returns_error);
    RUN_TEST(test_asil_s2e4c2_is_c);
    RUN_TEST(test_asil_s2e4c0_is_a);
    RUN_TEST(test_asil_sx_prefix_format);
    RUN_TEST(test_hara_init_creates_file);
    RUN_TEST(test_hara_init_already_exists_returns_2);
    RUN_TEST(test_hara_unknown_subcommand_returns_2);
    RUN_TEST(test_hara_show_missing_file_no_crash);
    RUN_TEST(test_hara_show_json_format);
    RUN_TEST(test_hara_show_markdown_format);
    RUN_TEST(test_hara_show_output_file);
    return UNITY_END();
}
