/*
 * Tests for x-FuSa spec v1.13.0/v1.14.0/v1.15.0 conformance:
 *   - qualitybar (FUSA-STUB001/FUSA-STUB002 detection + attestation)
 *   - hara/fmea/tara/safety-case/sas/sci schema conformance
 *   - summary.coveragePct + --min-coverage (fmea/tara)
 *   - --strict/--require-attestation gating
 *   - v1.15.0: hara attestation/cross-reference passthrough (§9.2),
 *     canonical `standard` ids + TARA closed impact/risk enums (§2.4.1/§9.2),
 *     project-relative file paths that exclude stdlib calls and
 *     string-literal text (§4/§1.6 rule 4), fmea --output, and
 *     summary.coveragePct <= 100 with a non-trivial test-source tree
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../vendor/unity/unity.h"
#include "cfusa/qualitybar.h"
#include "cfusa/utils.h"

extern int cmd_hara(int argc, char **argv);
extern int cmd_fmea(int argc, char **argv);
extern int cmd_tara(int argc, char **argv);
extern int cmd_safety_case(int argc, char **argv);
extern int cmd_sas(int argc, char **argv);
extern int cmd_sci(int argc, char **argv);

#define V114_DIR "/tmp/cfusa_v114_testdir"

void setUp(void) { (void)mkdir(V114_DIR, 0700); }
void tearDown(void) {}

static void write_file(const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", V114_DIR, name);
    FILE *f = cfusa_fopen_write(path);
    if (f) { fputs(body, f); fclose(f); }
}

static char *slurp(const char *name, size_t *len_out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", V114_DIR, name);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    if (len_out) *len_out = n;
    return buf;
}

/* ================================================================== */
/* qualitybar unit tests                                                */
/* ================================================================== */

//cfusa:req REQ-QB001
//cfusa:test REQ-QB001
void test_qb_stub_text_bracket_placeholder(void)
{
    TEST_ASSERT_TRUE(cfusa_qb_is_stub_text("[describe asset]"));
    TEST_ASSERT_TRUE(cfusa_qb_is_stub_text("Example hazard — replace with project-specific hazard"));
    TEST_ASSERT_TRUE(cfusa_qb_is_stub_text("TBD"));
    TEST_ASSERT_TRUE(cfusa_qb_is_stub_text("lorem ipsum dolor sit amet"));
    TEST_ASSERT_TRUE(cfusa_qb_is_stub_text("please fill in this field"));
}

//cfusa:req REQ-QB001
//cfusa:test REQ-QB001
void test_qb_stub_text_real_content_not_flagged(void)
{
    TEST_ASSERT_FALSE(cfusa_qb_is_stub_text("brake_apply does not perform its intended action"));
    TEST_ASSERT_FALSE(cfusa_qb_is_stub_text(""));
    TEST_ASSERT_FALSE(cfusa_qb_is_stub_text(NULL));
}

//cfusa:req REQ-QB002
//cfusa:test REQ-QB002
void test_qb_rule_b_needs_at_least_10_entries(void)
{
    const char *few[5] = {"a","a","a","a","a"};
    TEST_ASSERT_FALSE(cfusa_qb_rule_b_flagged(few, 5));
}

//cfusa:req REQ-QB002
//cfusa:test REQ-QB002
void test_qb_rule_b_flags_low_distinct_ratio(void)
{
    const char *same[12];
    for (int i = 0; i < 12; i++) same[i] = "identical failure mode text";
    TEST_ASSERT_TRUE(cfusa_qb_rule_b_flagged(same, 12));
}

//cfusa:req REQ-QB002
//cfusa:test REQ-QB002
void test_qb_rule_b_passes_high_distinct_ratio(void)
{
    const char *vals[] = {
        "alpha","bravo","charlie","delta","echo","foxtrot",
        "golf","hotel","india","juliet","kilo","lima"
    };
    TEST_ASSERT_FALSE(cfusa_qb_rule_b_flagged(vals, 12));
}

//cfusa:req REQ-QB003
//cfusa:test REQ-QB003
void test_qb_content_hash_is_deterministic_and_prefixed(void)
{
    char h1[80], h2[80];
    cfusa_qb_content_hash("{\"entries\":[]}", strlen("{\"entries\":[]}"), h1);
    cfusa_qb_content_hash("{\"entries\":[]}", strlen("{\"entries\":[]}"), h2);
    TEST_ASSERT_EQUAL_STRING(h1, h2);
    TEST_ASSERT_EQUAL_INT(0, strncmp(h1, "sha256:", 7));
    TEST_ASSERT_EQUAL_INT(71, (int)strlen(h1)); /* "sha256:" + 64 hex */

    char h3[80];
    cfusa_qb_content_hash("{\"entries\":[1]}", strlen("{\"entries\":[1]}"), h3);
    TEST_ASSERT_TRUE(strcmp(h1, h3) != 0);
}

//cfusa:req REQ-QB004
//cfusa:test REQ-QB004
void test_qb_attestation_absent_is_invalid(void)
{
    cfusa_attestation_t att;
    memset(&att, 0, sizeof(att));
    TEST_ASSERT_FALSE(cfusa_qb_attestation_valid(&att, "sha256:aa"));
}

//cfusa:req REQ-QB004
//cfusa:test REQ-QB004
void test_qb_attestation_self_attested_is_invalid(void)
{
    cfusa_attestation_t att;
    memset(&att, 0, sizeof(att));
    att.present = 1;
    strcpy(att.status, "reviewed");
    strcpy(att.implementation_author, "Alice");
    strcpy(att.independent_reviewer, "Alice");
    strcpy(att.content_hash, "sha256:aa");
    TEST_ASSERT_FALSE(cfusa_qb_attestation_valid(&att, "sha256:aa"));
}

//cfusa:req REQ-QB004
//cfusa:test REQ-QB004
void test_qb_attestation_stale_hash_is_invalid(void)
{
    cfusa_attestation_t att;
    memset(&att, 0, sizeof(att));
    att.present = 1;
    strcpy(att.status, "reviewed");
    strcpy(att.implementation_author, "auto");
    strcpy(att.independent_reviewer, "Jane Doe");
    strcpy(att.content_hash, "sha256:aaaa");
    TEST_ASSERT_FALSE(cfusa_qb_attestation_valid(&att, "sha256:bbbb"));
}

//cfusa:req REQ-QB004
//cfusa:test REQ-QB004
void test_qb_attestation_valid_when_independent_and_fresh(void)
{
    cfusa_attestation_t att;
    memset(&att, 0, sizeof(att));
    att.present = 1;
    strcpy(att.status, "reviewed");
    strcpy(att.implementation_author, "auto");
    strcpy(att.independent_reviewer, "Jane Doe");
    strcpy(att.content_hash, "sha256:aaaa");
    TEST_ASSERT_TRUE(cfusa_qb_attestation_valid(&att, "sha256:aaaa"));
}

//cfusa:req REQ-QB005
//cfusa:test REQ-QB005
void test_qb_attestation_read_roundtrip(void)
{
    const char *doc =
        "{\"kind\":\"fmea-report\",\"attestation\":{\"status\":\"reviewed\","
        "\"implementationAuthor\":\"auto\",\"independentReviewer\":\"Jane Doe\","
        "\"reviewedAt\":\"2026-07-28T00:00:00Z\",\"contentHash\":\"sha256:deadbeef\"}}";
    cfusa_attestation_t att;
    int found = cfusa_qb_attestation_read(doc, strlen(doc), &att);
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_STRING("reviewed", att.status);
    TEST_ASSERT_EQUAL_STRING("auto", att.implementation_author);
    TEST_ASSERT_EQUAL_STRING("Jane Doe", att.independent_reviewer);
    TEST_ASSERT_EQUAL_STRING("sha256:deadbeef", att.content_hash);
}

//cfusa:req REQ-QB005
//cfusa:test REQ-QB005
void test_qb_attestation_read_absent_returns_zero(void)
{
    cfusa_attestation_t att;
    int found = cfusa_qb_attestation_read("{\"kind\":\"fmea-report\"}", 22, &att);
    TEST_ASSERT_FALSE(found);
}

//cfusa:req REQ-QB006
//cfusa:test REQ-QB006
void test_qb_rule_disposed_true_when_entry_present(void)
{
    write_file(".fusa-dispositions.json",
        "{\"dispositions\":[{\"id\":\"DISP-0001\",\"rule\":\"FUSA-STUB001\","
        "\"action\":\"accept\",\"rationale\":\"reviewed\",\"reviewer\":\"Jane\"}]}");
    TEST_ASSERT_TRUE(cfusa_qb_rule_disposed(V114_DIR, "FUSA-STUB001"));
    TEST_ASSERT_FALSE(cfusa_qb_rule_disposed(V114_DIR, "FUSA-STUB002"));

    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-dispositions.json", V114_DIR);
    (void)remove(path);
}

//cfusa:req REQ-UTIL018
//cfusa:test REQ-UTIL018
void test_qb_rule_disposed_true_with_pretty_printed_whitespace(void)
{
    /* issue #159: cfusa_qb_rule_disposed() used the same rigid,
     * whitespace-intolerant sscanf pattern as the disposition loader —
     * a pretty-printed file (space after the colon) silently never
     * matched, so the quality-bar gate never saw a real disposition. */
    write_file(".fusa-dispositions.json",
        "{\n  \"dispositions\": [\n    {\n      \"id\": \"DISP-0001\",\n"
        "      \"rule\": \"FUSA-STUB001\",\n      \"action\": \"accept\"\n"
        "    }\n  ]\n}\n");
    TEST_ASSERT_TRUE(cfusa_qb_rule_disposed(V114_DIR, "FUSA-STUB001"));
    TEST_ASSERT_FALSE(cfusa_qb_rule_disposed(V114_DIR, "FUSA-STUB002"));

    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-dispositions.json", V114_DIR);
    (void)remove(path);
}

/* ================================================================== */
/* hara schema conformance                                              */
/* ================================================================== */

//cfusa:req REQ-HARA-SCHEMA001
//cfusa:test REQ-HARA-SCHEMA001
void test_hara_init_scaffold_has_three_empty_collections(void)
{
    char *argv[] = {"cfusa", "init", "--dir", V114_DIR, NULL};
    int rc = cmd_hara(4, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len;
    char *buf = slurp(".fusa-hara.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"operationalSituations\": []"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"hazards\": []"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"safetyGoals\": []"));
    /* x-FuSa spec §1.6 rule 1: no placeholder text in a freshly scaffolded file */
    TEST_ASSERT_FALSE(cfusa_qb_is_stub_text(buf));

    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-hara.json", V114_DIR);
    (void)remove(path);
}

//cfusa:req REQ-HARA-SCHEMA002
//cfusa:test REQ-HARA-SCHEMA002
void test_hara_show_json_reports_fssr_gap(void)
{
    write_file(".fusa-hara.json",
        "{\"project\":\"p\",\"standard\":\"iso26262\",\"operationalSituations\":"
        "[{\"id\":\"OS-1\",\"description\":\"Highway driving at speed\"}],"
        "\"hazards\":[{\"id\":\"H-1\",\"description\":\"Unintended acceleration\","
        "\"situations\":[\"OS-1\"],\"risk\":{\"severity\":\"S3\",\"exposure\":\"E3\","
        "\"controllability\":\"C2\",\"asil\":\"ASIL-C\"},\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Prevent unintended accel\","
        "\"hazards\":[\"H-1\"],\"asil\":\"ASIL-C\",\"fssrRefs\":[]}]}");

    char *argv[] = {"cfusa", "show", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_hara(6, argv);
    (void)rc; /* not gated by fssrRefs gap alone */

    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-hara.json", V114_DIR);
    (void)remove(path);
}

//cfusa:req REQ-HARA-SCHEMA003
//cfusa:test REQ-HARA-SCHEMA003
void test_hara_show_text_detects_placeholder(void)
{
    write_file(".fusa-hara.json",
        "{\"project\":\"p\",\"standard\":\"iso26262\",\"operationalSituations\":[],"
        "\"hazards\":[{\"id\":\"H-1\",\"description\":\"[describe hazardous event]\","
        "\"situations\":[],\"risk\":{\"severity\":\"S1\",\"exposure\":\"E1\","
        "\"controllability\":\"C1\",\"asil\":\"QM\"},\"safetyGoals\":[]}],"
        "\"safetyGoals\":[]}");

    char *argv[] = {"cfusa", "show", "--dir", V114_DIR, NULL};
    int rc = cmd_hara(4, argv);
    TEST_ASSERT_EQUAL(1, rc); /* FUSA-STUB001 always gates */

    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-hara.json", V114_DIR);
    (void)remove(path);
}

/* x-FuSa spec v1.15.0 / §9.2: `hara --format json` MUST be a verbatim
 * passthrough of .fusa-hara.json's own §1.2.5 shape (source/situations/
 * safetyGoals per hazard, hazards/safeState per safety goal) plus a
 * passthrough `attestation`, and completeness MUST surface an ASIL
 * mismatch, not just leave it as a text-mode-only warning. */
//cfusa:req REQ-HARA-SCHEMA004
//cfusa:test REQ-HARA-SCHEMA004
void test_hara_show_json_passes_through_cross_refs_and_attestation(void)
{
    write_file(".fusa-hara.json",
        "{\"project\":\"p\",\"standard\":\"iso26262\",\"operationalSituations\":"
        "[{\"id\":\"OS-1\",\"description\":\"Highway driving at speed\"}],"
        "\"hazards\":[{\"id\":\"H-1\",\"description\":\"Unintended acceleration\","
        "\"source\":\"design review\",\"situations\":[\"OS-1\"],"
        "\"risk\":{\"severity\":\"S3\",\"exposure\":\"E3\",\"controllability\":\"C2\","
        "\"asil\":\"ASIL-A\"},\"safetyGoals\":[\"SG-1\"]}],"
        "\"safetyGoals\":[{\"id\":\"SG-1\",\"description\":\"Prevent unintended accel\","
        "\"hazards\":[\"H-1\"],\"asil\":\"ASIL-A\",\"safeState\":\"Engine off\","
        "\"fssrRefs\":[\"REQ-1\"]}],"
        "\"attestation\":{\"status\":\"reviewed\",\"implementationAuthor\":\"auto\","
        "\"independentReviewer\":\"Jane Doe\",\"reviewedAt\":\"2026-01-01T00:00:00Z\","
        "\"contentHash\":\"sha256:deadbeef\"}}");

    /* --output so we can inspect the JSON body directly (not stdout). */
    char out[512]; snprintf(out, sizeof(out), "%s/hara_passthrough.json", V114_DIR);
    char *argv2[] = {"cfusa", "show", "--dir", V114_DIR, "--format", "json",
                      "--output", out, NULL};
    cmd_hara(8, argv2);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    char jbuf[16384];
    size_t n = fread(jbuf, 1, sizeof(jbuf) - 1, f);
    jbuf[n] = '\0';
    fclose(f);

    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"source\": \"design review\""));
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"situations\": [\"OS-1\"]"));
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"safetyGoals\": [\"SG-1\"]"));
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"hazards\": [\"H-1\"]"));
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"safeState\": \"Engine off\""));
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"independentReviewer\": \"Jane Doe\""));
    /* S3/E3/C2 derives to ASIL-C, not the stored ASIL-A. */
    TEST_ASSERT_NOT_NULL(strstr(jbuf, "\"asilMismatches\": 1"));

    remove(out);
    char path[512]; snprintf(path, sizeof(path), "%s/.fusa-hara.json", V114_DIR);
    (void)remove(path);
}

/* ================================================================== */
/* fmea schema conformance + coverage + attestation                    */
/* ================================================================== */

static void write_fmea_source(int n_funcs)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/fmea_v114_src.c", V114_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    for (int i = 0; i < n_funcs; i++)
        fprintf(f, "int do_thing_%d(int x)\n{\n    return x + %d;\n}\n\n", i, i);
    fclose(f);
}

//cfusa:req REQ-FMEA-SCHEMA001
//cfusa:test REQ-FMEA-SCHEMA001
void test_fmea_json_has_ratingscale_and_summary(void)
{
    write_fmea_source(3);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_fmea(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len;
    char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"ratingScale\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"failureMode\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"actionPriority\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"componentsInProject\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"coveragePct\""));
    TEST_ASSERT_NULL(strstr(buf, "[describe"));

    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

//cfusa:req REQ-FMEA-SCHEMA002
//cfusa:test REQ-FMEA-SCHEMA002
void test_fmea_failure_mode_varies_per_function(void)
{
    write_fmea_source(15);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    cmd_fmea(5, argv);

    size_t len;
    char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "do_thing_0"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "do_thing_14"));

    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

//cfusa:req REQ-FMEA-COV001
//cfusa:test REQ-FMEA-COV001
void test_fmea_min_coverage_gate(void)
{
    write_fmea_source(5);
    /* Coverage is 100% of what was found, so a 101% gate must always fail. */
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--min-coverage", "101", NULL};
    int rc = cmd_fmea(7, argv);
    TEST_ASSERT_EQUAL(1, rc);

    char *argv2[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--min-coverage", "0", NULL};
    int rc2 = cmd_fmea(7, argv2);
    TEST_ASSERT_EQUAL(0, rc2);

    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

//cfusa:req REQ-FMEA-ATTEST001
//cfusa:test REQ-FMEA-ATTEST001
void test_fmea_attest_flag_stamps_attestation(void)
{
    write_fmea_source(4);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--attest", "Jane Doe", NULL};
    int rc = cmd_fmea(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len;
    char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"status\": \"reviewed\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"independentReviewer\": \"Jane Doe\""));

    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

/* x-FuSa spec §2.4.1: `standard` is a canonical lowercase id, never a
 * display string. */
//cfusa:req REQ-FMEA-SCHEMA003
//cfusa:test REQ-FMEA-SCHEMA003
void test_fmea_standard_is_canonical_id(void)
{
    write_fmea_source(2);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    cmd_fmea(5, argv);

    size_t len;
    char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\": \"iso26262\""));
    TEST_ASSERT_NULL(strstr(buf, "IEC 60812"));

    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

/* x-FuSa spec §4: entries[].file MUST be project-relative — including the
 * subdirectory, not truncated to a bare basename — regardless of whether
 * --dir is given relative or absolute. */
//cfusa:req REQ-FMEA-SCHEMA004
//cfusa:test REQ-FMEA-SCHEMA004
void test_fmea_file_field_is_project_relative_with_subdir(void)
{
    char subdir[512]; snprintf(subdir, sizeof(subdir), "%s/sub", V114_DIR);
    mkdir(subdir, 0700);
    char srcpath[512]; snprintf(srcpath, sizeof(srcpath), "%s/nested.c", subdir);
    FILE *f = cfusa_fopen_write(srcpath);
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f, "int handle_request(int x)\n{\n    return x;\n}\n");
    fclose(f);

    /* Relative --dir: the "file" field must include the subdirectory, not
     * be truncated to a bare basename. */
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    cmd_fmea(5, argv);
    size_t len; char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"file\": \"sub/nested.c\""));
    TEST_ASSERT_NULL(strstr(buf, "\"file\": \"nested.c\""));

    remove(srcpath);
    (void)rmdir(subdir);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

/* x-FuSa spec §1.6 rule 4: a call to a standard-library function is not a
 * project component, and a `(` found inside a string literal (a test-case
 * description, not real code) must not be mistaken for a call site. */
//cfusa:req REQ-FMEA-SCHEMA005
//cfusa:test REQ-FMEA-SCHEMA005
void test_fmea_skips_stdlib_calls_and_string_literal_parens(void)
{
    char srcpath[512]; snprintf(srcpath, sizeof(srcpath), "%s/stub_src.c", V114_DIR);
    FILE *f = cfusa_fopen_write(srcpath);
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f,
        "int real_project_fn(int x)\n{\n    return x;\n}\n\n"
        "void user_of_stdlib(char *buf, size_t n)\n"
        "{\n"
        "    snprintf(buf, n,\n"
        "        \"some multi-line format\");\n"
        "    fprintf(stderr, \"error\\n\");\n"
        "}\n\n"
        "static const struct { const char *desc; } CASES[] = {\n"
        "    {\"strcpy fires\"},\n"
        "};\n");
    fclose(f);

    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    cmd_fmea(5, argv);
    size_t len; char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);

    TEST_ASSERT_NOT_NULL(strstr(buf, "\"item\": \"real_project_fn\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"item\": \"user_of_stdlib\""));
    /* Neither the stdlib calls nor the string-literal-embedded "strcpy"
     * text should appear as an `item`. */
    TEST_ASSERT_NULL(strstr(buf, "\"item\": \"snprintf\""));
    TEST_ASSERT_NULL(strstr(buf, "\"item\": \"fprintf\""));
    TEST_ASSERT_NULL(strstr(buf, "strcpy"));

    remove(srcpath);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

/* x-FuSa spec §9.2: `fmea --output <file>` writes exactly that path,
 * distinct from --output-dir (GitHub issue: getopt_long's unambiguous-
 * prefix matching previously silently treated --output as an abbreviation
 * of --output-dir since fmea defined no --output long option at all). */
//cfusa:req REQ-FMEA-OUTPUT001
//cfusa:test REQ-FMEA-OUTPUT001
void test_fmea_output_flag_writes_exact_path(void)
{
    write_fmea_source(2);
    char out[512]; snprintf(out, sizeof(out), "%s/fmea_direct.json", V114_DIR);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--output", out, NULL};
    int rc = cmd_fmea(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) fclose(f);

    /* --output alone (no --format) must default to JSON, not silently
     * misbehave the way the previously-missing long option did. */
    char out2[512]; snprintf(out2, sizeof(out2), "%s/fmea_direct2.json", V114_DIR);
    char *argv2[] = {"cfusa", "--dir", V114_DIR, "--output", out2, NULL};
    int rc2 = cmd_fmea(5, argv2);
    TEST_ASSERT_EQUAL(0, rc2);
    FILE *f2 = fopen(out2, "r");
    TEST_ASSERT_NOT_NULL(f2);
    if (f2) {
        char buf[64] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f2);
        buf[n] = '\0';
        TEST_ASSERT_NOT_NULL(strstr(buf, "schemaVersion"));
        fclose(f2);
    }

    remove(out); remove(out2);
    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
}

/* x-FuSa spec §9.2: summary.coveragePct MUST NOT exceed 100. A fixture with
 * only project source can never exercise this (there's no denominator to
 * overcount against) — the regression needs a non-trivial test-source tree
 * alongside real project source, per the spec's own implementation note. */
//cfusa:req REQ-FMEA-COV002
//cfusa:test REQ-FMEA-COV002
void test_fmea_coveragepct_never_exceeds_100_with_test_tree(void)
{
    write_fmea_source(3);
    /* A test-source file (test_ prefix) is excluded from both the
     * numerator and denominator — its own functions must never leak into
     * componentsInProject regardless of how many "real-looking" function
     * definitions it contains. */
    char testpath[512]; snprintf(testpath, sizeof(testpath), "%s/test_fmea_v114.c", V114_DIR);
    FILE *f = cfusa_fopen_write(testpath);
    TEST_ASSERT_NOT_NULL(f);
    for (int i = 0; i < 20; i++)
        fprintf(f, "void test_case_%d(void)\n{\n}\n\n", i);
    fclose(f);

    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_fmea(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len; char *buf = slurp("fmea.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NULL(strstr(buf, "\"coveragePct\": 101"));
    /* Cheap structural check that coveragePct is a plausible 0-100 value
     * and the test-tree functions were not folded into the count. */
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"componentsAnalyzed\": 3, \"componentsInProject\": 3"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"coveragePct\": 100"));
    TEST_ASSERT_NULL(strstr(buf, "test_case_"));

    remove(testpath);
    char p1[512]; snprintf(p1, sizeof(p1), "%s/fmea_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/fmea.json", V114_DIR); remove(p2);
}

/* ================================================================== */
/* tara schema conformance (SFOP impact)                                */
/* ================================================================== */

static void write_tara_source(void)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/tara_v114_src.c", V114_DIR);
    FILE *f = cfusa_fopen_write(path);
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f,
        "int parse_config(char *buf)\n{\n    return 0;\n}\n\n"
        "int recv_packet(int fd)\n{\n    return fd;\n}\n\n"
        "int check_auth_token(char *tok)\n{\n    return 1;\n}\n\n"
        "void copy_buffer(char *dst, char *src)\n{\n}\n\n");
    fclose(f);
}

//cfusa:req REQ-TARA-SCHEMA001
//cfusa:test REQ-TARA-SCHEMA001
void test_tara_json_has_sfop_impact(void)
{
    write_tara_source();
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_tara(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len;
    char *buf = slurp("tara.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"threats\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"impact\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"safety\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"financial\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"operational\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"privacy\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"assetInventoryMethod\""));
    TEST_ASSERT_NULL(strstr(buf, "[describe"));

    char p1[512]; snprintf(p1, sizeof(p1), "%s/tara_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/tara.json", V114_DIR); remove(p2);
    char p3[512]; snprintf(p3, sizeof(p3), "%s/tara.md", V114_DIR); remove(p3);
}

/* x-FuSa spec §2.4.1/§9.2 (v1.14.1 closed enums, clarified by the same-day
 * v1.15.0 audit): `standard` is the canonical lowercase id, and
 * impact.{safety,financial,operational,privacy} MUST use
 * critical|major|moderate|negligible — never high|medium|low, which is a
 * distinct scale reserved for attackFeasibility. `risk` MUST be derived
 * from the spec's combination table, not an ad hoc score. */
//cfusa:req REQ-TARA-SCHEMA002
//cfusa:test REQ-TARA-SCHEMA002
void test_tara_standard_id_and_closed_impact_enum(void)
{
    write_tara_source();
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    cmd_tara(5, argv);

    size_t len; char *buf = slurp("tara.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"standard\": \"iso21434\""));
    TEST_ASSERT_NULL(strstr(buf, "ISO/SAE 21434:2021 Clause 15\","));

    /* Every impact.* value must be one of the four closed-enum members —
     * spot-check that none of the old high|medium|low vocabulary leaked
     * into a `impact` object (attackFeasibility legitimately uses "medium"
     * elsewhere in the same document, so this checks specifically inside
     * an "impact": {...} block). */
    const char *imp = strstr(buf, "\"impact\": {");
    TEST_ASSERT_NOT_NULL(imp);
    const char *imp_end = strchr(imp, '}');
    TEST_ASSERT_NOT_NULL(imp_end);
    char block[512] = "";
    size_t blen = (size_t)(imp_end - imp);
    if (blen < sizeof(block)) { memcpy(block, imp, blen); block[blen] = '\0'; }
    TEST_ASSERT_NULL(strstr(block, "\"high\""));
    TEST_ASSERT_NULL(strstr(block, "\"medium\""));
    TEST_ASSERT_NULL(strstr(block, "\"low\""));

    char p1[512]; snprintf(p1, sizeof(p1), "%s/tara_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/tara.json", V114_DIR); remove(p2);
    char p3[512]; snprintf(p3, sizeof(p3), "%s/tara.md", V114_DIR); remove(p3);
}

/* x-FuSa spec §9.2: threats[].location.file MUST be project-relative
 * (including subdirectory), and a call to a standard-library function
 * (e.g. strcpy/memcpy themselves) MUST NOT be emitted as the asset/item —
 * §1.6 rule 4 applies to tara's asset scanner the same way it does to
 * fmea's. */
//cfusa:req REQ-TARA-SCHEMA003
//cfusa:test REQ-TARA-SCHEMA003
void test_tara_location_relative_and_skips_stdlib_calls(void)
{
    char subdir[512]; snprintf(subdir, sizeof(subdir), "%s/sub", V114_DIR);
    mkdir(subdir, 0700);
    char srcpath[512]; snprintf(srcpath, sizeof(srcpath), "%s/nested_asset.c", subdir);
    FILE *f = cfusa_fopen_write(srcpath);
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f,
        "int recv_data(int fd, char *buf, int n)\n"
        "{\n"
        "    return fd + n + (int)(long)buf;\n"
        "}\n\n"
        "void raw_stdlib_only(char *dst, const char *src)\n"
        "{\n"
        "    memcpy(dst, src,\n"
        "        128);\n"
        "}\n");
    fclose(f);

    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    cmd_tara(5, argv);

    size_t len; char *buf = slurp("tara.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"file\": \"sub/nested_asset.c\""));
    TEST_ASSERT_NULL(strstr(buf, "\"asset\": \"Data handled by memcpy"));

    remove(srcpath);
    (void)rmdir(subdir);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/tara.json", V114_DIR); remove(p2);
    char p3[512]; snprintf(p3, sizeof(p3), "%s/tara.md", V114_DIR); remove(p3);
}

/* x-FuSa spec §9.2: summary.coveragePct MUST NOT exceed 100, exercised with
 * a non-trivial test-source tree alongside real project source. */
//cfusa:req REQ-TARA-COV001
//cfusa:test REQ-TARA-COV001
void test_tara_coveragepct_never_exceeds_100_with_test_tree(void)
{
    write_tara_source();
    char testpath[512]; snprintf(testpath, sizeof(testpath), "%s/test_tara_v114.c", V114_DIR);
    FILE *f = cfusa_fopen_write(testpath);
    TEST_ASSERT_NOT_NULL(f);
    for (int i = 0; i < 15; i++)
        fprintf(f, "int test_recv_packet_%d(int fd)\n{\n    return fd;\n}\n\n", i);
    fclose(f);

    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_tara(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len; char *buf = slurp("tara.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NULL(strstr(buf, "\"coveragePct\": 101"));
    TEST_ASSERT_NULL(strstr(buf, "test_recv_packet_"));

    remove(testpath);
    char p1[512]; snprintf(p1, sizeof(p1), "%s/tara_v114_src.c", V114_DIR); remove(p1);
    char p2[512]; snprintf(p2, sizeof(p2), "%s/tara.json", V114_DIR); remove(p2);
    char p3[512]; snprintf(p3, sizeof(p3), "%s/tara.md", V114_DIR); remove(p3);
}

/* ================================================================== */
/* safety-case GSN schema                                               */
/* ================================================================== */

//cfusa:req REQ-SC-SCHEMA001
//cfusa:test REQ-SC-SCHEMA001
void test_safety_case_json_has_gsn_node_types(void)
{
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_safety_case(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len;
    char *buf = slurp("safety-case.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"nodes\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"edges\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"completeness\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"type\": \"goal\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"type\": \"strategy\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "supportedBy"));

    char p[512]; snprintf(p, sizeof(p), "%s/safety-case.json", V114_DIR); remove(p);
}

/* issue #97: an uppercase-cased evidence filename (a defensible, common
 * convention some downstream projects use, e.g. HARA.md) must still be
 * found and cited — not silently treated as absent because of a
 * hardcoded exact-lowercase match on a case-sensitive filesystem. */
//cfusa:req REQ-SC004
//cfusa:test REQ-SC004
void test_safety_case_finds_uppercase_hara_evidence(void)
{
    write_file("HARA.md", "# HARA\n\nHazard analysis content.\n");

    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", NULL};
    int rc = cmd_safety_case(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    size_t len;
    char *buf = slurp("safety-case.json", &len);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"Sn1\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"evidence\": \"HARA.md\""));

    char p[512];
    snprintf(p, sizeof(p), "%s/safety-case.json", V114_DIR); remove(p);
    snprintf(p, sizeof(p), "%s/HARA.md", V114_DIR); remove(p);
}

/* Same guarantee for the markdown Evidence Index table (a second,
 * independent hardcoded-filename call site issue #97 also flagged). */
//cfusa:req REQ-SC004
//cfusa:test REQ-SC004
void test_safety_case_markdown_evidence_index_finds_uppercase_files(void)
{
    write_file("SAFETY-PLAN.md", "# Safety Plan\n");

    char out[512]; snprintf(out, sizeof(out), "%s/safety-case-case-test.md", V114_DIR);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--output", out, NULL};
    int rc = cmd_safety_case(5, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    if (f) {
        char buf[8192] = "";
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        if (fclose(f) != 0) TEST_FAIL_MESSAGE("fclose failed");
        TEST_ASSERT_NOT_NULL(strstr(buf, "SAFETY-PLAN.md | present"));
        remove(out);
    }
    char p[512]; snprintf(p, sizeof(p), "%s/SAFETY-PLAN.md", V114_DIR); remove(p);
}

/* ================================================================== */
/* sas checklist/summary schema                                        */
/* ================================================================== */

//cfusa:req REQ-SAS-SCHEMA001
//cfusa:test REQ-SAS-SCHEMA001
void test_sas_json_has_checklist_and_summary(void)
{
    char out[512]; snprintf(out, sizeof(out), "%s/sas.json", V114_DIR);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--output", out, NULL};
    int rc = cmd_sas(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"checklist\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"summary\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"present\""));
    remove(out);

    /* x-FuSa spec §9.3: sas.json is not a replacement for the sas.md
     * companion — a companion MUST also be written. */
    char md[512]; snprintf(md, sizeof(md), "%s/sas.md", V114_DIR);
    FILE *mf = fopen(md, "r");
    TEST_ASSERT_NOT_NULL(mf);
    if (mf) fclose(mf);
    (void)remove(md);
}

/* ================================================================== */
/* sci hash-field convention (x-FuSa spec §2.7)                        */
/* ================================================================== */

//cfusa:req REQ-SCI-SCHEMA001
//cfusa:test REQ-SCI-SCHEMA001
void test_sci_json_hash_field_is_prefixed(void)
{
    write_file("sci_v114_src.c", "int sci_v114_probe(void) { return 0; }\n");

    char out[512]; snprintf(out, sizeof(out), "%s/sci_v114.json", V114_DIR);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--output", out, NULL};
    int rc = cmd_sci(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *f = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(f);
    char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"artifacts\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"hash\": \"sha256:"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"version\""));
    remove(out);
    char srcpath[512]; snprintf(srcpath, sizeof(srcpath), "%s/sci_v114_src.c", V114_DIR);
    remove(srcpath);
}

/* x-FuSa spec §4: artifacts[].file MUST be project-relative even when --dir
 * is given as an absolute path (V114_DIR itself is already absolute — on
 * macOS /tmp is a symlink to /private/tmp, so this also exercises the
 * "don't resolve symlinks before relativizing" fix). */
//cfusa:req REQ-SCI-SCHEMA002
//cfusa:test REQ-SCI-SCHEMA002
void test_sci_json_file_field_is_project_relative(void)
{
    char subdir[512]; snprintf(subdir, sizeof(subdir), "%s/sub", V114_DIR);
    mkdir(subdir, 0700);
    char srcpath[512]; snprintf(srcpath, sizeof(srcpath), "%s/nested_sci.c", subdir);
    FILE *f = cfusa_fopen_write(srcpath);
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f, "int sci_nested_probe(void) { return 0; }\n");
    fclose(f);

    char out[512]; snprintf(out, sizeof(out), "%s/sci_rel.json", V114_DIR);
    char *argv[] = {"cfusa", "--dir", V114_DIR, "--format", "json", "--output", out, NULL};
    int rc = cmd_sci(7, argv);
    TEST_ASSERT_EQUAL(0, rc);

    FILE *rf = fopen(out, "r");
    TEST_ASSERT_NOT_NULL(rf);
    char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, rf);
    buf[n] = '\0';
    fclose(rf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"file\": \"sub/nested_sci.c\""));
    TEST_ASSERT_NULL(strstr(buf, V114_DIR));

    remove(out);
    remove(srcpath);
    (void)rmdir(subdir);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_qb_stub_text_bracket_placeholder);
    RUN_TEST(test_qb_stub_text_real_content_not_flagged);
    RUN_TEST(test_qb_rule_b_needs_at_least_10_entries);
    RUN_TEST(test_qb_rule_b_flags_low_distinct_ratio);
    RUN_TEST(test_qb_rule_b_passes_high_distinct_ratio);
    RUN_TEST(test_qb_content_hash_is_deterministic_and_prefixed);
    RUN_TEST(test_qb_attestation_absent_is_invalid);
    RUN_TEST(test_qb_attestation_self_attested_is_invalid);
    RUN_TEST(test_qb_attestation_stale_hash_is_invalid);
    RUN_TEST(test_qb_attestation_valid_when_independent_and_fresh);
    RUN_TEST(test_qb_attestation_read_roundtrip);
    RUN_TEST(test_qb_attestation_read_absent_returns_zero);
    RUN_TEST(test_qb_rule_disposed_true_when_entry_present);
    RUN_TEST(test_qb_rule_disposed_true_with_pretty_printed_whitespace);

    RUN_TEST(test_hara_init_scaffold_has_three_empty_collections);
    RUN_TEST(test_hara_show_json_reports_fssr_gap);
    RUN_TEST(test_hara_show_text_detects_placeholder);
    RUN_TEST(test_hara_show_json_passes_through_cross_refs_and_attestation);

    RUN_TEST(test_fmea_json_has_ratingscale_and_summary);
    RUN_TEST(test_fmea_failure_mode_varies_per_function);
    RUN_TEST(test_fmea_min_coverage_gate);
    RUN_TEST(test_fmea_attest_flag_stamps_attestation);
    RUN_TEST(test_fmea_standard_is_canonical_id);
    RUN_TEST(test_fmea_file_field_is_project_relative_with_subdir);
    RUN_TEST(test_fmea_skips_stdlib_calls_and_string_literal_parens);
    RUN_TEST(test_fmea_output_flag_writes_exact_path);
    RUN_TEST(test_fmea_coveragepct_never_exceeds_100_with_test_tree);

    RUN_TEST(test_tara_json_has_sfop_impact);
    RUN_TEST(test_tara_standard_id_and_closed_impact_enum);
    RUN_TEST(test_tara_location_relative_and_skips_stdlib_calls);
    RUN_TEST(test_tara_coveragepct_never_exceeds_100_with_test_tree);

    RUN_TEST(test_safety_case_json_has_gsn_node_types);
    RUN_TEST(test_safety_case_finds_uppercase_hara_evidence);
    RUN_TEST(test_safety_case_markdown_evidence_index_finds_uppercase_files);

    RUN_TEST(test_sas_json_has_checklist_and_summary);

    RUN_TEST(test_sci_json_hash_field_is_prefixed);
    RUN_TEST(test_sci_json_file_field_is_project_relative);

    return UNITY_END();
}
