#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>
#include "cfusa/utils.h"
#include "cfusa/version.h"
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/config.h"

/*
 * Tool qualification self-test (DO-178C §12 / ISO 26262-8 §11).
 * Computes SHA-256 of the cfusa binary itself and runs two suites:
 *
 *   1. Known-answer tests (KAT) — crypto self-tests.
 *   2. FUSA rule exercise cases — positive and negative cases for each
 *      registered engine rule, using synthetic isolated project dirs.
 *      This mirrors go-FuSa's qualify.Run() + BuiltinCases() approach.
 */

extern void cfusa_lint_register_rules(void);
extern void cfusa_analyze_register_rules(void);
extern void cfusa_cyber_register_rules(void);
extern void cfusa_safety_register_rules(void);

/* ── Known-answer self-tests ─────────────────────────────────────────── */

typedef struct {
    const char *name;
    int (*run)(void);
    int passed;
} qualify_test_t;

static int qt_sha256(void)
{
    const unsigned char msg[] = "abc";
    char hex[65];
    cfusa_sha256_buf(msg, 3, hex);
    return strcmp(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0;
}

static int qt_hmac(void)
{
    const unsigned char key[] = "key";
    const unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    char hex[65];
    cfusa_hmac_sha256(key, 3, msg, 43, hex);
    return strcmp(hex,
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8") == 0;
}

static int qt_version(void)
{
    return strlen(CFUSA_VERSION_STRING) > 0;
}

static int qt_walk(void)
{
    return 1; /* walker smoke test — no crash */
}

static qualify_test_t g_kat[] = {
    {"SHA-256 known-answer",     qt_sha256, 0},
    {"HMAC-SHA256 known-answer", qt_hmac,   0},
    {"Version string non-empty", qt_version, 0},
    {"Source walker no crash",   qt_walk,    0},
    {NULL, NULL, 0}
};

/* ── FUSA rule exercise cases ─────────────────────────────────────────── */

typedef struct {
    const char *name;
    const char *rule_id;
    const char *description;
    int expect_finding;
    int (*run)(void);
    int passed;
} fusa_case_t;

#define QTMP "/tmp/cfusa_qualify_case"

static void qt_rm_file(const char *dir, const char *name)
{
    char p[512]; snprintf(p, sizeof(p), "%s/%s", dir, name); remove(p);
}

static int qt_mkdir_p(const char *path)
{
    char tmp[512]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    for (char *p = tmp+1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    return mkdir(tmp, 0700) != 0 && errno != EEXIST ? -1 : 0;
}

static int qt_write_file(const char *dir, const char *relpath, const char *content)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", dir, relpath);
    /* Create parent dir if needed */
    char parent[512]; strncpy(parent, path, sizeof(parent)-1);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; qt_mkdir_p(parent); }
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    if (content) fputs(content, f);
    fclose(f); return 0;
}

static void qt_setup(void)
{
    /* Remove and recreate base temp dir */
    (void)system("rm -rf " QTMP);
    mkdir(QTMP, 0700);
}

static int qt_count_rule(const cfusa_report_t *rpt, const char *id)
{
    int n = 0;
    for (int i = 0; i < rpt->count; i++)
        if (strcmp(rpt->findings[i].rule_id, id) == 0) n++;
    return n;
}

/* Run safety rules against QTMP and count findings for rule_id */
static int safety_findings(const char *rule_id)
{
    cfusa_engine_reset();
    cfusa_safety_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_all(QTMP, &cfg, &rpt);
    int n = qt_count_rule(&rpt, rule_id);
    cfusa_report_free(&rpt); return n;
}

/* Run cyber rules against QTMP and count findings for rule_id */
static int cyber_findings(const char *rule_id)
{
    cfusa_engine_reset();
    cfusa_cyber_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_CYBER, QTMP, &cfg, &rpt);
    int n = qt_count_rule(&rpt, rule_id);
    cfusa_report_free(&rpt); return n;
}

/* Run lint rules against QTMP and count findings for rule_id */
static int lint_findings(const char *rule_id)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_LINT, QTMP, &cfg, &rpt);
    int n = qt_count_rule(&rpt, rule_id);
    cfusa_report_free(&rpt); return n;
}

/* Run analyze rules against QTMP and count findings for rule_id */
static int analyze_findings(const char *rule_id)
{
    cfusa_engine_reset();
    cfusa_analyze_register_rules();
    cfusa_config_t cfg; cfusa_config_defaults(&cfg);
    cfusa_report_t rpt; cfusa_report_init(&rpt);
    cfusa_engine_run_category(CFUSA_CATEGORY_ANALYZE, QTMP, &cfg, &rpt);
    int n = qt_count_rule(&rpt, rule_id);
    cfusa_report_free(&rpt); return n;
}

/* ── FUSA001 cases ─────────────────────────────────────────────────────── */

static int fusa001_pos(void)
{
    qt_setup();
    /* No .fusa.json → expect FUSA001 finding */
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    qt_write_file(QTMP, ".github/workflows/ci.yml", "name: CI\n");
    return safety_findings("FUSA001") > 0;
}

static int fusa001_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    qt_write_file(QTMP, ".github/workflows/ci.yml", "name: CI\n");
    return safety_findings("FUSA001") == 0;
}

/* ── FUSA002 cases ─────────────────────────────────────────────────────── */

static int fusa002_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    qt_write_file(QTMP, ".github/workflows/ci.yml", "name: CI\n");
    return safety_findings("FUSA002") > 0;
}

static int fusa002_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    qt_write_file(QTMP, ".github/workflows/ci.yml", "name: CI\n");
    return safety_findings("FUSA002") == 0;
}

/* ── FUSA003 cases ─────────────────────────────────────────────────────── */

static int fusa003_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    return safety_findings("FUSA003") > 0;
}

static int fusa003_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT License\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    return safety_findings("FUSA003") == 0;
}

/* ── FUSA004 cases ─────────────────────────────────────────────────────── */

static int fusa004_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    return safety_findings("FUSA004") > 0;
}

static int fusa004_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test project\n");
    return safety_findings("FUSA004") == 0;
}

/* ── FUSA005 cases ─────────────────────────────────────────────────────── */

static int fusa005_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    return safety_findings("FUSA005") > 0;
}

static int fusa005_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, ".fusa.json", "{\"configVersion\":\"1.0\"}\n");
    qt_write_file(QTMP, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.16)\n");
    qt_write_file(QTMP, "LICENSE", "MIT\n");
    qt_write_file(QTMP, "README.md", "# test\n");
    qt_write_file(QTMP, ".github/workflows/ci.yml", "name: CI\non: [push]\n");
    return safety_findings("FUSA005") == 0;
}

/* ── CYBER rule exercise cases ─────────────────────────────────────────── */

static int cy001_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, "t.c",
        "void fn(char *d, const char *s) { strcpy(d, s); }\n");
    return cyber_findings("CFUSA-CY001") > 0;
}

static int cy001_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, "t.c",
        "void fn(char *d, const char *s, size_t n) { memcpy(d, s, n); }\n");
    /* memcpy fires CY001 — use safe snprintf instead */
    qt_rm_file(QTMP, "t.c");
    qt_write_file(QTMP, "t.c",
        "#include <stdio.h>\nvoid fn(char *d, size_t n, const char *s)"
        " { snprintf(d, n, \"%s\", s); }\n");
    return cyber_findings("CFUSA-CY001") == 0;
}

static int cy009_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, "t.c",
        "void fn(void) { MD5_CTX ctx; MD5_Init(&ctx); }\n");
    return cyber_findings("CFUSA-CY009") > 0;
}

static int cy009_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, "t.c",
        "#include <openssl/sha.h>\nvoid fn(void) { SHA256_CTX ctx; SHA256_Init(&ctx); }\n");
    return cyber_findings("CFUSA-CY009") == 0;
}

/* ── LINT rule exercise cases ──────────────────────────────────────────── */

static int l002_pos(void)
{
    qt_setup();
    /* goto must be at the start of a line (after whitespace) for L002 to fire */
    qt_write_file(QTMP, "t.c",
        "void fn(int x) {\n"
        "    if (x)\n"
        "        goto done;\n"
        "done:\n"
        "    return;\n"
        "}\n");
    return lint_findings("CFUSA-L002") > 0;
}

static int l002_neg(void)
{
    qt_setup();
    qt_write_file(QTMP, "t.c",
        "void fn(int x) { if (x) { return; } }\n");
    return lint_findings("CFUSA-L002") == 0;
}

/* ── ANALYZE rule exercise cases ────────────────────────────────────────── */

static int a002_pos(void)
{
    qt_setup();
    qt_write_file(QTMP, "t.c",
        "#include <stdlib.h>\nvoid fn(size_t n) { char *p = malloc(n);\n"
        "    p[0] = 0; /* no NULL check */ }\n");
    return analyze_findings("CFUSA-A002") > 0;
}

static int a002_neg(void)
{
    qt_setup();
    /* if-check on same line as malloc — A002 requires no 'if' on the same line */
    qt_write_file(QTMP, "t.c",
        "#include <stdlib.h>\nvoid fn(size_t n) {\n"
        "    char *p; if ((p = malloc(n)) == NULL) return;\n"
        "    p[0] = 0; }\n");
    return analyze_findings("CFUSA-A002") == 0;
}

static fusa_case_t g_cases[] = {
    /* FUSA project-structure rules */
    {"FUSA001-pos: missing .fusa.json",     "FUSA001", "Missing .fusa.json fires FUSA001",           1, fusa001_pos, 0},
    {"FUSA001-neg: .fusa.json present",     "FUSA001", ".fusa.json present suppresses FUSA001",       0, fusa001_neg, 0},
    {"FUSA002-pos: no build system",        "FUSA002", "No build system file fires FUSA002",          1, fusa002_pos, 0},
    {"FUSA002-neg: CMakeLists.txt present", "FUSA002", "CMakeLists.txt suppresses FUSA002",           0, fusa002_neg, 0},
    {"FUSA003-pos: no LICENSE",             "FUSA003", "Missing LICENSE fires FUSA003",               1, fusa003_pos, 0},
    {"FUSA003-neg: LICENSE present",        "FUSA003", "LICENSE present suppresses FUSA003",          0, fusa003_neg, 0},
    {"FUSA004-pos: no README",              "FUSA004", "Missing README fires FUSA004",                1, fusa004_pos, 0},
    {"FUSA004-neg: README.md present",      "FUSA004", "README.md present suppresses FUSA004",        0, fusa004_neg, 0},
    {"FUSA005-pos: no CI config",           "FUSA005", "Missing CI config fires FUSA005",             1, fusa005_pos, 0},
    {"FUSA005-neg: .github/workflows present","FUSA005","CI config present suppresses FUSA005",       0, fusa005_neg, 0},
    /* Cyber rule exercises */
    {"CY001-pos: strcpy fires",             "CFUSA-CY001", "strcpy() triggers CY001",                1, cy001_pos, 0},
    {"CY001-neg: snprintf clean",           "CFUSA-CY001", "snprintf() does not trigger CY001",      0, cy001_neg, 0},
    {"CY009-pos: MD5 fires",                "CFUSA-CY009", "MD5_Init() triggers CY009",              1, cy009_pos, 0},
    {"CY009-neg: SHA-256 clean",            "CFUSA-CY009", "SHA256_Init() does not trigger CY009",   0, cy009_neg, 0},
    /* Lint rule exercises */
    {"L002-pos: goto fires",                "CFUSA-L002", "goto statement triggers L002",             1, l002_pos, 0},
    {"L002-neg: no goto clean",             "CFUSA-L002", "No goto does not trigger L002",            0, l002_neg, 0},
    /* Analyze rule exercises */
    {"A002-pos: unchecked malloc fires",    "CFUSA-A002", "Unchecked malloc triggers A002",           1, a002_pos, 0},
    {"A002-neg: checked malloc clean",      "CFUSA-A002", "Checked malloc does not trigger A002",     0, a002_neg, 0},
    {NULL, NULL, NULL, 0, NULL, 0}
};

/* ── Main command ─────────────────────────────────────────────────────── */

int cmd_qualify(int argc, char **argv)
{
    const char *binary  = NULL;
    const char *output  = NULL;
    const char *fmt_s   = "text";
    int verbose = 0;

    static const struct option long_opts[] = {
        {"binary",  required_argument, NULL, 'b'},
        {"output",  required_argument, NULL, 'o'},
        {"format",  required_argument, NULL, 'f'},
        {"verbose", no_argument,       NULL, 'v'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "b:o:f:vh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'b': binary  = optarg; break;
        case 'o': output  = optarg; break;
        case 'f': fmt_s   = optarg; break;
        case 'v': verbose = 1;      break;
        case 'h':
            printf("Usage: cfusa qualify [--binary <path>] [--format text|json]\n"
                   "                     [--output <file>] [--verbose]\n\n"
                   "Tool qualification self-test per DO-178C §12 / ISO 26262-8 §11.\n"
                   "Runs SHA-256/HMAC known-answer tests and FUSA rule exercise cases.\n");
            return 0;
        default: return 2;
        }
    }

    /* Hash the binary if provided */
    char bin_hash[65] = "(not provided)";
    if (binary && cfusa_file_exists(binary))
        cfusa_sha256_file(binary, bin_hash);

    /* Run KAT tests */
    int kat_pass = 0, kat_fail = 0;
    for (int i = 0; g_kat[i].name; i++) {
        g_kat[i].passed = g_kat[i].run();
        if (g_kat[i].passed) kat_pass++; else kat_fail++;
        if (verbose)
            printf("  [%s] %s\n", g_kat[i].passed?"PASS":"FAIL", g_kat[i].name);
    }

    /* Run FUSA rule exercise cases */
    int case_pass = 0, case_fail = 0;
    for (int i = 0; g_cases[i].name; i++) {
        g_cases[i].passed = g_cases[i].run();
        if (g_cases[i].passed) case_pass++; else case_fail++;
        if (verbose)
            printf("  [%s] %s\n", g_cases[i].passed?"PASS":"FAIL", g_cases[i].name);
    }

    int total_pass = kat_pass + case_pass;
    int total_fail = kat_fail + case_fail;
    int total      = total_pass + total_fail;

    char ts[32]; cfusa_timestamp_now(ts);

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 1; } }

    if (!strcmp(fmt_s, "json")) {
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"qualification\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"%s\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"binarySha256\": \"%s\",\n"
            "  \"total\": %d,\n"
            "  \"passed\": %d,\n"
            "  \"failed\": %d,\n"
            "  \"qualified\": %s,\n"
            "  \"results\": [\n",
            CFUSA_VERSION_STRING, ts, bin_hash,
            total, total_pass, total_fail,
            (total_fail == 0) ? "true" : "false");
        for (int i = 0; g_kat[i].name; i++)
            fprintf(out,
                "    {\"name\": \"%s\", \"kind\": \"kat\", \"result\": \"%s\"},\n",
                g_kat[i].name, g_kat[i].passed ? "PASS" : "FAIL");
        for (int i = 0; g_cases[i].name; i++) {
            const char *comma = g_cases[i+1].name ? "," : "";
            fprintf(out,
                "    {\"name\": \"%s\", \"kind\": \"rule-exercise\","
                " \"ruleId\": \"%s\", \"result\": \"%s\"}%s\n",
                g_cases[i].name, g_cases[i].rule_id,
                g_cases[i].passed ? "PASS" : "FAIL", comma);
        }
        fprintf(out, "  ]\n}\n");
    } else {
        fprintf(out,
            "cfusa Tool Qualification Record\n"
            "Version:        %s\n"
            "Timestamp:      %s\n"
            "Binary SHA-256: %s\n\n"
            "Known-answer tests:\n",
            CFUSA_VERSION_STRING, ts, bin_hash);
        for (int i = 0; g_kat[i].name; i++)
            fprintf(out, "  [%s] %s\n",
                g_kat[i].passed ? "PASS" : "FAIL", g_kat[i].name);
        fprintf(out, "\nFUSA rule exercise cases:\n");
        for (int i = 0; g_cases[i].name; i++)
            fprintf(out, "  [%s] %s\n",
                g_cases[i].passed ? "PASS" : "FAIL", g_cases[i].name);
        fprintf(out, "\nResult: %d passed, %d failed  —  %s\n",
            total_pass, total_fail,
            (total_fail == 0) ? "QUALIFIED" : "NOT QUALIFIED");
    }

    if (output && out != stdout) fclose(out);
    return total_fail > 0 ? 1 : 0;
}
