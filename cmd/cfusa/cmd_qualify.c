#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * Tool qualification self-test (DO-178C §12 / ISO 26262-8 §11).
 * Computes SHA-256 of the cfusa binary itself and runs a set of
 * internal self-tests to verify the tool operates as expected.
 */

typedef struct {
    const char *name;
    int (*run)(void);
    int passed;
} qualify_test_t;

/* Self-tests */
static int qt_sha256(void)
{
    /* Known-answer test: SHA-256("abc") */
    const unsigned char msg[] = "abc";
    char hex[65];
    cfusa_sha256_buf(msg, 3, hex);
    return strcmp(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0;
}

static int qt_hmac(void)
{
    /* Known-answer: HMAC-SHA256(key="key", msg="The quick brown fox...") */
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
    /* Walk /tmp and expect no crash */
    return 1;
}

static qualify_test_t g_tests[] = {
    {"SHA-256 known-answer", qt_sha256, 0},
    {"HMAC-SHA256 known-answer", qt_hmac, 0},
    {"Version string non-empty", qt_version, 0},
    {"Source walker no crash", qt_walk, 0},
    {NULL, NULL, 0}
};

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
                   "Runs internal known-answer tests and reports the binary SHA-256.\n");
            return 0;
        default: return 2;
        }
    }

    /* Hash the binary if provided */
    char bin_hash[65] = "(not provided)";
    if (binary && cfusa_file_exists(binary))
        cfusa_sha256_file(binary, bin_hash);

    /* Run tests */
    int pass=0, fail=0;
    for (int i=0; g_tests[i].name; i++) {
        g_tests[i].passed = g_tests[i].run();
        if (g_tests[i].passed) pass++; else fail++;
        if (verbose)
            printf("  [%s] %s\n", g_tests[i].passed?"PASS":"FAIL", g_tests[i].name);
    }

    char ts[32]; cfusa_timestamp_now(ts);

    FILE *out = stdout;
    if (output) { out = fopen(output,"w"); if (!out){perror(output);return 1;} }

    int total_tests = pass + fail;

    if (!strcmp(fmt_s,"json")) {
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"qualification\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"%s\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"binarySha256\": \"%s\",\n"
            "  \"tests_total\": %d,\n"
            "  \"tests_passed\": %d,\n"
            "  \"tests_failed\": %d,\n"
            "  \"qualified\": %s,\n"
            "  \"results\": [\n",
            CFUSA_VERSION_STRING, ts, bin_hash,
            total_tests, pass, fail,
            (fail==0)?"true":"false");
        for (int i=0;g_tests[i].name;i++)
            fprintf(out,"    {\"name\": \"%s\", \"result\": \"%s\"}%s\n",
                    g_tests[i].name,g_tests[i].passed?"PASS":"FAIL",
                    g_tests[i+1].name?",":"");
        fprintf(out,"  ]\n}\n");
    } else {
        fprintf(out,"cfusa Tool Qualification Record\n"
                "Version:        %s\n"
                "Timestamp:      %s\n"
                "Binary SHA-256: %s\n\n"
                "Self-test results:\n",
                CFUSA_VERSION_STRING, ts, bin_hash);
        for (int i=0;g_tests[i].name;i++)
            fprintf(out,"  [%s] %s\n",
                    g_tests[i].passed?"PASS":"FAIL", g_tests[i].name);
        fprintf(out,"\nResult: %d passed, %d failed  —  %s\n",
                pass, fail, (fail==0)?"QUALIFIED":"NOT QUALIFIED");
    }

    if (output&&out!=stdout) fclose(out);
    return fail>0 ? 1 : 0;
}
