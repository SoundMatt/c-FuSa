/*
 * cfusa vuln — Known-vulnerable function pattern scan.
 *
 * Scans C source for patterns mapped to CWE/CVE categories.
 * For real dependency scanning, integrate with osv.dev via HTTP.
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/report.h"
#include "cfusa/utils.h"

typedef struct {
    const char *pattern;
    const char *cve_or_cwe;
    const char *description;
    const char *remediation;
} vuln_pattern_t;

static const vuln_pattern_t PATTERNS[] = {
    {"gets(",        "CWE-120/CVE-CLASS",
     "gets() has no bounds check — any call is a buffer overflow vulnerability",
     "Replace with fgets(buf, sizeof(buf), stdin)"},
    {"sprintf(",     "CWE-134/CVE-CLASS",
     "sprintf() may overflow the destination buffer",
     "Replace with snprintf(buf, sizeof(buf), ...)"},
    {"strcpy(",      "CWE-120/CVE-CLASS",
     "strcpy() does not check destination size",
     "Replace with strlcpy() or strncpy() with explicit size"},
    {"strcat(",      "CWE-120/CVE-CLASS",
     "strcat() does not check destination size",
     "Replace with strlcat() or strncat() with explicit size"},
    {"scanf(\"%s\"", "CWE-120/CVE-CLASS",
     "scanf with %%s has no width limit — buffer overflow risk",
     "Use scanf(\"%255s\", ...) with explicit field width"},
    {"tmpnam(",      "CWE-377/CVE-CLASS",
     "tmpnam() creates insecure temp file names (race condition)",
     "Replace with mkstemp()"},
    {"system(",      "CWE-78/CVE-CLASS",
     "system() can lead to command injection",
     "Avoid system(); use execv() with sanitised arguments"},
    {"rand(",        "CWE-338/CVE-CLASS",
     "rand() is not cryptographically secure",
     "Use /dev/urandom or a CSPRNG for security-sensitive values"},
    {"mktemp(",      "CWE-377/CVE-CLASS",
     "mktemp() is deprecated and insecure",
     "Replace with mkstemp()"},
    {"popen(",       "CWE-78/CVE-CLASS",
     "popen() passes a command to the shell — injection risk",
     "Validate all arguments; prefer execv() family functions"},
    {NULL, NULL, NULL, NULL}
};

#define MAX_VULNS 4096
typedef struct {
    char file[256];
    int  line;
    const vuln_pattern_t *pat;
} vuln_hit_t;

static vuln_hit_t g_hits[MAX_VULNS];
static int        g_hit_count;

/* Returns 1 if pattern is found at a word boundary (not preceded by [a-zA-Z0-9_]) */
static int match_word(const char *line, const char *pattern)
{
    const char *p = line;
    while ((p = strstr(p, pattern)) != NULL) {
        /* Check character immediately before the match */
        if (p > line) {
            char prev = p[-1];
            if ((prev >= 'a' && prev <= 'z') ||
                (prev >= 'A' && prev <= 'Z') ||
                (prev >= '0' && prev <= '9') ||
                prev == '_') {
                p++;
                continue; /* part of a longer identifier */
            }
        }
        return 1;
    }
    return 0;
}

static void vuln_line(const char *path, int lineno,
                       const char *line, void *vctx)
{
    (void)vctx;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '/' || *p == '*') return;
    for (int i = 0; PATTERNS[i].pattern; i++) {
        if (match_word(line, PATTERNS[i].pattern) && g_hit_count < MAX_VULNS) {
            strncpy(g_hits[g_hit_count].file, path, 255);
            g_hits[g_hit_count].line = lineno;
            g_hits[g_hit_count].pat  = &PATTERNS[i];
            g_hit_count++;
        }
    }
}

static int vuln_file(const char *path, void *v)
{ cfusa_scan_lines(path, vuln_line, v); return 0; }

int cmd_vuln(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = NULL;
    const char *fmt_s  = "text";

    static const struct option lo[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:f:h", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'h':
            printf("Usage: cfusa vuln [--dir <path>] [--output <file>] [--format text|json]\n\n"
                   "Scans source for known-vulnerable function patterns "
                   "mapped to CWE/CVE categories.\n");
            return 0;
        default: return 1;
        }
    }

    g_hit_count = 0;
    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, vuln_file, NULL);

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 1; } }

    if (fmt == FMT_JSON) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"tool\": \"cfusa vuln\",\n"
            "  \"generated\": \"%s\",\n"
            "  \"total\": %d,\n"
            "  \"findings\": [\n", ts, g_hit_count);
        for (int i = 0; i < g_hit_count; i++) {
            fprintf(out,
                "    {\"file\": \"%s\", \"line\": %d, \"cwe\": \"%s\","
                " \"description\": \"%s\", \"remediation\": \"%s\"}%s\n",
                g_hits[i].file, g_hits[i].line,
                g_hits[i].pat->cve_or_cwe,
                g_hits[i].pat->description,
                g_hits[i].pat->remediation,
                (i < g_hit_count - 1) ? "," : "");
        }
        fprintf(out, "  ]\n}\n");
    } else {
        for (int i = 0; i < g_hit_count; i++) {
            fprintf(out,
                "[VULN] %s:%d  %s\n"
                "       %s\n"
                "       Fix: %s\n\n",
                g_hits[i].file, g_hits[i].line,
                g_hits[i].pat->cve_or_cwe,
                g_hits[i].pat->description,
                g_hits[i].pat->remediation);
        }
        if (g_hit_count == 0)
            fprintf(out, "No known-vulnerable patterns found.\n");
        else
            fprintf(out, "Total: %d vulnerable pattern(s) found.\n", g_hit_count);
    }

    if (output && out != stdout) fclose(out);
    return g_hit_count > 0 ? 1 : 0;
}
