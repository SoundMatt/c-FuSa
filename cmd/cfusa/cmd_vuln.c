#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Scans for known-vulnerable function patterns mapped to CVE/CWE catalogue.
 * For a real project, integrate with OSV (osv.dev) via HTTP or
 * feed a known-vulnerable package list.
 */

typedef struct {
    const char *pattern;
    const char *cve_or_cwe;
    const char *description;
    const char *remediation;
} vuln_pattern_t;

static const vuln_pattern_t PATTERNS[] = {
    {"gets(", "CWE-120/CVE-CLASS",
     "gets() has no bounds check — any call is a vulnerability",
     "Replace with fgets(buf, sizeof(buf), stdin)"},
    {"sprintf(", "CWE-134/CVE-CLASS",
     "sprintf() may overflow destination buffer",
     "Replace with snprintf(buf, sizeof(buf), ...)"},
    {"strcpy(", "CWE-120/CVE-CLASS",
     "strcpy() does not check destination size",
     "Replace with strlcpy() or strncpy() with explicit size"},
    {"strcat(", "CWE-120/CVE-CLASS",
     "strcat() does not check destination size",
     "Replace with strlcat() or strncat() with explicit size"},
    {"scanf(\"%s\"", "CWE-120/CVE-CLASS",
     "scanf with %%s has no width limit — buffer overflow risk",
     "Use scanf(\"%255s\", ...) with explicit width"},
    {"tmpnam(", "CWE-377/CVE-CLASS",
     "tmpnam() creates insecure temp file names",
     "Replace with mkstemp()"},
    {"system(", "CWE-78/CVE-CLASS",
     "system() can lead to command injection",
     "Avoid system(); use execv() with sanitized arguments"},
    {"rand(", "CWE-338/CVE-CLASS",
     "rand() is not cryptographically secure",
     "Use /dev/urandom or a CSPRNG for security-sensitive values"},
    {NULL, NULL, NULL, NULL}
};

typedef struct {
    int finding_count;
} vuln_ctx_t;

static void vuln_line(const char *path, int lineno, const char *line, void *vctx)
{
    vuln_ctx_t *ctx = vctx;
    const char *p=line; while(*p==' '||*p=='\t') p++;
    if(*p=='/'||*p=='*') return;
    for (int i=0; PATTERNS[i].pattern; i++) {
        if (strstr(line, PATTERNS[i].pattern)) {
            printf("[VULN] %s:%d  %s\n"
                   "       %s\n"
                   "       Fix: %s\n\n",
                   path, lineno, PATTERNS[i].cve_or_cwe,
                   PATTERNS[i].description,
                   PATTERNS[i].remediation);
            ctx->finding_count++;
        }
    }
}

static int vuln_file(const char *path, void *v)
{
    cfusa_scan_lines(path, vuln_line, v); return 0;
}

int cmd_vuln(int argc, char **argv)
{
    const char *dir = ".";

    static const struct option long_opts[] = {
        {"dir",  required_argument, NULL, 'd'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir = optarg; break;
        case 'h':
            printf("Usage: cfusa vuln [--dir <path>]\n\n"
                   "Scans source for known-vulnerable function patterns "
                   "mapped to CWE/CVE categories.\n");
            return 0;
        default: return 1;
        }
    }

    vuln_ctx_t ctx = {0};
    static const char * const exts[]={".c",".h"};
    cfusa_walk_sources(dir, exts, 2, vuln_file, &ctx);

    if (ctx.finding_count == 0)
        printf("No known-vulnerable patterns found.\n");
    else
        printf("Total: %d vulnerable pattern(s) found.\n", ctx.finding_count);

    return ctx.finding_count > 0 ? 1 : 0;
}
