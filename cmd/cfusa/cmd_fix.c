/*
 * cfusa fix — Auto-fix guidance for known-remediable findings.
 *
 * Re-runs all rules and filters to findings that have deterministic
 * remediation guidance. Prints a numbered fix list with step-by-step
 * instructions for each affected location.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/engine.h"
#include "cfusa/report.h"

typedef struct {
    const char *rule_id;
    const char *summary;
    const char *guidance;
} fix_entry_t;

static const fix_entry_t FIXES[] = {
    /* ---- LINT ---- */
    {"CFUSA-L002",
     "Remove goto statement",
     "Replace goto with structured control flow (break, continue, return, or\n"
     "  refactor into a helper function). MISRA-C:2012 R15.1 prohibits all goto."},
    {"CFUSA-L003",
     "Replace dynamic allocation",
     "Replace malloc/calloc/realloc/free with static buffers or stack allocations.\n"
     "  If dynamic memory is required, use a bounded memory pool."},
    {"CFUSA-L005",
     "Remove #undef directive",
     "Do not undefine macros. Use a single definition point in a header.\n"
     "  MISRA-C:2012 R20.5 disallows #undef."},
    {"CFUSA-L006",
     "Remove setjmp/longjmp",
     "Replace non-local jumps with explicit return-code propagation.\n"
     "  MISRA-C:2012 R17.4: setjmp and longjmp shall not be used."},
    {"CFUSA-L009",
     "Remove #pragma directive",
     "Isolate any necessary pragma behind a portability macro and document why.\n"
     "  Prefer standard language features where possible."},
    {"CFUSA-L010",
     "Zero errno before use",
     "Set errno = 0 immediately before any call that may set it:\n"
     "  errno = 0;\n"
     "  long v = strtol(s, &end, 10);\n"
     "  if (errno || end == s) { /* handle error */ }"},

    /* ---- ANALYZE ---- */
    {"CFUSA-A001",
     "Replace unsafe string function",
     "Unsafe: gets, strcpy, strcat, sprintf, scanf\n"
     "  Replacement: fgets(buf, sizeof(buf), stdin),\n"
     "               strncpy(dst, src, sizeof(dst)-1),\n"
     "               snprintf(buf, sizeof(buf), fmt, ...)."},
    {"CFUSA-A002",
     "Check malloc/calloc return value",
     "Test the pointer before use:\n"
     "  void *p = malloc(n);\n"
     "  if (!p) { /* handle OOM */ return -1; }"},
    {"CFUSA-A003",
     "Cast comparison operands to matching sign",
     "Explicitly cast before comparison to remove sign mismatch:\n"
     "  if ((size_t)signed_val < unsigned_val) { ... }\n"
     "  Or change the variable type to eliminate the mismatch."},
    {"CFUSA-A005",
     "Replace assert with a run-time fault handler in production code",
     "Assertions that abort the process are unsafe in safety-critical paths.\n"
     "  Replace: assert(condition);\n"
     "  With:    if (!(condition)) { handle_fault(FAULT_XYZ); }"},

    /* ---- CYBER ---- */
    {"CFUSA-CY001",
     "Add explicit size argument to copy function",
     "Include the destination buffer size in every copy call:\n"
     "  strncpy(dst, src, sizeof(dst) - 1);\n"
     "  dst[sizeof(dst) - 1] = '\\0';"},
    {"CFUSA-CY002",
     "Use a string literal as the format argument",
     "Never pass a variable as the printf format argument:\n"
     "  Bad:  printf(user_input);\n"
     "  Safe: printf(\"%s\", user_input);   /* CERT-C FIO30-C */"},
    {"CFUSA-CY003",
     "Sanitise shell command arguments before calling system/popen",
     "Validate and whitelist every byte of external input before including\n"
     "  it in a shell command. Prefer execve() over system()."},
    {"CFUSA-CY004",
     "Add NULL check before pointer dereference",
     "Check every pointer from an allocation, lookup, or external call:\n"
     "  if (!ptr) { return ERROR_NULL; }   /* CERT-C EXP34-C */"},
    {"CFUSA-CY005",
     "Guard allocation size against integer overflow",
     "Validate that n * sizeof(T) does not overflow before allocating:\n"
     "  if (n > SIZE_MAX / sizeof(T)) { return ERROR_OVERFLOW; }\n"
     "  void *p = malloc(n * sizeof(T));   /* CERT-C INT30-C */"},
    {"CFUSA-CY007",
     "Null the pointer after free to prevent double-free",
     "Set the pointer to NULL immediately after freeing:\n"
     "  free(ptr);\n"
     "  ptr = NULL;   /* CERT-C MEM31-C */"},
    {"CFUSA-CY009",
     "Replace weak or deprecated cryptographic primitive",
     "Do not use MD5, SHA-1, DES, RC4, or ECB mode.\n"
     "  Hash:      SHA-256 or SHA-3\n"
     "  Symmetric: AES-GCM or ChaCha20-Poly1305   /* ISO 21434 CS-7 */"},
    {"CFUSA-CY010",
     "Replace dangerous function with a safe alternative",
     "Dangerous: gets, mktemp, tmpnam, rand, sprintf, strcpy\n"
     "  Safe:      fgets, mkstemp, arc4random/getrandom, snprintf, strncpy"},
    {NULL, NULL, NULL}
};

static const fix_entry_t *lookup_fix(const char *rule_id)
{
    for (int i = 0; FIXES[i].rule_id; i++)
        if (!strcmp(FIXES[i].rule_id, rule_id))
            return &FIXES[i];
    return NULL;
}

int cmd_fix(int argc, char **argv)
{
    const char *dir = ".";

    static const struct option lo[] = {
        {"dir",  required_argument, NULL, 'd'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "d:h", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir = optarg; break;
        case 'h':
            printf("Usage: cfusa fix [--dir <path>]\n\n"
                   "Re-runs all checks and lists findings that have deterministic\n"
                   "remediation guidance, with step-by-step fix instructions.\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    cfusa_lint_register_rules();
    cfusa_analyze_register_rules();
    cfusa_cyber_register_rules();

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    cfusa_engine_run_all(dir, &cfg, &rpt);

    int total   = rpt.count;
    int fixable = 0;

    printf("cfusa fix — Remediation guidance\n");
    printf("Project: %s %s\n\n", cfg.project, cfg.version);

    for (int i = 0; i < total; i++) {
        const cfusa_finding_t *f = &rpt.findings[i];
        const fix_entry_t *fix   = lookup_fix(f->rule_id);
        if (!fix) continue;
        fixable++;
        printf("[%d] %s:%d  (%s)\n",
               fixable, f->file, f->line, f->rule_id);
        printf("  Finding:  %s\n", f->message);
        printf("  Fix:      %s\n", fix->summary);
        printf("  Guidance:\n");
        const char *g = fix->guidance;
        char line_buf[256];
        while (*g) {
            const char *nl = strchr(g, '\n');
            size_t len = nl ? (size_t)(nl - g) : strlen(g);
            if (len >= sizeof(line_buf)) len = sizeof(line_buf) - 1;
            memcpy(line_buf, g, len); line_buf[len] = '\0';
            printf("    %s\n", line_buf);
            if (!nl) break;
            g = nl + 1;
        }
        printf("\n");
    }

    printf("---\n");
    printf("%d finding(s) total: %d with fix guidance, %d without\n",
           total, fixable, total - fixable);

    cfusa_report_free(&rpt);
    cfusa_engine_reset();
    return 0;
}
