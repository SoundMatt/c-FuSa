//cfusa:req REQ-FIX001 REQ-FIX002 REQ-CLI-FIX001

/*
 * cfusa fix — Auto-fix guidance for known-remediable findings.
 *
 * Re-runs all rules and filters to findings that have deterministic
 * remediation guidance. Prints a numbered fix list with step-by-step
 * instructions for each affected location.
 */
#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/engine.h"
#include "cfusa/report.h"
#include "cfusa/utils.h"

typedef struct {
    const char *rule_id;
    const char *summary;
    const char *guidance;
} fix_entry_t;

static const fix_entry_t FIXES[] = {
    /* ---- LINT ---- */
    {"CFUSA-L001",
     "Split function into smaller units",
     "Extract cohesive blocks into well-named helper functions until each\n"
     "  function is under the configured max-lines limit. MISRA-C guidance:\n"
     "  short functions are easier to review and unit-test exhaustively."},
    {"CFUSA-L002",
     "Remove goto statement",
     "Replace goto with structured control flow (break, continue, return, or\n"
     "  refactor into a helper function). MISRA-C:2012 R15.1 prohibits all goto."},
    {"CFUSA-L003",
     "Replace dynamic allocation",
     "Replace malloc/calloc/realloc/free with static buffers or stack allocations.\n"
     "  If dynamic memory is required, use a bounded memory pool."},
    {"CFUSA-L004",
     "Remove recursion",
     "Rewrite the recursive call as an explicit loop with a caller-owned stack\n"
     "  or work queue. MISRA-C:2012 R17.2: functions shall not call themselves,\n"
     "  directly or indirectly (unbounded recursion risks stack overflow)."},
    {"CFUSA-L005",
     "Remove #undef directive",
     "Do not undefine macros. Use a single definition point in a header.\n"
     "  MISRA-C:2012 R20.5 disallows #undef."},
    {"CFUSA-L006",
     "Remove setjmp/longjmp",
     "Replace non-local jumps with explicit return-code propagation.\n"
     "  MISRA-C:2012 R17.4: setjmp and longjmp shall not be used."},
    {"CFUSA-L007",
     "Restrict or const-qualify file-scope mutable variable",
     "Give the variable the narrowest possible scope, or add 'const' if it is\n"
     "  never written after initialization. MISRA-C:2012 R8.9: an object shall\n"
     "  be defined at block scope if its identifier only appears in one function."},
    {"CFUSA-L008",
     "Replace void* with a concrete pointer type",
     "Use the actual pointee type instead of void* so the compiler can check\n"
     "  assignments and dereferences. MISRA-C:2012 R11.5: a conversion from\n"
     "  void* to a pointer to object type should be avoided."},
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
    {"CFUSA-L011",
     "Replace octal constant with hex or decimal",
     "Rewrite so the intent is unambiguous — a leading zero on a nonzero\n"
     "  constant is easy to misread as decimal:\n"
     "  Bad:  int mode = 0755;\n"
     "  Safe: int mode = 0x1ED;  /* or spell out the decimal value */\n"
     "  MISRA-C:2012 R7.1: octal constants (other than zero) shall not be used."},
    {"CFUSA-L012",
     "Rename macro that shadows a C keyword",
     "Pick a name that cannot collide with a reserved word, e.g. prefix it\n"
     "  with the module name: #define CFUSA_INT 42  instead of  #define int 42.\n"
     "  MISRA-C:2012 R20.4: a macro shall not be defined with a name that is\n"
     "  a keyword."},

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
    {"CFUSA-A006",
     "Verify bounds before pointer arithmetic",
     "Check the resulting pointer stays within the object before dereferencing:\n"
     "  if (p + n <= end) { use(p + n); }   /* MISRA-C:2012 R18.4 */\n"
     "  Prefer indexing into a bounded array over raw pointer offsets."},
    {"CFUSA-A007",
     "Check the return value of the system call",
     "Test the result before proceeding — a silently ignored failure (e.g.\n"
     "  write(), close(), chdir()) leaves the program acting on unverified\n"
     "  state:\n"
     "  if (write(fd, buf, n) < 0) { /* handle error */ }   /* CERT-C ERR33-C */"},
    {"CFUSA-A004",
     "Guard boundary-constant arithmetic against overflow",
     "Check for overflow/underflow before an operation that can reach\n"
     "  INT_MAX/INT_MIN/UINT_MAX:\n"
     "  if (a > INT_MAX - b) { /* handle overflow */ } else { r = a + b; }\n"
     "  CERT-C INT30-C / INT32-C."},

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
    //cfusa:req REQ-FIX005
    {"CFUSA-CY006",
     "Null the pointer immediately after free to prevent use-after-free",
     "Set the pointer to NULL right after freeing it — any later use then\n"
     "  dereferences NULL (a clean crash) instead of freed memory:\n"
     "  free(ptr);\n"
     "  ptr = NULL;\n"
     "  For a struct field: free(obj->field); obj->field = NULL;   /* CWE-416, CERT-C MEM30-C */"},
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
    {"CFUSA-CY008",
     "Replace insecure temp-file function with mkstemp()",
     "tmpnam/mktemp/tempnam race between name generation and file creation:\n"
     "  Bad:  char *p = tmpnam(NULL); FILE *f = fopen(p, \"w\");\n"
     "  Safe: char tmpl[] = \"/tmp/app-XXXXXX\"; int fd = mkstemp(tmpl);\n"
     "  /* CERT-C FIO21-C */"},
    {"CFUSA-CY010",
     "Replace dangerous function with a safe alternative",
     "Dangerous: gets, mktemp, tmpnam, rand, sprintf, strcpy\n"
     "  Safe:      fgets, mkstemp, arc4random/getrandom, snprintf, strncpy"},
    {"CFUSA-CY011",
     "Validate or whitelist URLs/proxies before use",
     "Never pass an unvalidated variable as a curl URL or proxy target:\n"
     "  if (!is_allowed_host(url)) { return ERROR_UNTRUSTED_URL; }\n"
     "  curl_easy_setopt(curl, CURLOPT_URL, url);   /* CWE-918, ISO 21434 CS-10 */"},
    {"CFUSA-CY012",
     "Remove SO_DEBUG socket option",
     "Drop setsockopt(fd, SOL_SOCKET, SO_DEBUG, ...) before shipping — it\n"
     "  exposes internal TCP state and must not reach a production build."},
    {"CFUSA-CY013",
     "Sanitise archive entry paths before extraction",
     "Resolve and verify every entry stays inside the target directory:\n"
     "  char *real = realpath(entry_path, NULL);\n"
     "  if (!real || strncmp(real, dest_dir, strlen(dest_dir)) != 0) {\n"
     "      reject_entry(); }   /* CWE-23, zip-slip */"},
    {"CFUSA-CY014",
     "Use a modern TLS method with a minimum version floor",
     "Replace deprecated SSLv2/SSLv3/TLSv1-only methods:\n"
     "  SSL_CTX *ctx = SSL_CTX_new(TLS_method());\n"
     "  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);   /* CERT-C MSC61-C */"},
    {"CFUSA-CY015",
     "Use parameterised queries instead of building SQL with sprintf",
     "Bad:  sprintf(q, \"SELECT * FROM t WHERE id=%s\", id);\n"
     "  Safe: sqlite3_prepare_v2(db, \"SELECT * FROM t WHERE id=?\", -1, &stmt, NULL);\n"
     "        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);   /* CWE-89 */"},
    {"CFUSA-CY016",
     "Tighten directory permissions",
     "Create directories no more permissive than 0750:\n"
     "  mkdir(path, 0750);   /* CWE-732, CERT-C FIO06-C */"},
    {"CFUSA-CY017",
     "Tighten file permissions",
     "Create files no more permissive than 0640:\n"
     "  int fd = open(path, O_CREAT | O_WRONLY, 0640);   /* CWE-732, CERT-C FIO06-C */"},
    {"CFUSA-CY018",
     "Validate external file paths before use",
     "Resolve and verify the path stays within the expected directory before\n"
     "  opening it:\n"
     "  char *real = realpath(user_path, NULL);\n"
     "  if (!real || strncmp(real, base_dir, strlen(base_dir)) != 0) {\n"
     "      return ERROR_PATH_TRAVERSAL; }   /* CWE-22 */"},
    {"CFUSA-CY019",
     "Replace access()-then-open() with an atomic open",
     "The access()/open() pair is a TOCTOU race — the file can change between\n"
     "  the check and the use:\n"
     "  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);\n"
     "  if (fd < 0) { /* handle: already exists or other error */ }   /* CWE-362 */"},
    {"CFUSA-CY020",
     "Replace hardcoded /tmp path with mkstemp()",
     "A fixed temp-file name is predictable and race-prone:\n"
     "  char tmpl[] = \"/tmp/app-XXXXXX\"; int fd = mkstemp(tmpl);\n"
     "  /* CWE-377, CERT-C FIO21-C */"},
    {NULL, NULL, NULL}
};

static const fix_entry_t *lookup_fix(const char *rule_id)
{
    for (int i = 0; FIXES[i].rule_id; i++)
        if (!strcmp(FIXES[i].rule_id, rule_id))
            return &FIXES[i];
    return NULL;
}

/* ---- Real autofix: CFUSA-CY006 (free() without a following NULL-out) ----
 *
 * issue #210: the only rewrite in this file that is genuinely mechanical
 * and unambiguous. CY006 flags every `free(x);` call (cmd_cyber.c has no
 * finer signal than that), so this can't tell "missing NULL" from
 * "already correct" on its own — instead it inlines that check itself:
 * only insert `x = NULL;` when the next non-blank line doesn't already
 * set the same lvalue to NULL. Applying the insertion is therefore never
 * wrong, only occasionally a no-op-turned-skip. Scope is deliberately
 * narrow: only a bare `free(<lvalue>);` line (nothing else on it) with a
 * simple lvalue (identifier chars, '.', "->", '[', ']', digits — no
 * function calls or casts) is rewritten; anything else is left for the
 * guidance text above. */

typedef struct {
    int line;              /* 1-based source line of the free() call */
    char indent[64];       /* leading whitespace to reuse on the inserted line */
    char lvalue[192];   /* the freed expression, e.g. "ptr" or "obj->field" */
} null_after_free_fix_t;

static int is_lvalue_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.' ||
           c == '-' || c == '>' || c == '[' || c == ']';
}

/* Parses a line that (after leading whitespace) is exactly
 * "free(<lvalue>);" with nothing else on it. Returns 1 and fills
 * *lvalue_out on match, 0 otherwise (rejects anything with extra
 * characters, casts, or a non-trivial argument, per the narrow-scope
 * rule above). */
static int parse_bare_free_call(const char *code_line, char *lvalue_out,
                                 size_t lvalue_cap, char *indent_out,
                                 size_t indent_cap)
{
    const char *p = code_line;
    size_t ind_len = 0;
    while ((*p == ' ' || *p == '\t') && ind_len + 1 < indent_cap) {
        indent_out[ind_len++] = *p++;
    }
    indent_out[ind_len] = '\0';
    if (strncmp(p, "free(", 5) != 0) return 0;
    p += 5;
    const char *start = p;
    while (is_lvalue_char(*p)) p++;
    size_t len = (size_t)(p - start);
    if (len == 0 || len >= lvalue_cap) return 0;
    /* Must be exactly ");" (optional trailing whitespace) after the lvalue —
     * anything else (a cast, an expression, trailing code) is out of scope. */
    while (*p == ' ' || *p == '\t') p++;
    if (p[0] != ')' || p[1] != ';') return 0;
    p += 2;
    while (*p == ' ' || *p == '\t' || *p == '\r') p++;
    if (*p != '\0') return 0;
    memcpy(lvalue_out, start, len);
    lvalue_out[len] = '\0';
    return 1;
}

/* True if `line`, once its leading whitespace is skipped, already sets
 * `lvalue` to NULL (e.g. "ptr = NULL;") — used to skip an insertion that
 * would just duplicate an existing fix. */
static int line_already_nulls(const char *line, const char *lvalue)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t len = strlen(lvalue);
    if (strncmp(p, lvalue, len) != 0) return 0;
    p += len;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '=') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return strncmp(p, "NULL", 4) == 0;
}

/* Joins `dir` and `rel_path` into a file path this process can actually
 * open. `rel_path` (a finding's `file` field) is USUALLY dir-relative, but
 * cfusa_report_add()'s relativization can silently fail — same symlink-
 * prefix-mismatch class as issue #219 — leaving it absolute instead; join
 * would then produce a bogus doubled path. Detecting and using an already-
 * absolute path directly sidesteps that without depending on #219's fix. */
static void resolve_finding_path(const char *dir, const char *rel_path,
                                  char *out, size_t out_cap)
{
    if (rel_path[0] == '/')
        snprintf(out, out_cap, "%s", rel_path);
    else
        snprintf(out, out_cap, "%s/%s", dir, rel_path);
}

/* Collects one candidate fix per matching CFUSA-CY006 finding in `path`
 * (relative to `dir`) into `out` (capacity `cap`); returns the count
 * appended. Reads the file once per call rather than per-finding. */
static int collect_null_after_free_fixes(const char *dir, const char *rel_path,
                                          const cfusa_finding_t *findings, int n,
                                          null_after_free_fix_t *out, int cap)
{
    char full[600];
    resolve_finding_path(dir, rel_path, full, sizeof(full));
    size_t flen = 0;
    char *content = cfusa_read_file(full, &flen);
    if (!content) return 0;

    /* Index line starts for O(1) access by 1-based line number. */
    int max_lines = 1;
    for (size_t i = 0; i < flen; i++) if (content[i] == '\n') max_lines++;
    char **lines = malloc((size_t)max_lines * sizeof(char *));
    if (!lines) { free(content); return 0; }
    int nlines = 0;
    lines[nlines++] = content;
    for (size_t i = 0; i < flen; i++) {
        if (content[i] == '\n') {
            content[i] = '\0';
            if (nlines < max_lines) lines[nlines++] = content + i + 1;
        }
    }

    int found = 0;
    for (int i = 0; i < n && found < cap; i++) {
        const cfusa_finding_t *f = &findings[i];
        if (strcmp(f->rule_id, "CFUSA-CY006") != 0) continue;
        if (strcmp(f->file, rel_path) != 0) continue;
        if (f->line < 1 || f->line > nlines) continue;

        null_after_free_fix_t cand;
        if (!parse_bare_free_call(lines[f->line - 1], cand.lvalue, sizeof(cand.lvalue),
                                   cand.indent, sizeof(cand.indent)))
            continue;
        if (f->line < nlines && line_already_nulls(lines[f->line], cand.lvalue))
            continue; /* already fixed */
        cand.line = f->line;
        out[found++] = cand;
    }

    free(lines);
    free(content);
    return found;
}

static int null_after_free_cmp(const void *a, const void *b)
{
    return ((const null_after_free_fix_t *)a)->line -
           ((const null_after_free_fix_t *)b)->line;
}

/* Applies (or, with dry_run, only prints) every collected fix for one file,
 * inserting from the bottom up so earlier line numbers stay valid. Returns
 * the number of insertions made/planned. */
static int apply_null_after_free_fixes(const char *dir, const char *rel_path,
                                        null_after_free_fix_t *fixes, int nfix,
                                        int dry_run)
{
    if (nfix == 0) return 0;
    qsort(fixes, (size_t)nfix, sizeof(fixes[0]), null_after_free_cmp);

    char full[600];
    resolve_finding_path(dir, rel_path, full, sizeof(full));
    size_t flen = 0;
    char *content = cfusa_read_file(full, &flen);
    if (!content) return 0;

    for (int i = 0; i < nfix; i++) {
        printf("  %s:%d  free(%s);\n", rel_path, fixes[i].line, fixes[i].lvalue);
        printf("    %s+ %s%s = NULL;\n", dry_run ? "(dry-run) " : "",
               fixes[i].indent, fixes[i].lvalue);
    }
    if (dry_run) { free(content); return nfix; }

    /* Rebuild the file with one inserted line per fix, walking bottom-up
     * so already-processed insertions never shift a later fix's target
     * line out from under it. */
    for (int i = nfix - 1; i >= 0; i--) {
        char *lines_start = content;
        int lineno = 1;
        char *p = content;
        while (lineno < fixes[i].line && *p) {
            if (*p == '\n') lineno++;
            p++;
        }
        /* p now points to the start of the target line; advance to just
         * past its terminating '\n' (or EOF) — the insertion point. */
        char *insert_at = p;
        while (*insert_at && *insert_at != '\n') insert_at++;
        if (*insert_at == '\n') insert_at++;

        char newline[320];
        int wn = snprintf(newline, sizeof(newline), "%s%s = NULL;\n",
                           fixes[i].indent, fixes[i].lvalue);
        if (wn < 0) continue;
        size_t before_len = (size_t)(insert_at - lines_start);
        size_t after_len  = flen - before_len;
        size_t new_total  = flen + (size_t)wn;
        char *rebuilt = malloc(new_total + 1);
        if (!rebuilt) continue;
        memcpy(rebuilt, lines_start, before_len);
        memcpy(rebuilt + before_len, newline, (size_t)wn);
        memcpy(rebuilt + before_len + (size_t)wn, insert_at, after_len);
        rebuilt[new_total] = '\0';
        free(content);
        content = rebuilt;
        flen = new_total;
    }

    FILE *out = cfusa_fopen_write(full);
    if (out) {
        fwrite(content, 1, flen, out);
        fclose(out);
    }
    free(content);
    return nfix;
}

int cmd_fix(int argc, char **argv)
{
    const char *dir         = ".";
    const char *report_file = NULL;
    int apply = 0, dry_run = 0;

    static const struct option lo[] = {
        {"dir",      required_argument, NULL, 'd'},
        {"report",   required_argument, NULL, 'r'},
        {"apply",    no_argument,       NULL, 'a'},
        {"dry-run",  no_argument,       NULL, 'n'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:r:anh", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir         = optarg; break;
        case 'r': report_file = optarg; break;
        case 'a': apply       = 1;     break;
        case 'n': dry_run     = 1;     break;
        case 'h':
            printf("Usage: cfusa fix [--dir <path>] [--report <file>] [--dry-run] [--apply]\n\n"
                   "Re-runs all checks and lists findings that have deterministic\n"
                   "remediation guidance, with step-by-step fix instructions.\n"
                   "  --report <file>   Write JSON findings report to file\n"
                   "  --dry-run         Preview the CFUSA-CY006 (free-without-NULL) auto-fix\n"
                   "                    without writing any file\n"
                   "  --apply           Write the CFUSA-CY006 auto-fix into source files\n"
                   "                    (inserts '<ptr> = NULL;' after a bare free(<ptr>);\n"
                   "                    call, skipped if already NULL'd on the next line —\n"
                   "                    every other rule is guidance-only, see above)\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_analyze_register_rules();
    cfusa_cyber_register_rules();

    cfusa_report_t rpt;
    cfusa_report_init(&rpt);
    /* issue #153-class: without project_root, cfusa_report_add() leaves
     * `file` absolute instead of relativizing it like cmd_check.c does —
     * so a finding fixed here and later reported via --report gets a
     * different fingerprint than the same real finding from `cfusa
     * check`, silently breaking disposition matching between them. */
    {
        char *abs = realpath(dir, NULL);
        if (abs) {
            strncpy(rpt.project_root, abs, sizeof(rpt.project_root) - 1);
            free(abs);
        } else {
            strncpy(rpt.project_root, dir, sizeof(rpt.project_root) - 1);
        }
    }
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

    //cfusa:req REQ-FIX006
    /* issue #210: real autofix, scoped to CFUSA-CY006 (see the comment
     * above apply_null_after_free_fixes()). One file at a time: findings
     * aren't grouped by file elsewhere in this report, so scan for each
     * distinct `file` value in turn and skip ones already processed. */
    if (apply || dry_run) {
        printf("---\n");
        printf("Auto-fix (CFUSA-CY006 — null pointer after free):\n");
        int any = 0;
        for (int i = 0; i < total; i++) {
            const char *rel_path = rpt.findings[i].file;
            int already_done = 0;
            for (int j = 0; j < i; j++)
                if (!strcmp(rpt.findings[j].file, rel_path)) { already_done = 1; break; }
            if (already_done) continue;

            /* At most `total` findings can possibly match this one file. */
            null_after_free_fix_t *cand = malloc((size_t)total * sizeof(*cand));
            if (!cand) continue;
            int ncand = collect_null_after_free_fixes(dir, rel_path, rpt.findings,
                                                        total, cand, total);
            if (ncand > 0)
                any += apply_null_after_free_fixes(dir, rel_path, cand, ncand, dry_run);
            free(cand);
        }
        if (any == 0) {
            printf("  (nothing to do — no bare free(<lvalue>); call is missing its NULL-out)\n");
        } else {
            printf("---\n");
            printf("%d auto-fix(es) %s across the findings above.\n",
                   any, dry_run ? "would be applied (--dry-run, no files written)"
                                 : "applied");
        }
    }

    if (report_file) {
        if (cfusa_report_write(&rpt, report_file, FMT_JSON) != 0) {
            cfusa_report_free(&rpt);
            cfusa_engine_reset();
            return 3;
        }
        printf("Report written to %s\n", report_file);
    }

    cfusa_report_free(&rpt);
    cfusa_engine_reset();
    return total > 0 ? 1 : 0;
}
