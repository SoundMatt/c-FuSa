#if defined(__linux__) || defined(__unix__)
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "cfusa/gitdiff.h"
#include "cfusa/utils.h"

#define CHANGED_INITIAL_CAP 32

/* Same validation cmd_impact.c's validate_git_ref() already applies: a
 * leading '-' would be parsed by git as an option, not a ref, enabling
 * argument injection; the character allowlist covers every legal git
 * ref-name character actually seen in practice (branch/tag names,
 * commit SHAs, and revision-syntax suffixes like ~1/^2). */
static int validate_git_ref(const char *ref)
{
    if (!ref || !*ref) return 0;
    if (ref[0] == '-') return 0;
    for (const char *p = ref; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') ||
              *p == '.' || *p == '_' || *p == '/' ||
              *p == '~' || *p == '^' || *p == ':' || *p == '-'))
            return 0;
    }
    return 1;
}

/* Runs `git_argv` (execvp-style, NULL-terminated, conventionally
 * starting with "git" as argv[0] per POSIX exec convention) with no
 * shell (pipe() + fork() + execvp("git", ...) with a literal program
 * name, matching cmd_impact.c's run_git_diff() exactly) and captures
 * its full stdout into a heap buffer (grown via realloc, no fixed-size
 * truncation cap). stderr is redirected to /dev/null in the child.
 * Returns the buffer (caller frees) on success, NULL on any failure
 * (pipe/fork/exec failure, or the child exiting non-zero — a non-git-
 * repo or bad-ref `git diff` exits non-zero, which this treats as "no
 * output" rather than guessing at partial results). *len_out receives
 * the byte count. */
static char *run_git_capture(char * const git_argv[], size_t *len_out)
{
    *len_out = 0;
    int fds[2];
    if (pipe(fds) != 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return NULL; }

    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execvp("git", git_argv);
        _exit(127);
    }

    close(fds[1]);
    FILE *p = fdopen(fds[0], "r");
    if (!p) { close(fds[0]); waitpid(pid, NULL, 0); return NULL; }

    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(p); waitpid(pid, NULL, 0); return NULL; }

    size_t n;
    char chunk[8192];
    while ((n = fread(chunk, 1, sizeof(chunk), p)) > 0) {
        if (len + n + 1 > cap) {
            while (len + n + 1 > cap) cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); fclose(p); waitpid(pid, NULL, 0); return NULL; }
            buf = tmp;
        }
        memcpy(buf + len, chunk, n);
        len += n;
    }
    fclose(p);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) { free(buf); return NULL; }

    buf[len] = '\0';
    *len_out = len;
    return buf;
}

static int changed_reserve(cfusa_changed_lines_t *list, int need)
{
    if (need <= list->cap) return 1;
    int new_cap = list->cap ? list->cap : CHANGED_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    cfusa_changed_range_t *tmp = realloc(list->items,
                                          (size_t)new_cap * sizeof(cfusa_changed_range_t));
    if (!tmp) return 0;
    list->items = tmp;
    list->cap = new_cap;
    return 1;
}

/* Parses a unified-diff hunk header "@@ -oldStart[,oldCount] +newStart
 * [,newCount] @@ [trailing context text]" and extracts the new-side
 * start/count. The old-side numbers never contain '+', so the first '+'
 * on the line unambiguously introduces the new-side range. */
static int parse_hunk_header(const char *line, int *new_start, int *new_count)
{
    if (strncmp(line, "@@ ", 3) != 0) return 0;
    const char *p = strchr(line, '+');
    if (!p) return 0;
    p++;
    char *end;
    long ns = strtol(p, &end, 10);
    if (end == p) return 0;
    long nc = 1;
    if (*end == ',') {
        p = end + 1;
        nc = strtol(p, &end, 10);
        if (end == p) return 0;
    }
    *new_start = (int)ns;
    *new_count = (int)nc;
    return 1;
}

int cfusa_git_changed_lines_load(const char *dir, const char *ref,
                                  cfusa_changed_lines_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!validate_git_ref(ref)) return 0;

    /* git diff paths are always repo-root-relative; strip the repo-root-
     * to-`dir` prefix (empty when `dir` IS the repo root) so they line
     * up with cfusa_finding_t.file's `dir`-relative convention. A
     * failure here (not a git repo, no git binary, ...) is caught by
     * the diff call below anyway, so it's not separately fatal — an
     * empty prefix is also the correct fallback when `dir` is already
     * the repo root. */
    char prefix[512] = "";
    {
        char *pargv[] = {"git", "-C", (char *)dir, "rev-parse",
                          "--show-prefix", NULL};
        size_t plen = 0;
        char *pout = run_git_capture(pargv, &plen);
        if (pout) {
            char *trimmed = cfusa_str_trim(pout);
            strncpy(prefix, trimmed, sizeof(prefix) - 1);
            free(pout);
        }
    }
    size_t prefix_len = strlen(prefix);

    char *argv[] = {"git", "-C", (char *)dir, "diff", "--unified=0",
                     (char *)ref, "--", ".", NULL};
    size_t len = 0;
    char *content = run_git_capture(argv, &len);
    if (!content) return 0; /* not a git repo, bad ref, git not found, ... */

    char cur_file[CFUSA_FINDING_FILE_MAX] = "";
    int have_file = 0;

    char *save = NULL;
    char *line = strtok_r(content, "\n", &save);
    while (line) {
        if (strncmp(line, "+++ ", 4) == 0) {
            have_file = 0;
            const char *path = line + 4;
            if (strcmp(path, "/dev/null") != 0) {
                if (strncmp(path, "b/", 2) == 0) path += 2;
                if (prefix_len && strncmp(path, prefix, prefix_len) == 0)
                    path += prefix_len;
                strncpy(cur_file, path, sizeof(cur_file) - 1);
                cur_file[sizeof(cur_file) - 1] = '\0';
                have_file = 1;
            }
        } else if (have_file && strncmp(line, "@@ ", 3) == 0) {
            int ns, nc;
            if (parse_hunk_header(line, &ns, &nc) && nc > 0) {
                if (!changed_reserve(out, out->count + 1)) {
                    fprintf(stderr,
                        "cfusa: WARNING: out of memory loading git diff "
                        "ranges — --changed-since results may be "
                        "incomplete\n");
                    break;
                }
                cfusa_changed_range_t *r = &out->items[out->count];
                strncpy(r->file, cur_file, sizeof(r->file) - 1);
                r->file[sizeof(r->file) - 1] = '\0';
                r->start = ns;
                r->end   = ns + nc - 1;
                out->count++;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(content);
    return 1;
}

void cfusa_git_changed_lines_free(cfusa_changed_lines_t *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap   = 0;
}

void cfusa_report_filter_to_changed_lines(cfusa_report_t *rpt,
                                           const cfusa_changed_lines_t *changed)
{
    int kept = 0;
    for (int i = 0; i < rpt->count; i++) {
        cfusa_finding_t *f = &rpt->findings[i];
        int keep = (f->line <= 0); /* directory/file-level finding: always kept */
        if (!keep) {
            for (int j = 0; j < changed->count; j++) {
                const cfusa_changed_range_t *r = &changed->items[j];
                if (strcmp(f->file, r->file) == 0 &&
                    f->line >= r->start && f->line <= r->end) {
                    keep = 1;
                    break;
                }
            }
        }
        if (keep) {
            if (kept != i) rpt->findings[kept] = *f;
            kept++;
        }
    }
    rpt->count = kept;

    rpt->error_count = rpt->warning_count = rpt->info_count = 0;
    rpt->dispositioned_count = 0;
    for (int i = 0; i < rpt->count; i++) {
        cfusa_finding_t *f = &rpt->findings[i];
        if (f->disposition_id[0]) {
            rpt->dispositioned_count++;
            continue;
        }
        switch (f->severity) {
        case SEV_ERROR:   rpt->error_count++;   break;
        case SEV_WARNING: rpt->warning_count++; break;
        case SEV_INFO:    rpt->info_count++;    break;
        }
    }
}
