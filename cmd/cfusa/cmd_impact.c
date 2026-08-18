#if defined(__linux__) || defined(__unix__)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Change impact analysis on requirements.
 * Diffs changed files between two git refs and maps back to requirements
 * found in .cfusa-reqs.json and //cfusa:req annotations.
 */

#define MAX_FILES  512

//cfusa:req REQ-IMP001 REQ-IMP002 REQ-IMP003
static int validate_git_ref(const char *ref)
{
    if (!ref || !*ref) return 0;
    /* A leading '-' would be parsed by git as an option, not a ref, enabling
     * argument injection (e.g. "--output=..."). Reject it outright. */
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

/*
 * Runs `git diff --name-only <from> <to> --` with no shell: pipe() + fork() +
 * execvp("git", argv). from/to are passed as separate argv entries (never
 * concatenated into a shell command string), so even a validate_git_ref()
 * bypass could never be interpreted as shell syntax (CWE-78). stderr is
 * redirected to /dev/null in the child to match the previous "2>/dev/null"
 * behaviour.
 */
static int run_git_diff(const char *from, const char *to,
                        char files[][512], int *nfiles)
{
    int fds[2];
    if (pipe(fds) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }

    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        char *argvg[] = {"git", "diff", "--name-only",
                          (char *)from, (char *)to, "--", NULL};
        execvp("git", argvg);
        _exit(127);
    }

    close(fds[1]);
    FILE *p = fdopen(fds[0], "r");
    if (!p) { close(fds[0]); waitpid(pid, NULL, 0); return -1; }

    *nfiles = 0;
    char line[512];
    while (fgets(line, sizeof(line), p) && *nfiles < MAX_FILES) {
        size_t n = strlen(line);
        if (n > 0 && line[n-1] == '\n') line[n-1] = '\0';
        strncpy(files[*nfiles], line, 511);
        files[*nfiles][511] = '\0';
        (*nfiles)++;
    }
    fclose(p);
    waitpid(pid, NULL, 0);
    return 0;
}

static int file_has_annotation(const char *filepath, const char *req_id)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "//cfusa:req") && strstr(line, req_id)) {
            found = 1;
            break;
        }
        if (strstr(line, "//cfusa:test") && strstr(line, req_id)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

typedef char req_id_t[64];

/*
 * Requirement id array grows dynamically via realloc — there is no fixed
 * cap. A compile-time array size here previously caused .fusa-reqs.json
 * files with more entries than the cap to be silently truncated, so
 * requirements past the cap could never be matched against changed files
 * (project issue #100). *out_truncated is set on allocation failure so the
 * caller can refuse to report a partial result as complete; the returned
 * pointer must be free()d by the caller.
 */
static req_id_t *load_req_ids(const char *dir, int *out_n, int *out_truncated)
{
    *out_n = 0;
    *out_truncated = 0;

    char path[512];
    cfusa_path_join(path, sizeof(path), dir, ".fusa-reqs.json");

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        cfusa_path_join(path, sizeof(path), dir, ".cfusa-reqs.json");
        content = cfusa_read_file(path, &len);
    }
    if (!content) return NULL;

    req_id_t *ids = NULL;
    int n = 0, cap = 0;
    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[64] = "";
        sscanf(p, "\"id\":\"%63[^\"]", id);
        if (id[0]) {
            if (n >= cap) {
                int new_cap = cap ? cap * 2 : 128;
                req_id_t *tmp = realloc(ids, (size_t)new_cap * sizeof(req_id_t));
                if (!tmp) { *out_truncated = 1; break; }
                ids = tmp;
                cap = new_cap;
            }
            strncpy(ids[n], id, 63);
            ids[n][63] = '\0';
            n++;
        }
        p++;
    }
    free(content);
    *out_n = n;
    return ids;
}

int cmd_impact(int argc, char **argv)
{
    const char *dir  = ".";
    const char *from = "HEAD~1";
    const char *to   = "HEAD";

    static const struct option long_opts[] = {
        {"dir",  required_argument, NULL, 'd'},
        {"from", required_argument, NULL, 'f'},
        {"to",   required_argument, NULL, 't'},
        {"help", no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:f:t:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir  = optarg; break;
        case 'f': from = optarg; break;
        case 't': to   = optarg; break;
        case 'h':
            printf("Usage: cfusa impact [--dir <path>] [--from <ref>] [--to <ref>]\n\n"
                   "Change impact analysis on requirements.\n"
                   "Diffs files between two git refs and maps to //cfusa:req annotations.\n"
                   "Defaults: --from HEAD~1 --to HEAD\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    /* Validate git refs to prevent command injection (CWE-78 / CERT-C FIO30-C) */
    if (!validate_git_ref(from)) {
        fprintf(stderr, "cfusa impact: invalid --from ref '%s'\n", from);
        return 1;
    }
    if (!validate_git_ref(to)) {
        fprintf(stderr, "cfusa impact: invalid --to ref '%s'\n", to);
        return 1;
    }

    /* Get changed files */
    static char files[MAX_FILES][512];
    int nfiles = 0;
    if (run_git_diff(from, to, files, &nfiles) < 0) {
        fprintf(stderr, "cfusa impact: failed to run git diff — not a git repo?\n");
        return 1;
    }

    if (nfiles == 0) {
        printf("No files changed between %s and %s\n", from, to);
        return 0;
    }

    /* Load requirement IDs */
    int nreqs = 0, req_ids_truncated = 0;
    req_id_t *req_ids = load_req_ids(dir, &nreqs, &req_ids_truncated);
    if (req_ids_truncated) {
        fprintf(stderr,
                "cfusa impact: ERROR: requirement catalog failed to load in "
                "full (out of memory) — refusing to report an impact result "
                "that could be mistaken for complete\n");
        free(req_ids);
        return 1;
    }

    printf("Change Impact Analysis — %s\n", cfg.project);
    printf("  From: %s\n", from);
    printf("  To:   %s\n", to);
    printf("  Changed files: %d\n\n", nfiles);

    int impacted = 0;
    for (int r = 0; r < nreqs; r++) {
        int hit = 0;
        for (int fi = 0; fi < nfiles; fi++) {
            if (file_has_annotation(files[fi], req_ids[r])) {
                if (!hit) {
                    printf("  %s  (impacted files)\n", req_ids[r]);
                    hit = 1;
                    impacted++;
                }
                printf("    - %s\n", files[fi]);
            }
        }
    }

    if (nreqs == 0) {
        /* No requirements registry — just print the changed files */
        printf("Changed files (no .cfusa-reqs.json found):\n");
        for (int fi = 0; fi < nfiles; fi++)
            printf("  %s\n", files[fi]);
        printf("\nRun 'cfusa req' to list requirement annotations found in source.\n");
    } else {
        printf("\n%d of %d requirement(s) potentially impacted by this change.\n",
               impacted, nreqs);
        if (impacted > 0)
            printf("Review impacted requirements and update tests as needed.\n");
    }

    free(req_ids);
    return 0;
}
