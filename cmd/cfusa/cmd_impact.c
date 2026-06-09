#if defined(__linux__) || defined(__unix__)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Change impact analysis on requirements.
 * Diffs changed files between two git refs and maps back to requirements
 * found in .cfusa-reqs.json and //cfusa:req annotations.
 */

#define MAX_FILES  512
#define MAX_REQS   256

//cfusa:req REQ-IMP001 REQ-IMP002 REQ-IMP003
static int validate_git_ref(const char *ref)
{
    if (!ref || !*ref) return 0;
    for (const char *p = ref; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') ||
              *p == '.' || *p == '_' || *p == '/' ||
              *p == '~' || *p == '^' || *p == ':' || *p == '-'))
            return 0;
    }
    return 1;
}

static int run_git_diff(const char *from, const char *to,
                        char files[][512], int *nfiles)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "git diff --name-only %s %s 2>/dev/null", from, to);

    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    *nfiles = 0;
    char line[512];
    while (fgets(line, sizeof(line), p) && *nfiles < MAX_FILES) {
        size_t n = strlen(line);
        if (n > 0 && line[n-1] == '\n') line[n-1] = '\0';
        strncpy(files[*nfiles], line, 511);
        files[*nfiles][511] = '\0';
        (*nfiles)++;
    }
    pclose(p);
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

static int load_req_ids(const char *dir, char ids[][64], int max_ids)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, ".cfusa-reqs.json");

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) return 0;

    int n = 0;
    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL && n < max_ids) {
        char id[64] = "";
        sscanf(p, "\"id\":\"%63[^\"]", id);
        if (id[0]) {
            strncpy(ids[n], id, 63);
            ids[n][63] = '\0';
            n++;
        }
        p++;
    }
    free(content);
    return n;
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
        default: return 1;
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
    static char req_ids[MAX_REQS][64];
    int nreqs = load_req_ids(dir, req_ids, MAX_REQS);

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

    return 0;
}
