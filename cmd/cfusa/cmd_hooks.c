#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <getopt.h>
#include "cfusa/utils.h"

#define HOOK_CONTENT \
    "#!/bin/sh\n" \
    "# cfusa pre-commit hook — installed by 'cfusa hooks --install'\n" \
    "set -e\n" \
    "if command -v cfusa >/dev/null 2>&1; then\n" \
    "  echo 'cfusa: running pre-commit safety checks...'\n" \
    "  cfusa check --dir . || { echo 'cfusa: checks failed, commit blocked'; exit 1; }\n" \
    "else\n" \
    "  echo 'cfusa: binary not found, skipping pre-commit checks'\n" \
    "fi\n"

int cmd_hooks(int argc, char **argv)
{
    const char *dir    = ".";
    int install   = 0;
    int uninstall = 0;

    static const struct option long_opts[] = {
        {"dir",       required_argument, NULL, 'd'},
        {"install",   no_argument,       NULL, 'i'},
        {"uninstall", no_argument,       NULL, 'u'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:iuh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir       = optarg; break;
        case 'i': install   = 1;      break;
        case 'u': uninstall = 1;      break;
        case 'h':
            printf("Usage: cfusa hooks --install   [--dir <path>]\n"
                   "       cfusa hooks --uninstall  [--dir <path>]\n\n"
                   "Installs or removes a git pre-commit hook that runs 'cfusa check'.\n");
            return 0;
        default: return 2;
        }
    }

    char hook_path[512];
    snprintf(hook_path, sizeof(hook_path), "%s/.git/hooks/pre-commit", dir);

    if (!uninstall && !install) {
        /* Status */
        printf("Hook path: %s\n", hook_path);
        printf("Status:    %s\n", cfusa_file_exists(hook_path) ? "installed" : "not installed");
        return 0;
    }

    if (uninstall) {
        if (cfusa_file_exists(hook_path)) {
            if (remove(hook_path) == 0)
                printf("Pre-commit hook removed: %s\n", hook_path);
            else
                perror(hook_path);
        } else {
            printf("No cfusa hook found at %s\n", hook_path);
        }
        return 0;
    }

    /* Install */
    char hooks_dir[512];
    snprintf(hooks_dir, sizeof(hooks_dir), "%s/.git/hooks", dir);
    if (!cfusa_dir_exists(hooks_dir)) {
        fprintf(stderr, "cfusa hooks: %s not found — is this a git repository?\n", hooks_dir);
        return 1;
    }

    FILE *f = fopen(hook_path, "w");
    if (!f) { perror(hook_path); return 3; }
    fputs(HOOK_CONTENT, f);
    fclose(f);
    chmod(hook_path, 0755);

    printf("Pre-commit hook installed: %s\n", hook_path);
    printf("cfusa check will run on every 'git commit'.\n");
    return 0;
}
