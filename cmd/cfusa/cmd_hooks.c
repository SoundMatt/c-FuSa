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
    int show_hook = 0;

    static const struct option long_opts[] = {
        {"dir",       required_argument, NULL, 'd'},
        {"install",   no_argument,       NULL, 'i'},
        {"uninstall", no_argument,       NULL, 'u'},
        {"show",      no_argument,       NULL, 's'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:iush", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir       = optarg; break;
        case 'i': install   = 1;      break;
        case 'u': uninstall = 1;      break;
        case 's': show_hook = 1;      break;
        case 'h':
            printf("Usage: cfusa hooks <subcommand> [--dir <path>]\n\n"
                   "Subcommands:\n"
                   "  install    Install pre-commit hook into .git/hooks/\n"
                   "  remove     Remove the cfusa pre-commit hook\n"
                   "  show       Print the hook script to stdout\n\n"
                   "Flags: --install / --uninstall / --show also accepted.\n");
            return 0;
        default: return 2;
        }
    }

    /* Accept subcommand style: hooks install | hooks remove | hooks show */
    if (optind < argc) {
        const char *sub = argv[optind];
        if (strcmp(sub, "install") == 0)       install   = 1;
        else if (strcmp(sub, "remove") == 0
              || strcmp(sub, "uninstall") == 0) uninstall = 1;
        else if (strcmp(sub, "show") == 0)      show_hook = 1;
        else {
            fprintf(stderr, "cfusa hooks: unknown subcommand '%s'\n", sub);
            return 2;
        }
    }

    if (show_hook) {
        fputs(HOOK_CONTENT, stdout);
        return 0;
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
        struct stat st;
        if (stat(hook_path, &st) != 0) {
            fprintf(stderr, "cfusa hooks: no hook found at %s\n", hook_path);
            return 2;
        }
        if (remove(hook_path) != 0) {
            perror(hook_path);
            return 3;
        }
        printf("pre-commit hook removed: %s\n", hook_path);
        return 0;
    }

    /* Install */
    char hooks_dir[512];
    snprintf(hooks_dir, sizeof(hooks_dir), "%s/.git/hooks", dir);

    /* Already installed? */
    if (cfusa_file_exists(hook_path)) {
        fprintf(stderr, "cfusa hooks: hook already exists at %s (remove first)\n", hook_path);
        return 2;
    }

    if (cfusa_mkdir_p(hooks_dir) != 0) {
        fprintf(stderr, "cfusa hooks: cannot create %s\n", hooks_dir);
        return 3;
    }

    FILE *f = fopen(hook_path, "w");
    if (!f) { perror(hook_path); return 3; }
    fputs(HOOK_CONTENT, f);
    fclose(f);
    chmod(hook_path, 0755);

    printf("pre-commit hook installed: %s\n", hook_path);
    printf("cfusa check will run on every 'git commit'.\n");
    return 0;
}
