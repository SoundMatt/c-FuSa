#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

int cmd_init(int argc, char **argv)
{
    const char *dir             = ".";
    const char *project         = NULL;
    const char *project_version = "0.1.0";
    const char *standard        = NULL;
    int force = 0;

    static const struct option long_opts[] = {
        {"dir",             required_argument, NULL, 'd'},
        {"project",         required_argument, NULL, 'p'},
        {"project-version", required_argument, NULL, 'V'},
        {"standard",        required_argument, NULL, 'S'},
        {"force",           no_argument,       NULL, 'F'},
        {"help",            no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:p:V:S:Fh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir             = optarg; break;
        case 'p': project         = optarg; break;
        case 'V': project_version = optarg; break;
        case 'S': standard        = optarg; break;
        case 'F': force           = 1;      break;
        case 'h':
            printf("Usage: cfusa init [--dir <path>] [--project <name>]\n"
                   "                  [--project-version <ver>]\n"
                   "                  [--standard iso26262|do178c|iec61508|misra-c]\n"
                   "                  [--force]\n\n"
                   "Creates .fusa.json and .fusa-reqs.json in the target directory.\n"
                   "Per-file: skips any file that already exists (--force overwrites).\n");
            return 0;
        default: return 2;
        }
    }

    /* §9.1: no --project + no TTY (CI) → usage error */
    if (!project && !isatty(STDIN_FILENO)) {
        fprintf(stderr, "cfusa init: --project is required in non-interactive mode\n");
        return 2;
    }

    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);

    if (project)
        strncpy(cfg.project, project, sizeof(cfg.project) - 1);
    if (project_version)
        strncpy(cfg.version, project_version, sizeof(cfg.version) - 1);

    if (standard) {
        cfg.standards_count = 0;
        char buf[256];
        strncpy(buf, standard, sizeof(buf) - 1);
        char *tok = strtok(buf, ",");
        while (tok && cfg.standards_count < CFUSA_MAX_STANDARDS) {
            strncpy(cfg.standards[cfg.standards_count++],
                    cfusa_str_trim(tok), 31);
            tok = strtok(NULL, ",");
        }
    }

    /* § 9.1 per-file: create each target only if absent (--force overwrites) */
    char config_path[512];
    cfusa_path_join(config_path, sizeof(config_path), dir, CFUSA_CONFIG_FILE);

    int wrote_config = 0;
    if (!force && cfusa_file_exists(config_path)) {
        fprintf(stderr, "cfusa init: %s already exists (skipping; use --force to overwrite)\n",
                config_path);
    } else {
        if (cfusa_config_save(dir, &cfg) != 0) {
            fprintf(stderr, "cfusa: failed to write %s\n", config_path);
            return 3;
        }
        wrote_config = 1;
        printf("Created %s\n", config_path);
    }

    /* Also create .fusa-reqs.json if missing */
    char reqs_path[512];
    cfusa_path_join(reqs_path, sizeof(reqs_path), dir, ".fusa-reqs.json");

    int wrote_reqs = 0;
    if (!force && cfusa_file_exists(reqs_path)) {
        fprintf(stderr, "cfusa init: %s already exists (skipping; use --force to overwrite)\n",
                reqs_path);
    } else {
        FILE *rf = fopen(reqs_path, "w");
        if (!rf) {
            fprintf(stderr, "cfusa: failed to write %s\n", reqs_path);
            return 3;
        }
        fprintf(rf, "{\"requirements\": []}\n");
        fclose(rf);
        wrote_reqs = 1;
        printf("Created %s\n", reqs_path);
    }

    if (!wrote_config && !wrote_reqs) {
        printf("Nothing to do (all files exist; use --force to overwrite)\n");
        return 0;
    }

    printf("  project:  %s@%s\n", cfg.project, cfg.version);
    printf("  standard: %s\n",
           cfg.standards_count > 0 ? cfg.standards[0] : "(none)");
    printf("\nRun 'cfusa check' to scan your project.\n");
    return 0;
}
