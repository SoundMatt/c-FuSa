#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

int cmd_init(int argc, char **argv)
{
    const char *dir      = ".";
    const char *project  = NULL;
    const char *standard = NULL;
    int force = 0;

    static const struct option long_opts[] = {
        {"dir",      required_argument, NULL, 'd'},
        {"project",  required_argument, NULL, 'p'},
        {"standard", required_argument, NULL, 'S'},
        {"force",    no_argument,       NULL, 'F'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:p:S:Fh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg; break;
        case 'p': project  = optarg; break;
        case 'S': standard = optarg; break;
        case 'F': force    = 1;      break;
        case 'h':
            printf("Usage: cfusa init [--dir <path>] [--project <name>]\n"
                   "                  [--standard iso26262|do178c|iec61508|misra-c]\n"
                   "                  [--force]\n\n"
                   "Creates .cfusa.json in the target directory.\n");
            return 0;
        default: return 1;
        }
    }

    char config_path[512];
    cfusa_path_join(config_path, sizeof(config_path), dir, CFUSA_CONFIG_FILE);

    if (!force && cfusa_file_exists(config_path)) {
        fprintf(stderr, "cfusa: %s already exists (use --force to overwrite)\n",
                config_path);
        return 1;
    }

    cfusa_config_t cfg;
    cfusa_config_defaults(&cfg);

    if (project)
        strncpy(cfg.project, project, sizeof(cfg.project) - 1);

    if (standard) {
        cfg.standards_count = 0;
        /* Parse comma-separated list */
        char buf[256];
        strncpy(buf, standard, sizeof(buf) - 1);
        char *tok = strtok(buf, ",");
        while (tok && cfg.standards_count < CFUSA_MAX_STANDARDS) {
            strncpy(cfg.standards[cfg.standards_count++],
                    cfusa_str_trim(tok), 31);
            tok = strtok(NULL, ",");
        }
    }

    if (cfusa_config_save(dir, &cfg) != 0) {
        fprintf(stderr, "cfusa: failed to write %s\n", config_path);
        return 1;
    }

    printf("Initialised %s\n", config_path);
    printf("  project:   %s\n", cfg.project);
    printf("  standards:");
    for (int i = 0; i < cfg.standards_count; i++)
        printf(" %s", cfg.standards[i]);
    printf("\n");
    printf("  exclude:  ");
    for (int i = 0; i < cfg.exclude_count; i++)
        printf(" %s", cfg.exclude_dirs[i]);
    printf("\n\nRun 'cfusa check' to scan your project.\n");
    return 0;
}
