#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Collects test evidence: scans for test result files, coverage data,
 * and bundles a verification summary.
 */

int cmd_verify(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = "test-evidence.md";
    const char *fmt_s  = "md";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:f:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'h':
            printf("Usage: cfusa verify [--dir <path>] [--output test-evidence.md]\n"
                   "                    [--format md|text|json]\n\n"
                   "Collects test result files and coverage data into a verification bundle.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char ts[32]; cfusa_timestamp_now(ts);

    /* Locate evidence files */
    static const char * const evidence[] = {
        "coverage.info","lcov.info","test_results.xml","test_results.json",
        "ctest_results.xml","junit.xml",NULL
    };

    char out_path[512];
    if (output[0]=='/') strncpy(out_path,output,sizeof(out_path)-1);
    else cfusa_path_join(out_path,sizeof(out_path),dir,output);

    FILE *f = fopen(out_path,"w");
    if (!f) { perror(out_path); return 1; }

    if (!strcmp(fmt_s,"json")) {
        fprintf(f,"{\n  \"project\": \"%s\", \"version\": \"%s\","
                " \"timestamp\": \"%s\",\n  \"evidence\": [\n",
                cfg.project, cfg.version, ts);
        int first=1;
        for (int i=0; evidence[i]; i++) {
            char ep[512];
            cfusa_path_join(ep,sizeof(ep),dir,evidence[i]);
            if (!cfusa_file_exists(ep)) continue;
            char hex[65]; cfusa_sha256_file(ep,hex);
            fprintf(f,"%s    {\"file\":\"%s\",\"sha256\":\"%s\"}",
                    first?"":",\n",evidence[i],hex);
            first=0;
        }
        fprintf(f,"\n  ]\n}\n");
    } else {
        fprintf(f,"# Test Evidence Summary\n\n"
                "**Project:** %s v%s  |  **Generated:** %s\n\n"
                "## Evidence Files\n\n"
                "| File | Present | SHA-256 |\n|---|---|---|\n",
                cfg.project, cfg.version, ts);
        for (int i=0; evidence[i]; i++) {
            char ep[512];
            cfusa_path_join(ep,sizeof(ep),dir,evidence[i]);
            if (cfusa_file_exists(ep)) {
                char hex[65]; cfusa_sha256_file(ep,hex);
                fprintf(f,"| %s | ✓ | `%s` |\n",evidence[i],hex);
            } else {
                fprintf(f,"| %s | ✗ | — |\n",evidence[i]);
            }
        }
        fprintf(f,"\n## Notes\n\n[Add test run notes here]\n");
    }

    fclose(f);
    printf("Verification bundle written to %s\n", out_path);
    return 0;
}
