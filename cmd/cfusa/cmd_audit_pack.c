#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Bundles all safety artifacts into a single audit package.
 * Creates a manifest of available artifacts with their SHA-256 checksums.
 * Note: actual ZIP creation requires libzip; this command produces a manifest
 * and instructs how to create the archive with standard tools.
 */

int cmd_audit_pack(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = "audit_pack";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa audit-pack [--dir <path>] [--output <name>]\n\n"
                   "Bundles all available safety artifacts into an audit package.\n"
                   "Creates <output>/MANIFEST.json listing each artifact with SHA-256.\n"
                   "Then: zip -r <output>.zip <output>/  to create the archive.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    cfusa_mkdir_p(output);

    char ts[32]; cfusa_timestamp_now(ts);

    static const char * const artifacts[] = {
        ".cfusa.json",
        "SAFETY_PLAN.md","HARA.md","TARA.md","FMEA.md",
        "SAFETY_CASE.md","SAS.md","TEST_EVIDENCE.md",
        "cfusa-report.json","cfusa-report.sarif",
        "coverage.info",
        NULL
    };

    char manifest_path[512];
    cfusa_path_join(manifest_path, sizeof(manifest_path), output, "MANIFEST.json");

    FILE *mf = fopen(manifest_path,"w");
    if (!mf) { perror(manifest_path); return 1; }

    fprintf(mf,
        "{\n  \"project\": \"%s\", \"version\": \"%s\","
        " \"timestamp\": \"%s\",\n  \"artifacts\": [\n",
        cfg.project, cfg.version, ts);

    int first=1, found=0;
    for (int i=0; artifacts[i]; i++) {
        char ap[512];
        cfusa_path_join(ap, sizeof(ap), dir, artifacts[i]);
        if (!cfusa_file_exists(ap)) continue;
        char hex[65];
        cfusa_sha256_file(ap, hex);
        fprintf(mf,"%s    {\"name\":\"%s\",\"sha256\":\"%s\"}",
                first?"":",\n", artifacts[i], hex);
        first=0;
        found++;
    }
    fprintf(mf,"\n  ]\n}\n");
    fclose(mf);

    printf("Audit manifest: %s  (%d artifacts)\n", manifest_path, found);
    printf("\nCreate archive with:\n  zip -r %s.zip %s/\n", output, output);
    printf("Or:              tar -czf %s.tar.gz %s/\n", output, output);
    return 0;
}
