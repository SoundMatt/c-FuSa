/* popen/pclose are POSIX */
#if defined(__linux__) || defined(__unix__)
#  define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"
#include <unistd.h>

/*
 * Bundles all safety artifacts into a single ZIP audit package.
 * Produces <output> (default: audit-pack.zip) with manifest.json at ZIP root.
 */

int cmd_audit_pack(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = "audit-pack.zip";

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
            printf("Usage: cfusa audit-pack [--dir <path>] [--output <file.zip>]\n\n"
                   "Bundles all available safety artifacts into a single ZIP.\n"
                   "Writes manifest.json (listing each artifact + sha256) at ZIP root.\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    /* Staging directory for the pack contents */
    char staging[512];
    snprintf(staging, sizeof(staging), "%s.cfusa-pack-staging", output);
    cfusa_mkdir_p(staging);

    char ts[32]; cfusa_timestamp_now(ts);

    /* Artifacts to collect (spec §8 MUST include all §1.2 inputs + §1.3 outputs) */
    static const char * const artifacts[] = {
        ".fusa.json",
        ".fusa-reqs.json",
        "safety-case.md",
        "tara.md",
        "fmea.json", "fmea.csv",
        "sbom.json",
        "provenance.json",
        "artifact-manifest.json",
        "qualify-report.json",
        "cfusa-report.json",
        "cfusa-report.sarif",
        "coverage.info",
        NULL
    };

    /* Build manifest entries */
    char manifest_path[512];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", staging);

    FILE *mf = fopen(manifest_path, "w");
    if (!mf) { perror(manifest_path); return 3; }

    char module[256];
    snprintf(module, sizeof(module), "%s@%s", cfg.project, cfg.version);

    fprintf(mf,
        "{\n"
        "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
        "  \"kind\": \"audit-manifest\",\n"
        "  \"tool\": \"c-FuSa\",\n"
        "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
        "  \"language\": \"c\",\n"
        "  \"generatedAt\": \"%s\",\n"
        "  \"module\": \"%s\",\n"
        "  \"files\": [\n",
        ts, module);

    int first = 1, found = 0;
    for (int i = 0; artifacts[i]; i++) {
        char ap[512];
        cfusa_path_join(ap, sizeof(ap), dir, artifacts[i]);
        if (!cfusa_file_exists(ap)) continue;
        /* v1.5 §8: audit-pack MUST NOT include itself */
        if (strcmp(cfusa_basename(ap), cfusa_basename(output)) == 0) continue;

        char hex[65];
        cfusa_sha256_file(ap, hex);

        /* Copy artifact to staging dir */
        char dest[512];
        cfusa_path_join(dest, sizeof(dest), staging, cfusa_basename(ap));
        {
            FILE *src_f = fopen(ap, "rb");
            FILE *dst_f = fopen(dest, "wb");
            if (src_f && dst_f) {
                char buf[4096]; size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src_f)) > 0)
                    fwrite(buf, 1, n, dst_f);
            }
            if (src_f) fclose(src_f);
            if (dst_f) fclose(dst_f);
        }

        /* Get file size */
        long fsize = 0;
        {
            FILE *tmp = fopen(ap, "rb");
            if (tmp) { fseek(tmp, 0, SEEK_END); fsize = ftell(tmp); fclose(tmp); }
        }

        fprintf(mf, "%s    {\"path\": \"%s\", \"size\": %ld, \"sha256\": \"%s\"}",
                first ? "" : ",\n", cfusa_basename(ap), fsize, hex);
        first = 0;
        found++;
    }
    fprintf(mf, "\n  ]\n}\n");
    fclose(mf);

    /* Create the ZIP using system zip command (flat, no subdirs) */
    char zip_cmd[2048];
    snprintf(zip_cmd, sizeof(zip_cmd),
             "cd \"%s\" && zip -j \"%s\" * 2>/dev/null",
             staging, output[0] == '/' ? output : "");

    /* Build absolute output path */
    char abs_output[512];
    if (output[0] != '/') {
        char cwd[256] = ".";
#if defined(_POSIX_VERSION)
        if (!getcwd(cwd, sizeof(cwd))) cwd[0] = '\0';
#endif
        snprintf(abs_output, sizeof(abs_output), "%s/%s", cwd, output);
    } else {
        snprintf(abs_output, sizeof(abs_output), "%s", output);
    }

    snprintf(zip_cmd, sizeof(zip_cmd),
             "cd \"%s\" && zip -j \"%s\" * 2>/dev/null",
             staging, abs_output);

    int rc = system(zip_cmd);
    if (rc != 0) {
        fprintf(stderr,
            "cfusa audit-pack: zip failed (exit %d).\n"
            "  Ensure 'zip' is installed, or manually: zip -j %s %s/*\n",
            rc, output, staging);
    } else {
        printf("Audit pack: %s  (%d artifacts + manifest.json)\n", output, found);
    }

    return rc != 0 ? 3 : 0;
}
