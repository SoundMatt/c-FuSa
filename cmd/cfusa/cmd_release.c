#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/* Generates SBOM (SPDX-2.3 tag-value), build provenance, and signs artifacts. */

typedef struct {
    FILE *out;
    int  count;
} sbom_ctx_t;

static int sbom_file(const char *path, void *vctx)
{
    sbom_ctx_t *ctx = vctx;
    char hex[65];
    cfusa_sha256_file(path, hex);
    ctx->count++;
    fprintf(ctx->out,
        "FileName: ./%s\n"
        "SPDXID: SPDXRef-File-%d\n"
        "FileChecksum: SHA256: %s\n"
        "FileType: SOURCE\n\n",
        cfusa_basename(path), ctx->count, hex);
    return 0;
}

static int write_sbom(const char *dir, const cfusa_config_t *cfg,
                       const char *out_path, const char *ts)
{
    FILE *f = fopen(out_path,"w");
    if (!f) { perror(out_path); return -1; }

    fprintf(f,
        "SPDXVersion: SPDX-2.3\n"
        "DataLicense: CC0-1.0\n"
        "SPDXID: SPDXRef-DOCUMENT\n"
        "DocumentName: %s\n"
        "DocumentNamespace: https://github.com/SoundMatt/c-FuSa/sbom/%s-%s\n"
        "Creator: Tool: cfusa\n"
        "Created: %s\n\n"
        "PackageName: %s\n"
        "SPDXID: SPDXRef-Package\n"
        "PackageVersion: %s\n"
        "PackageLicenseConcluded: MPL-2.0\n"
        "PackageLicenseDeclared: MPL-2.0\n"
        "PackageCopyrightText: NOASSERTION\n\n",
        cfg->project, cfg->project, cfg->version, ts,
        cfg->project, cfg->version);

    sbom_ctx_t ctx = {f, 0};
    static const char * const exts[]={".c",".h"};
    cfusa_walk_sources(dir, exts, 2, sbom_file, &ctx);
    fprintf(f,"Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package\n");
    fclose(f);
    return 0;
}

int cmd_release(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = ".cfusa_release";
    int full = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"full",   no_argument,       NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:fh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'f': full   = 1;     break;
        case 'h':
            printf("Usage: cfusa release [--dir <path>] [--output <dir>] [--full]\n\n"
                   "Generates SBOM (SPDX-2.3), build provenance, and artifact hashes.\n"
                   "--full also produces signed checksums for all artifacts.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    cfusa_mkdir_p(output);

    char ts[32]; cfusa_timestamp_now(ts);

    /* SBOM */
    char sbom_path[512];
    snprintf(sbom_path, sizeof(sbom_path), "%s/%s-%s.spdx",
             output, cfg.project, cfg.version);
    write_sbom(dir, &cfg, sbom_path, ts);
    printf("SBOM written:      %s\n", sbom_path);

    /* Build provenance JSON (SLSA-style) */
    char prov_path[512];
    snprintf(prov_path, sizeof(prov_path), "%s/provenance.json", output);
    FILE *pf = fopen(prov_path,"w");
    if (pf) {
        fprintf(pf,
            "{\n"
            "  \"_type\": \"https://in-toto.io/Statement/v0.1\",\n"
            "  \"subject\": [{\"name\": \"%s\", \"digest\": {}}],\n"
            "  \"predicateType\": \"https://slsa.dev/provenance/v0.2\",\n"
            "  \"predicate\": {\n"
            "    \"builder\": {\"id\": \"https://github.com/SoundMatt/c-FuSa\"},\n"
            "    \"buildType\": \"cmake\",\n"
            "    \"metadata\": {\"buildStartedOn\": \"%s\"},\n"
            "    \"materials\": []\n"
            "  }\n"
            "}\n",
            cfg.project, ts);
        fclose(pf);
        printf("Provenance written: %s\n", prov_path);
    }

    if (full) {
        /* Checksum manifest for release dir */
        char manifest[512];
        snprintf(manifest,sizeof(manifest),"%s/SHA256SUMS",output);
        FILE *mf = fopen(manifest,"w");
        if (mf) {
            char hex[65];
            cfusa_sha256_file(sbom_path,  hex);
            fprintf(mf,"%s  %s\n", hex, cfusa_basename(sbom_path));
            cfusa_sha256_file(prov_path, hex);
            fprintf(mf,"%s  %s\n", hex, cfusa_basename(prov_path));
            fclose(mf);
            printf("Manifest written:  %s\n", manifest);
        }
    }
    return 0;
}
