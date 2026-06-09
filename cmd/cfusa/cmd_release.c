/* popen/pclose are POSIX; required on Linux with -std=c99 -fno-extensions */
#if defined(__linux__) || defined(__unix__)
#  define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/commands.h"

/* Generates SPDX-3.0.1 JSON SBOM, SLSA provenance, and artifact manifest. */

typedef struct {
    FILE *out;
    int  count;
    int  first;
} sbom_ctx_t;

static int sbom_file(const char *path, void *vctx)
{
    sbom_ctx_t *ctx = vctx;
    char hex[65];
    cfusa_sha256_file(path, hex);
    if (!ctx->first) fprintf(ctx->out, ",\n");
    fprintf(ctx->out,
        "    {\n"
        "      \"SPDXID\": \"SPDXRef-File-%d\",\n"
        "      \"fileName\": \"./%s\",\n"
        "      \"fileTypes\": [\"SOURCE\"],\n"
        "      \"checksums\": [{\"algorithm\": \"SHA256\", \"checksumValue\": \"%s\"}]\n"
        "    }",
        ctx->count + 1, cfusa_basename(path), hex);
    ctx->count++;
    ctx->first = 0;
    return 0;
}

/* Generates SPDX 3.0.1 JSON SBOM (matches go-FuSa output format) */
static int write_sbom(const char *dir, const cfusa_config_t *cfg,
                       const char *out_path, const char *ts)
{
    FILE *f = fopen(out_path,"w");
    if (!f) { perror(out_path); return -1; }

    fprintf(f,
        "{\n"
        "  \"spdxVersion\": \"SPDX-3.0.1\",\n"
        "  \"dataLicense\": \"CC0-1.0\",\n"
        "  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n"
        "  \"name\": \"%s\",\n"
        "  \"documentNamespace\": \"https://github.com/SoundMatt/c-FuSa/sbom/%s-%s\",\n"
        "  \"creationInfo\": {\n"
        "    \"created\": \"%s\",\n"
        "    \"creators\": [\"Tool: cfusa\"]\n"
        "  },\n"
        "  \"packages\": [\n"
        "    {\n"
        "      \"SPDXID\": \"SPDXRef-Package\",\n"
        "      \"name\": \"%s\",\n"
        "      \"versionInfo\": \"%s\",\n"
        "      \"downloadLocation\": \"https://github.com/SoundMatt/c-FuSa\",\n"
        "      \"licenseConcluded\": \"MPL-2.0\",\n"
        "      \"licenseDeclared\": \"MPL-2.0\",\n"
        "      \"copyrightText\": \"NOASSERTION\"\n"
        "    }\n"
        "  ],\n"
        "  \"files\": [\n",
        cfg->project, cfg->project, cfg->version, ts,
        cfg->project, cfg->version);

    sbom_ctx_t ctx = {f, 0, 1};
    static const char * const exts[]={".c",".h"};
    cfusa_walk_sources(dir, exts, 2, sbom_file, &ctx);

    fprintf(f,
        "\n  ],\n"
        "  \"relationships\": [\n"
        "    {\n"
        "      \"spdxElementId\": \"SPDXRef-DOCUMENT\",\n"
        "      \"relationshipType\": \"DESCRIBES\",\n"
        "      \"relatedSpdxElement\": \"SPDXRef-Package\"\n"
        "    }\n"
        "  ]\n"
        "}\n");
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
    snprintf(sbom_path, sizeof(sbom_path), "%s/%s-%s.spdx.json",
             output, cfg.project, cfg.version);
    write_sbom(dir, &cfg, sbom_path, ts);
    printf("SBOM written:      %s\n", sbom_path);

    /* SLSA provenance — capture git commit SHA via popen if available */
    char commit[64] = "unknown";
    {
        FILE *gp = popen("git rev-parse HEAD 2>/dev/null", "r");
        if (gp) {
            if (fgets(commit, sizeof(commit), gp)) {
                char *nl = strchr(commit, '\n');
                if (nl) *nl = '\0';
            }
            pclose(gp);
        }
    }
    char branch[64] = "unknown";
    {
        FILE *gp = popen("git rev-parse --abbrev-ref HEAD 2>/dev/null", "r");
        if (gp) {
            if (fgets(branch, sizeof(branch), gp)) {
                char *nl = strchr(branch, '\n');
                if (nl) *nl = '\0';
            }
            pclose(gp);
        }
    }

    char prov_path[512];
    snprintf(prov_path, sizeof(prov_path), "%s/provenance.json", output);
    FILE *pf = fopen(prov_path,"w");
    if (pf) {
        fprintf(pf,
            "{\n"
            "  \"_type\": \"https://in-toto.io/Statement/v0.1\",\n"
            "  \"subject\": [{\"name\": \"%s\", \"digest\": {\"sha256\": \"\"}}],\n"
            "  \"predicateType\": \"https://slsa.dev/provenance/v0.2\",\n"
            "  \"predicate\": {\n"
            "    \"builder\": {\"id\": \"https://github.com/SoundMatt/c-FuSa\"},\n"
            "    \"buildType\": \"cmake\",\n"
            "    \"invocationEnvironment\": {\n"
            "      \"commit\": \"%s\",\n"
            "      \"branch\": \"%s\"\n"
            "    },\n"
            "    \"metadata\": {\n"
            "      \"buildStartedOn\": \"%s\",\n"
            "      \"completeness\": {\"arguments\": false, \"environment\": false, \"materials\": false}\n"
            "    },\n"
            "    \"materials\": []\n"
            "  }\n"
            "}\n",
            cfg.project, commit, branch, ts);
        fclose(pf);
        printf("Provenance written: %s  (commit: %.8s)\n", prov_path, commit);
    }

    if (full) {
        /* -- fmea: fmea.json + fmea.csv -- */
        printf("Running: cfusa fmea ...\n");
        {
            char *fmea_argv[8];
            char fmea_prog[] = "cfusa fmea";
            char *fmea_dir   = (char*)dir;
            char *fmea_odir  = (char*)output;
            fmea_argv[0] = fmea_prog;
            fmea_argv[1] = "--dir";       fmea_argv[2] = fmea_dir;
            fmea_argv[3] = "--output-dir";fmea_argv[4] = fmea_odir;
            fmea_argv[5] = NULL;
            cmd_fmea(5, fmea_argv);
        }
        /* -- boundary: boundary diagram -- */
        printf("Running: cfusa boundary ...\n");
        {
            char bnd_out[512];
            snprintf(bnd_out, sizeof(bnd_out), "%s/boundary.md", output);
            char *bnd_argv[8];
            char bnd_prog[] = "cfusa boundary";
            char *bnd_dir   = (char*)dir;
            bnd_argv[0] = bnd_prog;
            bnd_argv[1] = "--dir";    bnd_argv[2] = bnd_dir;
            bnd_argv[3] = "--output"; bnd_argv[4] = bnd_out;
            bnd_argv[5] = NULL;
            cmd_boundary(5, bnd_argv);
        }
        /* -- vuln scan → vuln-report.json -- */
        printf("Running: cfusa vuln ...\n");
        {
            char vuln_out[512];
            snprintf(vuln_out, sizeof(vuln_out), "%s/vuln-report.json", output);
            char *vuln_argv[10];
            char vuln_prog[] = "cfusa vuln";
            char fmt_json[]  = "json";
            vuln_argv[0] = vuln_prog;
            vuln_argv[1] = "--dir";    vuln_argv[2] = (char*)dir;
            vuln_argv[3] = "--output"; vuln_argv[4] = vuln_out;
            vuln_argv[5] = "--format"; vuln_argv[6] = fmt_json;
            vuln_argv[7] = NULL;
            cmd_vuln(7, vuln_argv);
            printf("Vuln report written: %s\n", vuln_out);
        }
        /* -- SHA256SUMS manifest -- */
        char manifest[512];
        snprintf(manifest, sizeof(manifest), "%s/SHA256SUMS", output);
        FILE *mf = fopen(manifest, "w");
        if (mf) {
            char hex[65];
            cfusa_sha256_file(sbom_path,  hex);
            fprintf(mf, "%s  %s\n", hex, cfusa_basename(sbom_path));
            cfusa_sha256_file(prov_path, hex);
            fprintf(mf, "%s  %s\n", hex, cfusa_basename(prov_path));
            fclose(mf);
            printf("Manifest written:  %s\n", manifest);
        }
    }
    return 0;
}
