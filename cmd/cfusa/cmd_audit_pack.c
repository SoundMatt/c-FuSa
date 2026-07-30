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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <ftw.h>

//cfusa:req REQ-AUDIT

/*
 * Bundles all safety artifacts into a single ZIP audit package.
 * Produces <output> (default: audit-pack.zip) with manifest.json at ZIP root.
 */

/* nftw() callback: remove() dispatches to unlink() or rmdir() as appropriate. */
static int ap_rm_visitor(const char *fpath, const struct stat *sb,
                          int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)typeflag; (void)ftwbuf;
    remove(fpath);
    return 0;
}

/*
 * Remove path (file or directory tree) without any shell. Uses POSIX
 * nftw(FTW_DEPTH|FTW_PHYS) — an iterative library tree-walk (no user-code
 * recursion, satisfying MISRA-C 2012 Rule 17.2) that visits children before
 * their parent directory and never follows symlinks (FTW_PHYS), so there is
 * no CWE-78 command-injection exposure and no symlink-follow risk.
 */
static void ap_rmdir_recursive(const char *path)
{
    nftw(path, ap_rm_visitor, 16, FTW_DEPTH | FTW_PHYS);
}

/*
 * Run `zip -j <abs_output> <files...>` from inside `staging` with no shell:
 * fork + chdir(staging) + execvp("zip", argv). Because argv is passed directly
 * to execvp, attacker-controlled path/file names can never be interpreted as
 * shell syntax (CWE-78). Returns the child exit status, or -1 on spawn failure.
 */
static int ap_run_zip(const char *staging, const char *abs_output,
                      char staged[][256], int nstaged)
{
    /* argv: "zip" "-j" abs_output <nstaged files> NULL */
    char *argvz[4 + 64 + 1];
    int ai = 0;
    argvz[ai++] = "zip";
    argvz[ai++] = "-j";
    argvz[ai++] = (char *)abs_output;
    for (int i = 0; i < nstaged && ai < 4 + 64; i++)
        argvz[ai++] = staged[i];
    argvz[ai] = NULL;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (chdir(staging) != 0) _exit(127);
        execvp("zip", argvz);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

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

    /*
     * Explicit space-separated, single-quoted list of staged basenames to
     * pass to `zip`, instead of a `*` shell glob. POSIX shell globs do not
     * match dotfiles (leading '.') by default, so `zip -j out *` silently
     * omitted .fusa.json/.fusa-reqs.json from the archive even though they
     * were correctly staged and correctly hashed into manifest.json below
     * -- a tamper-evidence-breaking mismatch between the manifest and the
     * actual archive contents. See issue #67.
     */
    char file_list[4096];
    size_t file_list_len = 0;
    file_list[0] = '\0';

    /* Staged basenames, passed as an execvp argv array (never to a shell). */
    char staged[64][256];
    int nstaged = 0;

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

        {
            int n = snprintf(file_list + file_list_len, sizeof(file_list) - file_list_len,
                              "%s'%s'", file_list_len > 0 ? " " : "", cfusa_basename(ap));
            if (n > 0 && (size_t)n < sizeof(file_list) - file_list_len)
                file_list_len += (size_t)n;
        }
        if (nstaged < 64) {
            snprintf(staged[nstaged], sizeof(staged[nstaged]), "%s", cfusa_basename(ap));
            nstaged++;
        }
    }
    fprintf(mf, "\n  ]\n}\n");
    fclose(mf);

    /* manifest.json itself has no leading dot, but include it explicitly
     * too so the file list is authoritative rather than mixing a glob and
     * an explicit list. */
    {
        int n = snprintf(file_list + file_list_len, sizeof(file_list) - file_list_len,
                          "%s'manifest.json'", file_list_len > 0 ? " " : "");
        if (n > 0 && (size_t)n < sizeof(file_list) - file_list_len)
            file_list_len += (size_t)n;
    }

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

    /* Remove any pre-existing output so zip creates a fresh archive */
    remove(abs_output);

    /* Create the ZIP with no shell: fork + chdir(staging) + execvp("zip", argv).
     * The staged basenames and the output path are passed as argv entries, so
     * they can never be interpreted as shell syntax (CWE-78). */
    (void)file_list;
    int rc = ap_run_zip(staging, abs_output, staged, nstaged);

    /* Clean up staging directory without a shell. */
    ap_rmdir_recursive(staging);

    if (rc != 0) {
        fprintf(stderr,
            "cfusa audit-pack: zip failed (exit %d).\n"
            "  Ensure 'zip' is installed, or manually: zip -j %s <artifacts>/*\n",
            rc, output);
    } else {
        fprintf(stderr, "Audit pack: %s  (%d artifacts + manifest.json)\n", output, found);
    }

    return rc != 0 ? 3 : 0;
}
