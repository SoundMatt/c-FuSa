#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/utils.h"

int cmd_sign(int argc, char **argv)
{
    const char *key    = NULL;
    const char *file   = NULL;
    const char *verify = NULL;

    static const struct option long_opts[] = {
        {"key",    required_argument, NULL, 'k'},
        {"file",   required_argument, NULL, 'i'},
        {"verify", required_argument, NULL, 'V'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "k:i:V:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'k': key    = optarg; break;
        case 'i': file   = optarg; break;
        case 'V': verify = optarg; break;
        case 'h':
            printf("Usage: cfusa sign --key <secret> --file <path>\n"
                   "       cfusa sign --key <secret> --verify <path.sig>\n\n"
                   "Signs a file with HMAC-SHA256 and writes <path>.sig,\n"
                   "or verifies an existing .sig file.\n");
            return 0;
        default: return 1;
        }
    }

    if (!key) {
        /* Read from env if not passed on command line */
        key = getenv("CFUSA_SIGN_KEY");
    }
    if (!key) {
        fprintf(stderr, "cfusa sign: --key or CFUSA_SIGN_KEY required\n");
        return 1;
    }

    if (verify) {
        /* Read stored signature from .sig file */
        size_t sig_len;
        char *stored = cfusa_read_file(verify, &sig_len);
        if (!stored) {
            fprintf(stderr, "cfusa sign: cannot read %s\n", verify);
            return 1;
        }
        /* Strip to 64 hex chars */
        char stored_hex[65];
        strncpy(stored_hex, stored, 64);
        stored_hex[64] = '\0';
        free(stored);

        /* Derive the original file path (strip .sig) */
        char orig[512];
        strncpy(orig, verify, sizeof(orig)-1);
        size_t len = strlen(orig);
        if (len>4 && strcmp(orig+len-4,".sig")==0)
            orig[len-4]='\0';

        size_t flen;
        unsigned char *fbuf = (unsigned char *)cfusa_read_file(orig, &flen);
        if (!fbuf) {
            fprintf(stderr,"cfusa sign: cannot read original file %s\n",orig);
            return 1;
        }

        char computed[65];
        cfusa_hmac_sha256((const unsigned char *)key, strlen(key),
                           fbuf, flen, computed);
        free(fbuf);

        if (strcmp(stored_hex, computed)==0) {
            printf("VALID  %s\n", orig);
            return 0;
        } else {
            fprintf(stderr, "INVALID  %s\n  expected: %s\n  got:      %s\n",
                    orig, stored_hex, computed);
            return 1;
        }
    }

    if (!file) {
        fprintf(stderr, "cfusa sign: --file required\n");
        return 1;
    }

    size_t flen;
    unsigned char *fbuf = (unsigned char *)cfusa_read_file(file, &flen);
    if (!fbuf) { perror(file); return 1; }

    char hex[65];
    cfusa_hmac_sha256((const unsigned char *)key, strlen(key), fbuf, flen, hex);
    free(fbuf);

    char sig_path[512];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", file);
    FILE *sf = fopen(sig_path, "w");
    if (!sf) { perror(sig_path); return 1; }
    fprintf(sf, "%s\n", hex);
    fclose(sf);

    printf("Signed  %s\n  HMAC-SHA256: %s\n  Signature:   %s\n", file, hex, sig_path);
    return 0;
}
