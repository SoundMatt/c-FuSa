#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/version.h"

//cfusa:req REQ-CLI-VERSION001 REQ-VER001
int cmd_version(int argc, char **argv)
{
    const char *fmt = "text";

    static const struct option lo[] = {
        {"format", required_argument, NULL, 'f'},
        {NULL,0,NULL,0}
    };
    int c; optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "f:", lo, NULL)) != -1) {
        if (c == 'f') fmt = optarg;
    }

    if (!strcmp(fmt, "json")) {
        printf("{\"tool\": \"c-FuSa\", \"version\": \"%s\", \"specVersion\": \"%s\"}\n",
               CFUSA_VERSION_STRING, CFUSA_SPEC_VERSION);
        return 0;
    }
    if (!strcmp(fmt, "text")) {
        printf("c-FuSa %s\n", CFUSA_VERSION_STRING);
        return 0;
    }
    fprintf(stderr, "cfusa version: unknown format %s (text or json)\n", fmt);
    return 2;
}
