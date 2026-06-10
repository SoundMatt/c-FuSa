#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/version.h"

int cmd_version(int argc, char **argv)
{
    const char *fmt = "text";

    static const struct option lo[] = {
        {"format", required_argument, NULL, 'f'},
        {NULL,0,NULL,0}
    };
    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "f:", lo, NULL)) != -1) {
        if (c == 'f') fmt = optarg;
    }

    if (!strcmp(fmt, "json")) {
        printf("{\"tool\": \"c-FuSa\", \"version\": \"%s\", \"specVersion\": \"%s\"}\n",
               CFUSA_VERSION_STRING, CFUSA_SPEC_VERSION);
        return 0;
    }

    printf("c-FuSa %s\n", CFUSA_VERSION_STRING);
    return 0;
}
