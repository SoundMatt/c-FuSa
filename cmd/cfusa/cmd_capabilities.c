#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/utils.h"
#include "cfusa/version.h"

/* §9.1: capabilities --format json — discovery handshake for FuSaOps */
int cmd_capabilities(int argc, char **argv)
{
    const char *fmt = "text";

    static const struct option lo[] = {
        {"format", required_argument, NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };
    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "f:h", lo, NULL)) != -1) {
        switch (c) {
        case 'f': fmt = optarg; break;
        case 'h':
            printf("Usage: cfusa capabilities [--format text|json]\n\n"
                   "Emits the tool's supported commands and formats.\n");
            return 0;
        default: return 2;
        }
    }

    if (!strcmp(fmt, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        printf("{\n"
               "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
               "  \"kind\": \"capabilities\",\n"
               "  \"tool\": \"c-FuSa\",\n"
               "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
               "  \"language\": \"c\",\n"
               "  \"generatedAt\": \"%s\",\n"
               "  \"specVersion\": \"" CFUSA_SPEC_VERSION "\",\n"
               "  \"commands\": [\n"
               "    \"version\", \"capabilities\", \"init\", \"check\", \"trace\",\n"
               "    \"qualify\", \"release\", \"audit-pack\", \"report\",\n"
               "    \"lint\", \"analyze\", \"cyber\", \"vuln\", \"fmea\",\n"
               "    \"boundary\", \"safety-case\", \"tara\", \"hara\",\n"
               "    \"coverage\", \"diff\", \"req\", \"disposition\",\n"
               "    \"iso26262\", \"iec61508\", \"iec62443\", \"do178\", \"misra\",\n"
               "    \"iso21434\", \"unece\", \"sign\", \"fix\"\n"
               "  ],\n"
               "  \"formats\": {\n"
               "    \"check\":     [\"text\", \"json\", \"sarif\", \"html\", \"md\"],\n"
               "    \"report\":    [\"text\", \"json\", \"sarif\", \"html\", \"md\"],\n"
               "    \"trace\":     [\"text\", \"json\", \"md\"],\n"
               "    \"qualify\":   [\"text\", \"json\"],\n"
               "    \"coverage\":  [\"text\", \"json\"],\n"
               "    \"do178\":     [\"text\", \"md\", \"json\"],\n"
               "    \"iso26262\":  [\"text\", \"json\"],\n"
               "    \"iec61508\":  [\"text\", \"json\"],\n"
               "    \"iec62443\":  [\"text\", \"json\"],\n"
               "    \"misra\":     [\"text\", \"json\"],\n"
               "    \"iso21434\":  [\"text\", \"json\"],\n"
               "    \"unece\":     [\"text\", \"json\"],\n"
               "    \"vuln\":      [\"text\", \"json\"],\n"
               "    \"diff\":      [\"json\"],\n"
               "    \"sci\":       [\"text\", \"json\"],\n"
               "    \"coupling\":  [\"json\"],\n"
               "    \"version\":   [\"text\", \"json\"]\n"
               "  },\n"
               "  \"standards\": [\"iso26262\", \"iec61508\", \"iec62443\", \"do178c\", \"misra-c\",\n"
               "               \"iso21434\", \"unece-r155\"]\n"
               "}\n",
               ts);
    } else {
        printf("c-FuSa %s (spec %s)\n", CFUSA_VERSION_STRING, CFUSA_SPEC_VERSION);
        printf("Required commands: version capabilities init check trace qualify release audit-pack report\n");
        printf("Standards: iso26262 iec61508 iec62443 do178c misra-c iso21434 unece-r155\n");
    }
    return 0;
}
