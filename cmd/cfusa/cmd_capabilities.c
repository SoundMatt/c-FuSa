/* open()/fdopen() are POSIX; required on Linux with -std=c99 */
#if defined(__linux__) || defined(__unix__)
#  define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include "cfusa/utils.h"
#include "cfusa/version.h"

/* §9.1: capabilities --format json — discovery handshake for FuSaOps */
int cmd_capabilities(int argc, char **argv)
{
    const char *fmt    = "text";
    const char *output = NULL;
    static const struct option lo[] = {
        {"format",required_argument,NULL,'f'},{"output",required_argument,NULL,'o'},
        {"help",no_argument,NULL,'h'},{NULL,0,NULL,0}
    };
    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "f:o:h", lo, NULL)) != -1) {
        switch (c) {
        case 'f': fmt    = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa capabilities [--format text|json] [--output <file>]\n\n"
                   "Emits the tool's supported commands and formats.\n");
            return 0;
        default: return 2;
        }
    }
    FILE *out = stdout;
    if (output) {
        int fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { perror(output); return 3; }
        if (!(out = fdopen(fd, "w"))) { close(fd); return 3; }
    }
    if (!strcmp(fmt, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
               "{\n"
               "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
               "  \"kind\": \"capabilities\",\n"
               "  \"tool\": \"c-FuSa\",\n"
               "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
               "  \"language\": \"c\",\n"
               "  \"generatedAt\": \"%s\",\n"
               "  \"specVersion\": \"" CFUSA_SPEC_VERSION "\",\n"
               "  \"commands\": [\n"
               "    \"version\", \"capabilities\", \"init\", \"check\", \"trace\", \"qualify\", \"release\",\n"
               "    \"audit-pack\", \"report\", \"verify\", \"hara\", \"tara\", \"fmea\", \"safety-case\",\n"
               "    \"coupling\", \"cyber\", \"vuln\", \"boundary\", \"coverage\", \"diff\", \"badge\",\n"
               "    \"iso26262\", \"iec61508\", \"iec62443\", \"slsa\", \"do178\", \"iso21434\", \"unece\",\n"
               "    \"lint\", \"analyze\", \"disposition\", \"sign\", \"sas\", \"sci\", \"pr\", \"req\",\n"
               "    \"fix\", \"hooks\", \"impact\", \"metrics\", \"comp\", \"template\", \"misra\"\n"
               "  ],\n"
               "  \"formats\": {\n"
               "    \"check\":     [\"text\", \"json\", \"sarif\", \"html\", \"md\"],\n"
               "    \"report\":    [\"text\", \"json\", \"sarif\", \"html\", \"md\"],\n"
               "    \"trace\":     [\"text\", \"json\", \"md\"],\n"
               "    \"qualify\":   [\"text\", \"json\"],\n"
               "    \"comp\":      [\"text\", \"json\"],\n"
               "    \"coverage\":  [\"text\", \"json\"],\n"
               "    \"do178\":     [\"text\", \"md\", \"json\"],\n"
               "    \"iso26262\":  [\"text\", \"json\"],\n"
               "    \"iec61508\":  [\"text\", \"json\"],\n"
               "    \"iec62443\":  [\"text\", \"json\"],\n"
               "    \"misra\":     [\"text\", \"json\"],\n"
               "    \"iso21434\":  [\"text\", \"json\"],\n"
               "    \"unece\":     [\"text\", \"json\"],\n"
               "    \"slsa\":      [\"text\", \"json\"],\n"
               "    \"vuln\":      [\"text\", \"json\"],\n"
               "    \"diff\":      [\"json\"],\n"
               "    \"sci\":       [\"text\", \"json\"],\n"
               "    \"coupling\":  [\"json\"],\n"
               "    \"version\":   [\"text\", \"json\"]\n"
               "  },\n"
               "  \"standards\": [\"iso26262\", \"iec61508\", \"iec62443\", \"do178c\", \"misra-c\",\n"
               "               \"iso21434\", \"unece-r155\", \"slsa\"]\n"
               "}\n",
               ts);
    } else {
        fprintf(out, "c-FuSa %s (spec %s)\nRequired commands: version capabilities init check trace qualify release audit-pack report\nStandards: iso26262 iec61508 iec62443 do178c misra-c iso21434 unece-r155 slsa\n",
                CFUSA_VERSION_STRING, CFUSA_SPEC_VERSION);
    }
    if (out != stdout) fclose(out);
    return 0;
}
