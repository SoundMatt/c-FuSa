#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * MISRA C:2012 rule coverage mapping.
 * Shows which MISRA-C:2012 rules cfusa covers, and which are gaps.
 */

typedef struct {
    const char *rule;
    const char *category;   /* mandatory / required / advisory */
    const char *title;
    const char *cfusa_rule; /* NULL = not covered */
} misra_row_t;

static const misra_row_t MISRA_RULES[] = {
    {"R1.1",  "required",  "All code shall conform to ISO 9899:2011",           NULL},
    {"R1.2",  "advisory",  "Language extensions should not be used",            NULL},
    {"R1.3",  "required",  "There shall be no occurrence of undefined behaviour",NULL},
    {"R2.1",  "required",  "A project shall not contain unreachable code",       NULL},
    {"R2.2",  "required",  "There shall be no dead code",                        NULL},
    {"R4.1",  "required",  "Octal and hexadecimal escapes shall be terminated",  NULL},
    {"R5.1",  "required",  "External identifiers shall be distinct",             NULL},
    {"R5.7",  "required",  "A tag name shall be a unique identifier",            NULL},
    {"R6.1",  "required",  "Bit-fields shall only be of essential Boolean type", NULL},
    {"R7.1",  "required",  "Octal constants shall not be used",                  NULL},
    {"R7.2",  "required",  "A suffix shall be applied to all integer constants", NULL},
    {"R7.4",  "required",  "A string literal shall not be assigned to an object with non-const type", NULL},
    {"R8.1",  "required",  "Types shall be explicitly specified",                NULL},
    {"R8.9",  "advisory",  "An object should be defined at block scope if possible","CFUSA-L007"},
    {"R9.1",  "mandatory", "The value of an object shall not be read before set", NULL},
    {"R10.1", "required",  "Operands shall not be of an inappropriate essential type",NULL},
    {"R10.3", "required",  "The value of an expression shall not be assigned to object of inappropriate type",NULL},
    {"R10.4", "required",  "Both operands of a binary operator shall have compatible types",NULL},
    {"R11.5", "advisory",  "A conversion should not be performed from pointer to void","CFUSA-L008"},
    {"R12.1", "advisory",  "The precedence of operators within expressions should be made explicit",NULL},
    {"R13.2", "required",  "The value of an expression shall be the same under any order of evaluation",NULL},
    {"R14.2", "required",  "A for loop shall be well-formed",                    NULL},
    {"R15.1", "advisory",  "The goto statement should not be used",              "CFUSA-L002"},
    {"R15.2", "required",  "The goto statement shall jump to a label after the current point",NULL},
    {"R15.5", "advisory",  "A function should have a single point of exit",      "CFUSA-L001"},
    {"R17.2", "required",  "Functions shall not call themselves, directly or indirectly","CFUSA-L004"},
    {"R17.4", "mandatory", "All exit paths from a function with non-void return shall have explicit return","CFUSA-L006"},
    {"R18.4", "advisory",  "The +, -, += and -= operators should not be applied to pointer-type expressions","CFUSA-A006"},
    {"R20.4", "required",  "A macro shall not be defined with the same name as a keyword",NULL},
    {"R20.5", "advisory",  "#undef should not be used",                          "CFUSA-L005"},
    {"R20.10","advisory",  "The # and ## preprocessor operators should not be used","CFUSA-L009"},
    {"R21.3", "required",  "Memory allocation and deallocation from stdlib shall not be used","CFUSA-L003"},
    {"R21.6", "required",  "Standard library I/O functions shall not be used in production",NULL},
    {"R22.8", "required",  "The value of errno shall be set to zero before call", "CFUSA-L010"},
    {NULL,NULL,NULL,NULL}
};

int cmd_misra(int argc, char **argv)
{
    const char *dir       = ".";
    const char *fmt_s     = "text";
    const char *output    = NULL;
    int         gaps_only = 0;

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"gaps",   no_argument,       NULL, 'g'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:f:o:gh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir       = optarg; break;
        case 'f': fmt_s     = optarg; break;
        case 'o': output    = optarg; break;
        case 'g': gaps_only = 1;     break;
        case 'h':
            printf("Usage: cfusa misra [--dir <path>] [--gaps]\n"
                   "                   [--format text|json] [--output <file>]\n\n"
                   "MISRA C:2012 rule coverage mapping.\n"
                   "  --gaps   Show only rules not covered by cfusa\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    int covered = 0, not_covered = 0;
    for (int i = 0; MISRA_RULES[i].rule; i++) {
        if (MISRA_RULES[i].cfusa_rule) covered++; else not_covered++;
    }

    FILE *out = stdout;
    if (output) { out = fopen(output, "w"); if (!out) { perror(output); return 3; } }

    if (!strcmp(fmt_s, "json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        fprintf(out,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"misra-coverage\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"projectRoot\": \"%s\",\n"
            "  \"standard\": \"MISRA C:2012\",\n"
            "  \"project\": \"%s\",\n"
            "  \"covered\": %d,\n"
            "  \"gaps\": %d,\n"
            "  \"rules\": [\n",
            ts, dir, cfg.project, covered, not_covered);
        int first = 1;
        for (int i = 0; MISRA_RULES[i].rule; i++) {
            const misra_row_t *r = &MISRA_RULES[i];
            if (gaps_only && r->cfusa_rule) continue;
            if (!first) fprintf(out, ",\n");
            const char *status = r->cfusa_rule ? "covered" : "gap";
            fprintf(out,
                "    {\"id\": \"%s\", \"category\": \"%s\","
                " \"title\": \"%s\", \"rule\": %s%s%s, \"status\": \"%s\"}",
                r->rule, r->category, r->title,
                r->cfusa_rule ? "\"" : "", r->cfusa_rule ? r->cfusa_rule : "null",
                r->cfusa_rule ? "\"" : "",
                status);
            first = 0;
        }
        fprintf(out, "\n  ]\n}\n");
    } else {
        fprintf(out, "MISRA C:2012 Rule Coverage\n");
        fprintf(out, "==========================\n\n");
        fprintf(out, "%-8s %-12s %-52s %s\n", "Rule", "Category", "Title", "cfusa Coverage");
        fprintf(out, "%-8s %-12s %-52s %s\n",
               "--------", "------------",
               "----------------------------------------------------", "--------------");

        for (int i = 0; MISRA_RULES[i].rule; i++) {
            const misra_row_t *r = &MISRA_RULES[i];
            if (gaps_only && r->cfusa_rule) continue;
            const char *coverage = r->cfusa_rule ? r->cfusa_rule : "GAP";
            fprintf(out, "%-8s %-12s %-52s %s\n",
                   r->rule, r->category, r->title, coverage);
        }

        fprintf(out, "\n%d rules covered by cfusa, %d gap(s).\n", covered, not_covered);
        fprintf(out, "Note: cfusa covers MISRA checking at the pattern/lint level.\n"
               "Full MISRA-C:2012 conformance requires compiler/static-analyser integration.\n");
    }

    if (output && out != stdout) fclose(out);
    return 0;
}
