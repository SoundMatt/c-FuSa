#include <stdio.h>
#include <string.h>
#include "cfusa/commands.h"
#include "cfusa/version.h"

const cfusa_command_t CFUSA_COMMANDS[] = {
    {"init",        "Initialise a .cfusa.json project config",          cmd_init},
    {"check",       "Run all safety checks (exits 1 on findings)",      cmd_check},
    {"lint",        "MISRA-C / CERT-C coding standard checks",          cmd_lint},
    {"analyze",     "Static analysis: overflows, unchecked returns",    cmd_analyze},
    {"cyber",       "CWE-mapped cybersecurity rules (ISO 21434)",       cmd_cyber},
    {"tara",        "Threat Analysis & Risk Assessment skeleton",        cmd_tara},
    {"fmea",        "Design FMEA from function signatures",             cmd_fmea},
    {"report",      "Full compliance report (text/json/sarif/html/md)", cmd_report},
    {"template",    "Safety doc templates (HARA, PSAC, etc.)",          cmd_template},
    {"trace",       "Requirements traceability matrix",                 cmd_trace},
    {"verify",      "Collect and bundle test evidence",                 cmd_verify},
    {"release",     "SBOM (SPDX), build provenance, artifact hashes",  cmd_release},
    {"qualify",     "Tool self-test and qualification record",          cmd_qualify},
    {"safety-case", "GSN safety case skeleton + evidence index",        cmd_safety_case},
    {"boundary",    "Component dependency graph from #include",         cmd_boundary},
    {"vuln",        "Known-vulnerable function pattern scan",           cmd_vuln},
    {"audit-pack",  "Bundle all artifacts into audit package",          cmd_audit_pack},
    {"diff",        "Compare two cfusa JSON reports",                   cmd_diff},
    {"badge",       "SVG status badge from report",                     cmd_badge},
    {"req",         "Show source locations for a requirement ID",       cmd_req},
    {"fix",         "Apply mechanical auto-fixes",                      cmd_fix},
    {"hooks",       "Install / remove git pre-commit hook",             cmd_hooks},
    {"sign",        "HMAC-SHA256 file signing and verification",        cmd_sign},
    {"do178",       "DO-178C Annex A objective gap report",             cmd_do178},
    {"sas",         "Software Accomplishment Summary (DO-178C §11.20)", cmd_sas},
    {"sci",         "Software Configuration Index with SHA-256",        cmd_sci},
    {"coverage",    "Structural coverage from gcov/lcov",               cmd_coverage},
    {"pr",          "Problem report CRUD log (DO-178C §11.17)",         cmd_pr},
    {"hara",        "Hazard Analysis & Risk Assessment (ISO 26262 §3)", cmd_hara},
    {"iso26262",    "ISO 26262 Part 6 compliance gap report",           cmd_iso26262},
    {"iec61508",    "IEC 61508 Parts 1–3 compliance gap report",        cmd_iec61508},
    {"misra",       "MISRA-C:2012 rule coverage mapping",               cmd_misra},
    {"disposition", "Manage finding disposition entries",               cmd_disposition},
    {"impact",      "Change impact analysis on requirements",           cmd_impact},
    {"metrics",     "Track safety metrics over time",                   cmd_metrics},
    {"coupling",    "Data/control coupling analysis (DO-178C §6.4.4.3)",cmd_coupling},
    {"iso21434",    "ISO 21434 cybersecurity compliance gap report",    cmd_iso21434},
    {"unece",       "UN R.155 cybersecurity compliance gap report",     cmd_unece},
    {"capabilities","Emit supported commands/formats (FuSaOps discovery)", cmd_capabilities},
    {"version",     "Print version",                                    cmd_version},
    {"help",        "Show this help",                                   cmd_help},
    {NULL, NULL, NULL}
};

const int CFUSA_COMMAND_COUNT =
    (int)(sizeof(CFUSA_COMMANDS)/sizeof(CFUSA_COMMANDS[0])) - 1;

int cmd_help(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("cfusa %s — C functional safety toolkit\n\n", CFUSA_VERSION_STRING);
    printf("Usage: cfusa <command> [options]\n\n");
    printf("Commands:\n\n");
    for (int i = 0; CFUSA_COMMANDS[i].name; i++)
        printf("  %-18s  %s\n", CFUSA_COMMANDS[i].name,
               CFUSA_COMMANDS[i].description);
    printf("\nRun 'cfusa <command> --help' for command-specific options.\n");
    printf("Documentation: https://github.com/SoundMatt/c-FuSa\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        cmd_help(0, NULL);
        return 0;
    }

    const char *cmd_name = argv[1];

    /* Pass remaining args to the command (shift by 1 so argv[0] is "cfusa <cmd>") */
    char prog_name[64];
    snprintf(prog_name, sizeof(prog_name), "cfusa %s", cmd_name);
    argv[1] = prog_name;
    argc--;
    argv++;

    for (int i = 0; CFUSA_COMMANDS[i].name; i++) {
        if (!strcmp(cmd_name, CFUSA_COMMANDS[i].name))
            return CFUSA_COMMANDS[i].run(argc, argv);
    }

    fprintf(stderr, "cfusa: unknown command '%s'\n"
            "Run 'cfusa help' for a list of commands.\n", cmd_name);
    return 2;
}
