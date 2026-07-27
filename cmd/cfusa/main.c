#include <stdio.h>
#include <string.h>
#include "cfusa/commands.h"
#include "cfusa/version.h"

/*
 * CFUSA_COMMANDS, CFUSA_COMMAND_COUNT and cmd_help() live in cmd_dispatch.c
 * (kept unit-testable there); this file only wires argv shifting and the
 * dispatch loop, and cannot itself be linked into a unit-test binary because
 * it defines main().
 */

//cfusa:req REQ-CLI-MAIN001
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
