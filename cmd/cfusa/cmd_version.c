#include <stdio.h>
#include "cfusa/version.h"

int cmd_version(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("cfusa version %s\n", CFUSA_VERSION_STRING);
    printf("C functional safety toolkit\n");
    printf("https://github.com/SoundMatt/c-FuSa\n");
    printf("License: Mozilla Public License 2.0\n");
    return 0;
}
