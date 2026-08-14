#include <string.h>
#include <ctype.h>
#include "cfusa/severity.h"

/* Case-insensitive equality — kept local rather than pulling in
 * strcasecmp() (POSIX, not C99) for one small comparison, matching the
 * project's existing convention (see qualitybar.c's qb_str_ieq_trim()). */
static int str_ieq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

int cfusa_dal_rank(const char *dal)
{
    if (!dal || !*dal) return -1;
    if (str_ieq(dal, "DAL-A")) return 4;
    if (str_ieq(dal, "DAL-B")) return 3;
    if (str_ieq(dal, "DAL-C")) return 2;
    if (str_ieq(dal, "DAL-D")) return 1;
    if (str_ieq(dal, "DAL-E")) return 0;
    return -1;
}

int cfusa_asil_rank(const char *asil)
{
    if (!asil || !*asil) return -1;
    if (str_ieq(asil, "QM"))     return 0;
    if (str_ieq(asil, "ASIL-A")) return 1;
    if (str_ieq(asil, "ASIL-B")) return 2;
    if (str_ieq(asil, "ASIL-C")) return 3;
    if (str_ieq(asil, "ASIL-D")) return 4;
    return -1;
}

int cfusa_required_severity(const char *enforce, const char *dal,
                             const char *asil, cfusa_severity_t *out_sev)
{
    if (enforce && str_ieq(enforce, "off"))
        return 0;
    if (enforce && str_ieq(enforce, "error")) {
        *out_sev = SEV_ERROR;
        return 1;
    }
    if (enforce && str_ieq(enforce, "warn")) {
        *out_sev = SEV_WARNING;
        return 1;
    }

    /* "auto" (including NULL/empty/unrecognized enforce values): derive
     * from whichever of dal/asil is more stringent. */
    int dr = cfusa_dal_rank(dal);
    int ar = cfusa_asil_rank(asil);
    int rank = (dr > ar) ? dr : ar; /* -1 if neither declared */

    if (rank <= 0) return 0; /* not declared, or DAL-E/QM -> gate off */
    *out_sev = (rank >= 3) ? SEV_ERROR : SEV_WARNING;
    return 1;
}

int cfusa_declared_asil_rank(const cfusa_config_t *cfg)
{
    if (!cfg) return -1;
    for (int i = 0; i < cfg->standards_count; i++) {
        const char *s = cfg->standards[i];
        if (strncmp(s, "iso26262", 8) == 0 || strncmp(s, "ISO 26262", 9) == 0) {
            const char *colon = strchr(s, ':');
            if (colon) {
                int r = cfusa_asil_rank(colon + 1);
                if (r >= 0) return r;
            }
        }
    }
    return -1;
}
