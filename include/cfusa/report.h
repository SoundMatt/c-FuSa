#ifndef CFUSA_REPORT_H
#define CFUSA_REPORT_H

#include <stdio.h>
#include <stdarg.h>

#define CFUSA_MAX_FINDINGS    8192
#define CFUSA_FINDING_MSG_MAX  512
#define CFUSA_FINDING_FILE_MAX 256

typedef enum {
    SEV_ERROR   = 0,
    SEV_WARNING = 1,
    SEV_INFO    = 2
} cfusa_severity_t;

typedef struct {
    char             rule_id[32];
    char             category[32];
    char             file[CFUSA_FINDING_FILE_MAX];
    int              line;
    int              end_line;    /* §4 MAY — 0 means not set */
    int              end_column;  /* §4 MAY — 0 means not set */
    cfusa_severity_t severity;
    char             message[CFUSA_FINDING_MSG_MAX];
    char             fingerprint[72]; /* "sha256:" + 64 hex chars + NUL (§4.2) */
    /* issue #122: set by cfusa_report_apply_dispositions() when this
     * finding's fingerprint matches an accept/mitigate-action entry in
     * .fusa-dispositions.json. Empty disposition_id means undispositioned
     * — the finding is never removed from findings[] either way, only
     * tagged; see cfusa_report_apply_dispositions() in disposition.c. */
    char             disposition_id[16];
    char             disposition_action[16];
} cfusa_finding_t;

typedef struct {
    cfusa_finding_t *findings;
    int              count;
    int              capacity;
    int              error_count;
    int              warning_count;
    int              info_count;
    /* issue #122: count of findings excluded from error_count/warning_count/
     * info_count above by cfusa_report_apply_dispositions() — reported as
     * its own summary bucket rather than silently shrinking the other
     * three, so a reader can't mistake "reviewed and accepted" for "fixed". */
    int              dispositioned_count;
    char             project[128];
    char             version[32];
    char             standard[128];
    char             timestamp[32];
    char             project_root[512];
    char             kind[32];
    int              no_summary; /* if non-zero, suppress SUMMARY/TOP-RULES block in text output */
} cfusa_report_t;

typedef enum {
    FMT_TEXT  = 0,
    FMT_JSON  = 1,
    FMT_SARIF = 2,
    FMT_HTML  = 3,
    FMT_MD    = 4,
    FMT_CSV   = 5
} cfusa_format_t;

void           cfusa_report_init(cfusa_report_t *rpt);
void           cfusa_report_free(cfusa_report_t *rpt);
void           cfusa_report_add(cfusa_report_t *rpt, const char *rule_id,
                                 const char *category, cfusa_severity_t sev,
                                 const char *file, int line,
                                 const char *fmt, ...);
void           cfusa_report_print(const cfusa_report_t *rpt, FILE *out,
                                   cfusa_format_t fmt);
int            cfusa_report_write(const cfusa_report_t *rpt, const char *path,
                                   cfusa_format_t fmt);
double         cfusa_report_score(const cfusa_report_t *rpt);
const char    *cfusa_severity_str(cfusa_severity_t sev);
cfusa_format_t cfusa_format_parse(const char *s);

#endif /* CFUSA_REPORT_H */
