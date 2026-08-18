#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cfusa/disposition.h"
#include "cfusa/utils.h"

#define DISP_FILE        ".fusa-dispositions.json"
#define DISP_FILE_LEGACY ".cfusa-dispositions.json"
#define DISP_INITIAL_CAP 32

static int disp_reserve(cfusa_disposition_list_t *list, int need)
{
    if (need <= list->cap) return 1;
    int new_cap = list->cap ? list->cap : DISP_INITIAL_CAP;
    while (new_cap < need) new_cap *= 2;
    cfusa_disposition_t *tmp = realloc(list->items,
                                        (size_t)new_cap * sizeof(cfusa_disposition_t));
    if (!tmp) return 0;
    list->items = tmp;
    list->cap = new_cap;
    return 1;
}

//cfusa:req REQ-DISP-ENFORCE001
int cfusa_dispositions_load(const char *dir, cfusa_disposition_list_t *list)
{
    memset(list, 0, sizeof(*list));

    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);
    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, DISP_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) return 1; /* no dispositions file at all — not an error */

    int ok = 1;
    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16] = "", rule[64] = "", fingerprint[72] = "", action[16] = "";
        char *fp;
        if ((fp = strstr(p, "\"id\":")))         sscanf(fp, "\"id\":\"%15[^\"]", id);
        if ((fp = strstr(p, "\"rule\":")))        sscanf(fp, "\"rule\":\"%63[^\"]", rule);
        if ((fp = strstr(p, "\"fingerprint\":"))) sscanf(fp, "\"fingerprint\":\"%71[^\"]", fingerprint);
        if ((fp = strstr(p, "\"action\":")))      sscanf(fp, "\"action\":\"%15[^\"]", action);

        if (id[0]) {
            if (!disp_reserve(list, list->count + 1)) {
                fprintf(stderr,
                    "cfusa: WARNING: out of memory loading %s — only %d "
                    "disposition(s) loaded; some previously-accepted "
                    "findings may not be suppressed this run\n",
                    DISP_FILE, list->count);
                ok = 0;
                break;
            }
            cfusa_disposition_t *d = &list->items[list->count];
            memset(d, 0, sizeof(*d));
            strncpy(d->id,          id,          sizeof(d->id) - 1);
            strncpy(d->rule,        rule,        sizeof(d->rule) - 1);
            strncpy(d->fingerprint, fingerprint, sizeof(d->fingerprint) - 1);
            strncpy(d->action,      action,      sizeof(d->action) - 1);
            list->count++;
        }
        p++; /* advance past this match so the next strstr() finds the
                following entry's "id" field, not the same one again */
    }
    free(content);
    return ok;
}

void cfusa_dispositions_free(cfusa_disposition_list_t *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap   = 0;
}

//cfusa:req REQ-DISP-ENFORCE002
void cfusa_report_apply_dispositions(cfusa_report_t *rpt,
                                      const cfusa_disposition_list_t *list)
{
    for (int i = 0; i < rpt->count; i++) {
        cfusa_finding_t *f = &rpt->findings[i];
        if (!f->fingerprint[0]) continue;

        for (int j = 0; j < list->count; j++) {
            const cfusa_disposition_t *d = &list->items[j];
            /* A disposition recorded without --fingerprint (rule-only)
             * never matches — see the header comment on why rule-only
             * scoping is deliberately not honored here. */
            if (!d->fingerprint[0]) continue;
            if (strcmp(d->fingerprint, f->fingerprint) != 0) continue;
            /* "fix" is a historical audit note only — the code presumably
             * no longer matches, so there is nothing live to suppress. */
            if (strcmp(d->action, "accept") != 0 && strcmp(d->action, "mitigate") != 0)
                continue;

            strncpy(f->disposition_id,     d->id,     sizeof(f->disposition_id) - 1);
            strncpy(f->disposition_action, d->action, sizeof(f->disposition_action) - 1);

            switch (f->severity) {
            case SEV_ERROR:   if (rpt->error_count   > 0) rpt->error_count--;   break;
            case SEV_WARNING: if (rpt->warning_count > 0) rpt->warning_count--; break;
            case SEV_INFO:    if (rpt->info_count    > 0) rpt->info_count--;    break;
            }
            rpt->dispositioned_count++;
            break; /* first matching disposition wins */
        }
    }
}
