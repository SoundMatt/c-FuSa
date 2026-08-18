#include <ctype.h>
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

/* issue #175: a hand-edited or migrated dispositions file naturally spells
 * the action past-tense ("accepted"/"mitigated"/"fixed") or with different
 * casing ("Accept"/"ACCEPT") — lowercases in place and canonicalizes those
 * synonyms to the "accept"/"fix"/"mitigate" values
 * cfusa_report_apply_dispositions() actually matches on, so a naturally
 * -spelled entry still suppresses instead of silently never matching. */
static void disp_normalize_action(char *action)
{
    for (char *c = action; *c; c++) *c = (char)tolower((unsigned char)*c);
    if      (strcmp(action, "accepted")  == 0) strcpy(action, "accept");
    else if (strcmp(action, "mitigated") == 0) strcpy(action, "mitigate");
    else if (strcmp(action, "fixed")     == 0) strcpy(action, "fix");
}

/* Shared by cfusa_dispositions_load()/cfusa_baseline_load(): parses
 * `content` (id/rule/fingerprint/action entries, in any wrapper array —
 * the parser doesn't care what key they're nested under) into `list`.
 * `label` is only used in WARNING messages, so a baseline-vs-disposition
 * parse failure is still attributed to the right file. */
static int disp_parse(const char *content, const char *label,
                       cfusa_disposition_list_t *list)
{
    int ok = 1;
    const char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16] = "", rule[64] = "", fingerprint[72] = "", action[16] = "";
        cfusa_json_extract_string(p, "id",          id,          sizeof(id));
        cfusa_json_extract_string(p, "rule",        rule,        sizeof(rule));
        cfusa_json_extract_string(p, "fingerprint", fingerprint, sizeof(fingerprint));
        cfusa_json_extract_string(p, "action",      action,      sizeof(action));
        if (action[0]) {
            disp_normalize_action(action);
            if (strcmp(action, "accept")   != 0 && strcmp(action, "fix") != 0 &&
                strcmp(action, "mitigate") != 0 && strcmp(action, "baseline") != 0) {
                fprintf(stderr,
                    "cfusa: WARNING: %s entry %s has unrecognized action "
                    "'%s' (expected accept|fix|mitigate|baseline) — this "
                    "entry will not suppress any finding\n",
                    label, id[0] ? id : "<unknown id>", action);
            }
        }

        if (id[0]) {
            if (!disp_reserve(list, list->count + 1)) {
                fprintf(stderr,
                    "cfusa: WARNING: out of memory loading %s — only %d "
                    "entry/entries loaded; some previously-accepted "
                    "findings may not be suppressed this run\n",
                    label, list->count);
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
    return ok;
}

//cfusa:req REQ-DISP-ENFORCE001
int cfusa_dispositions_load_from(const char *path, cfusa_disposition_list_t *list)
{
    memset(list, 0, sizeof(*list));
    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) return 1; /* no such file — not an error */
    int ok = disp_parse(content, path, list);
    free(content);
    return ok;
}

int cfusa_dispositions_load(const char *dir, cfusa_disposition_list_t *list)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);
    if (cfusa_file_exists(path))
        return cfusa_dispositions_load_from(path, list);

    char legacy[512];
    cfusa_path_join(legacy, sizeof(legacy), dir, DISP_FILE_LEGACY);
    return cfusa_dispositions_load_from(legacy, list);
}

int cfusa_baseline_load(const char *dir, cfusa_disposition_list_t *list)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, CFUSA_BASELINE_FILE);
    return cfusa_dispositions_load_from(path, list);
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
        /* issue #208: already dispositioned by an earlier call against a
         * different list (e.g. .fusa-dispositions.json, then
         * .fusa-baseline.json) — skip so a second matching entry can
         * never double-decrement error_count/warning_count/
         * dispositioned_count for the same finding. */
        if (f->disposition_id[0]) continue;

        for (int j = 0; j < list->count; j++) {
            const cfusa_disposition_t *d = &list->items[j];
            /* A disposition recorded without --fingerprint (rule-only)
             * never matches — see the header comment on why rule-only
             * scoping is deliberately not honored here. */
            if (!d->fingerprint[0]) continue;
            if (strcmp(d->fingerprint, f->fingerprint) != 0) continue;
            /* "fix" is a historical audit note only — the code presumably
             * no longer matches, so there is nothing live to suppress.
             * issue #208: "baseline" suppresses the same way accept/
             * mitigate do (see cfusa_baseline_load()'s doc comment for
             * why it's a distinct action rather than reusing "accept"). */
            if (strcmp(d->action, "accept")   != 0 &&
                strcmp(d->action, "mitigate") != 0 &&
                strcmp(d->action, "baseline") != 0)
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
