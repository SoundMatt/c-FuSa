#ifndef CFUSA_FIX_H
#define CFUSA_FIX_H

/* issue #212: cmd_fix.c's remediation-guidance table is the same data
 * `cfusa explain <RULE-ID>` wants to show alongside a rule's description
 * and standard citation -- expose a read-only lookup instead of a second,
 * inevitably-drifting copy of the same ~39 entries. */

typedef struct {
    const char *rule_id;
    const char *summary;
    const char *guidance;
} cfusa_fix_entry_t;

/* Returns the FIXES[] entry for `rule_id`, or NULL if that rule has no
 * remediation guidance (yet). Owned by cmd_fix.c; the returned pointer is
 * valid for the process lifetime (points into a static const table). */
const cfusa_fix_entry_t *cfusa_fix_lookup(const char *rule_id);

#endif /* CFUSA_FIX_H */
