//cfusa:req REQ-EXPLAIN001 REQ-EXPLAIN002 REQ-EXPLAIN003

/*
 * cfusa explain <RULE-ID> — issue #212: onboarding aid. Prints a rule's
 * full metadata (name, standard/clause citation, description) plus its
 * remediation guidance from `cfusa fix`'s table, in one place, so a team
 * new to the tool doesn't have to go read the rule's source to understand
 * a finding.
 *
 * Deliberately does NOT introduce a second, separately-authored writeup
 * table: cfusa_rule_t already carries id/category/name/description/
 * standard_id/clause for every registered rule (both whole-file rules and
 * the line-rule metadata stubs cfusa_engine_register_line_rule() creates
 * — see engine.h), and cfusa_fix_lookup() (cfusa/fix.h) already carries
 * remediation guidance for every rule that has one. This command is a
 * thin, hand-authoring-free presentation layer over both.
 */
#if defined(__linux__) || defined(__unix__)
#  define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "cfusa/engine.h"
#include "cfusa/fix.h"

/* Registers every rule set so the full metadata table is populated,
 * regardless of which category the requested rule id belongs to. Mirrors
 * cmd_check.c/cmd_fix.c's own registration calls. */
static void register_all_rules(void)
{
    cfusa_engine_reset();
    cfusa_lint_register_rules();
    cfusa_analyze_register_rules();
    cfusa_cyber_register_rules();
    cfusa_safety_register_rules();
}

/* Skips a leading "CFUSA-"/"CFUSA_" prefix (case-insensitive), if present.
 * Rule ids outside the lint/analyze/cyber families (COMP001, HARA001, ...)
 * never carry the prefix to begin with, so this is a no-op for them. */
static const char *skip_cfusa_prefix(const char *id)
{
    if ((id[0] == 'c' || id[0] == 'C') && (id[1] == 'f' || id[1] == 'F') &&
        (id[2] == 'u' || id[2] == 'U') && (id[3] == 's' || id[3] == 'S') &&
        (id[4] == 'a' || id[4] == 'A') && (id[5] == '-' || id[5] == '_'))
        return id + 6;
    return id;
}

/* Findings/rule ids are case-sensitive elsewhere in the tool, but a human
 * typing `cfusa explain cy006` at a shell prompt shouldn't have to
 * remember the exact "CFUSA-" prefix and casing — strip that prefix from
 * both sides, then compare case-insensitively (also ignoring any stray
 * '-'/'_' separator so "cy-006" and "cy_006" match too). */
static int ids_match_loosely(const char *a, const char *b)
{
    a = skip_cfusa_prefix(a);
    b = skip_cfusa_prefix(b);
    while (*a || *b) {
        while (*a == '-' || *a == '_') a++;
        while (*b == '-' || *b == '_') b++;
        if (!*a || !*b) break;
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

static const cfusa_rule_t *find_rule_loosely(const char *want)
{
    int n = cfusa_engine_rule_count();
    /* Exact match first, so an id that happens to be a substring/loose
     * match of a different rule's id never shadows the real one. */
    for (int i = 0; i < n; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (!strcmp(r->id, want)) return r;
    }
    for (int i = 0; i < n; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (ids_match_loosely(r->id, want)) return r;
    }
    return NULL;
}

static void print_wrapped_guidance(const char *g)
{
    char line_buf[256];
    while (*g) {
        const char *nl = strchr(g, '\n');
        size_t len = nl ? (size_t)(nl - g) : strlen(g);
        if (len >= sizeof(line_buf)) len = sizeof(line_buf) - 1;
        memcpy(line_buf, g, len); line_buf[len] = '\0';
        printf("    %s\n", line_buf);
        if (!nl) break;
        g = nl + 1;
    }
}

static void print_rule_ids(void)
{
    int n = cfusa_engine_rule_count();
    const char *last_category = "";
    for (int i = 0; i < n; i++) {
        const cfusa_rule_t *r = cfusa_engine_get_rule(i);
        if (strcmp(r->category, last_category) != 0) {
            printf("\n%s:\n", r->category);
            last_category = r->category;
        }
        printf("  %-16s %s\n", r->id, r->name);
    }
}

int cmd_explain(int argc, char **argv)
{
    if (argc >= 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        printf("Usage: cfusa explain <RULE-ID>\n"
               "       cfusa explain --list\n\n"
               "Prints a rule's full description, standard/clause citation, and\n"
               "remediation guidance (when available) in one place.\n"
               "  --list   List every registered rule id, grouped by category\n");
        return 0;
    }

    register_all_rules();

    if (argc >= 2 && (!strcmp(argv[1], "--list") || !strcmp(argv[1], "-l"))) {
        print_rule_ids();
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr,
            "cfusa explain: missing RULE-ID\n"
            "Usage: cfusa explain <RULE-ID>   (or: cfusa explain --list)\n");
        return 2;
    }

    const char *want = argv[1];
    const cfusa_rule_t *r = find_rule_loosely(want);
    if (!r) {
        fprintf(stderr, "cfusa explain: unknown rule '%s'\n", want);
        fprintf(stderr, "Run 'cfusa explain --list' to see every registered rule id.\n");
        return 1;
    }

    printf("%s — %s\n", r->id, r->name);
    printf("Category: %s\n", r->category);
    if (r->standard_id && r->standard_id[0]) {
        if (r->clause && r->clause[0])
            printf("Standard: %s %s\n", r->standard_id, r->clause);
        else
            printf("Standard: %s\n", r->standard_id);
    }
    if (r->description && r->description[0])
        printf("\n%s\n", r->description);

    const cfusa_fix_entry_t *fix = cfusa_fix_lookup(r->id);
    if (fix) {
        printf("\nFix: %s\n", fix->summary);
        printf("Guidance:\n");
        print_wrapped_guidance(fix->guidance);
    } else {
        printf("\nNo automated remediation guidance for this rule yet —\n"
               "see the description above and the standard clause it maps to.\n");
    }
    return 0;
}
