#include <string.h>
#include <stdio.h>
#include "cfusa/engine.h"

//cfusa:req REQ-ENG001 REQ-ENG002 REQ-ENG003 REQ-ENG004 REQ-ENG005
static const cfusa_rule_t *g_rules[CFUSA_MAX_RULES];
static int                 g_rule_count = 0;

void cfusa_engine_reset(void)
{
    g_rule_count = 0;
}

void cfusa_engine_register(const cfusa_rule_t *rule)
{
    if (g_rule_count >= CFUSA_MAX_RULES) {
        fprintf(stderr, "cfusa: rule table full, cannot register %s\n", rule->id);
        return;
    }
    g_rules[g_rule_count++] = rule;
}

int cfusa_engine_rule_count(void)
{
    return g_rule_count;
}

void cfusa_engine_list_rules(void)
{
    printf("%-18s %-10s %-40s %s\n", "ID", "CATEGORY", "NAME", "STANDARD");
    printf("%-18s %-10s %-40s %s\n",
           "------------------", "----------",
           "----------------------------------------", "--------");
    for (int i = 0; i < g_rule_count; i++) {
        const cfusa_rule_t *r = g_rules[i];
        printf("%-18s %-10s %-40s %s\n",
               r->id, r->category, r->name,
               r->standard ? r->standard : "");
    }
}

int cfusa_engine_run_all(const char *dir, const cfusa_config_t *cfg,
                          cfusa_report_t *rpt)
{
    int total = 0;
    for (int i = 0; i < g_rule_count; i++) {
        total += g_rules[i]->run(dir, cfg, rpt);
    }
    return total;
}

int cfusa_engine_run_category(const char *category, const char *dir,
                               const cfusa_config_t *cfg, cfusa_report_t *rpt)
{
    int total = 0;
    for (int i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i]->category, category) == 0)
            total += g_rules[i]->run(dir, cfg, rpt);
    }
    return total;
}
