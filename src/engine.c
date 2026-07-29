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

const cfusa_rule_t *cfusa_engine_get_rule(int i)
{
    if (i < 0 || i >= g_rule_count) return NULL;
    return g_rules[i];
}

void cfusa_engine_list_rules(void)
{
    printf("%-18s %-10s %-40s %s\n", "ID", "CATEGORY", "NAME", "STANDARD");
    printf("%-18s %-10s %-40s %s\n",
           "------------------", "----------",
           "----------------------------------------", "--------");
    for (int i = 0; i < g_rule_count; i++) {
        const cfusa_rule_t *r = g_rules[i];
        char std_disp[80];
        if (r->standard_id && r->standard_id[0]) {
            if (r->clause && r->clause[0])
                snprintf(std_disp, sizeof(std_disp), "%s %s", r->standard_id, r->clause);
            else
                snprintf(std_disp, sizeof(std_disp), "%s", r->standard_id);
        } else {
            std_disp[0] = '\0';
        }
        printf("%-18s %-10s %-40s %s\n",
               r->id, r->category, r->name, std_disp);
    }
}

int cfusa_engine_run_all(const char *dir, const cfusa_config_t *cfg,
                          cfusa_report_t *rpt)
{
    int total = 0;
    for (int i = 0; i < g_rule_count; i++) {
        if (!cfusa_config_is_rule_disabled(cfg, g_rules[i]->id))
            total += g_rules[i]->run(dir, cfg, rpt);
    }
    return total;
}

int cfusa_engine_run_category(const char *category, const char *dir,
                               const cfusa_config_t *cfg, cfusa_report_t *rpt)
{
    int total = 0;
    for (int i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i]->category, category) == 0
            && !cfusa_config_is_rule_disabled(cfg, g_rules[i]->id))
            total += g_rules[i]->run(dir, cfg, rpt);
    }
    return total;
}
