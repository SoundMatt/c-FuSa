#ifndef CFUSA_ENGINE_H
#define CFUSA_ENGINE_H

#include "report.h"
#include "config.h"

#define CFUSA_MAX_RULES         256
#define CFUSA_CATEGORY_LINT     "lint"
#define CFUSA_CATEGORY_ANALYZE  "analyze"
#define CFUSA_CATEGORY_CYBER    "cyber"
#define CFUSA_CATEGORY_ALL      "all"

typedef int (*cfusa_rule_fn)(const char *dir, const cfusa_config_t *cfg,
                              cfusa_report_t *rpt);

typedef struct {
    const char    *id;
    const char    *category;
    const char    *name;
    const char    *description;
    const char    *standard;     /* e.g. "MISRA-C:2012 R15.1" */
    cfusa_rule_fn  run;
} cfusa_rule_t;

void cfusa_engine_register(const cfusa_rule_t *rule);
int  cfusa_engine_run_all(const char *dir, const cfusa_config_t *cfg,
                           cfusa_report_t *rpt);
int  cfusa_engine_run_category(const char *category, const char *dir,
                                const cfusa_config_t *cfg,
                                cfusa_report_t *rpt);
int                  cfusa_engine_rule_count(void);
const cfusa_rule_t  *cfusa_engine_get_rule(int i);
void                 cfusa_engine_list_rules(void);
void                 cfusa_engine_reset(void);

/* Called by cmd_lint / cmd_analyze / cmd_cyber to register their rule sets. */
void cfusa_lint_register_rules(void);
void cfusa_analyze_register_rules(void);
void cfusa_cyber_register_rules(void);

#endif /* CFUSA_ENGINE_H */
