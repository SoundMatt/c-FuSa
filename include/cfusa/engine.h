#ifndef CFUSA_ENGINE_H
#define CFUSA_ENGINE_H

#include "report.h"
#include "config.h"

#define CFUSA_MAX_RULES         256
#define CFUSA_MAX_LINE_RULES    128
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
    const char    *standard_id;  /* canonical lowercase id (x-FuSa spec §2.4.1),
                                     e.g. "misra-c" — NULL/"" when no external
                                     standard applies (e.g. project-structure
                                     self-checks) */
    const char    *clause;       /* clause/rule reference within standard_id,
                                     e.g. "R15.1" — NULL/"" when not applicable */
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

/* ---- line-rule registration (issue #204) ----
 *
 * Every cfusa_rule_t rule whose .run() amounts to "walk the source tree,
 * open/read each qualifying file, and pattern-match each line" used to
 * do so entirely on its own -- cfusa_walk_sources() was called
 * independently by each such rule, so a source tree got walked (and
 * each qualifying file opened and read) once PER RULE rather than once
 * total; 54 separate cfusa_walk_sources() call sites were counted across
 * this project's cmd/cfusa command sources before this was introduced.
 *
 * cfusa_engine_register_line_rule() registers a pure per-line pattern-
 * matcher instead: cfusa_engine_run_all()/run_category() now perform
 * ONE source-tree walk, open and read each qualifying file ONCE, strip
 * each line through the shared cfusa_lex_strip_line() (cfusa/lex.h)
 * ONCE, and dispatch that single stripped line to every registered line
 * rule whose extension filter matches and whose id isn't disabled via
 * .fusa.json's "disabled_rules" -- rather than each rule re-opening and
 * re-scanning the same files independently. A rule whose logic needs
 * state that spans more than one line within a single file (e.g.
 * brace-depth/function-scope tracking) does not fit this shape and
 * should stay a regular whole-file cfusa_rule_t instead. */
/* `rpt` is passed explicitly (like cfusa_rule_fn's `rpt` parameter)
 * rather than expected to live inside `ctx`, since `ctx` is fixed once
 * at registration time -- before any cfusa_report_t exists for a given
 * run -- while `rpt` is only known once cfusa_engine_run_all()/
 * run_category() is actually called, and can differ across calls (e.g.
 * a fresh report per test case). `ctx` remains available for whatever
 * OTHER fixed, rule-specific state a callback needs. */
typedef void (*cfusa_line_rule_cb)(const char *path, int lineno,
                                    const char *code_line,
                                    const cfusa_config_t *cfg,
                                    cfusa_report_t *rpt, void *ctx);

typedef struct {
    const char           *id;
    const char           *category;
    const char           *name;
    const char           *description;
    const char           *standard_id; /* see cfusa_rule_t above */
    const char           *clause;      /* see cfusa_rule_t above */
    const char * const   *exts;        /* file extensions this rule applies to,
                                           e.g. {".c", ".h"} */
    int                    n_exts;
    cfusa_line_rule_cb     cb;
    void                  *ctx;        /* passed through to `cb` unchanged;
                                           owned by the caller, must outlive
                                           every cfusa_engine_run_all()/
                                           run_category() call */
} cfusa_line_rule_t;

/* Registers `rule` for the engine's single-pass walk-and-dispatch. Also
 * registers rule's id/category/name/description/standard_id/clause into
 * the SAME table cfusa_engine_get_rule()/cfusa_engine_list_rules() use
 * (as a metadata-only entry whose .run() is a no-op — the real findings
 * come from the walk-and-dispatch pass, not from that entry being
 * invoked) so report.c's per-finding standard/clause lookup and `cfusa
 * <cmd> --list-rules`-style output keep working exactly as they do for
 * a regular cfusa_rule_t, with no separate cfusa_engine_register() call
 * needed at the call site. */
void cfusa_engine_register_line_rule(const cfusa_line_rule_t *rule);

/* Called by cmd_lint / cmd_analyze / cmd_cyber / cmd_safety_rules to register rule sets. */
void cfusa_lint_register_rules(void);
void cfusa_analyze_register_rules(void);
void cfusa_cyber_register_rules(void);
void cfusa_safety_register_rules(void);
int  cfusa_safety_rule_count(void);

#endif /* CFUSA_ENGINE_H */
