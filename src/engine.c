#include <string.h>
#include <stdio.h>
#include "cfusa/engine.h"
#include "cfusa/utils.h"
#include "cfusa/lex.h"

//cfusa:req REQ-ENG001 REQ-ENG002 REQ-ENG003 REQ-ENG004 REQ-ENG005
static const cfusa_rule_t *g_rules[CFUSA_MAX_RULES];
static int                 g_rule_count = 0;

/* ---- line-rule table (issue #204) ---- */
static cfusa_line_rule_t g_line_rules[CFUSA_MAX_LINE_RULES];
static int                g_line_rule_count = 0;
/* One metadata-only cfusa_rule_t stub per registered line rule, kept in
 * stable storage so cfusa_engine_register()'s stored pointer stays valid
 * for the program's lifetime -- see cfusa_engine_register_line_rule(). */
static cfusa_rule_t g_line_rule_stubs[CFUSA_MAX_LINE_RULES];

void cfusa_engine_reset(void)
{
    g_rule_count = 0;
    g_line_rule_count = 0;
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

/* issue #204: metadata-only .run() for a line rule's cfusa_rule_t stub --
 * the real findings come from cfusa_engine_run_line_rules() below, so
 * this exists purely so report.c's standard/clause lookup and
 * cfusa_engine_list_rules() see the rule without double-counting or
 * re-walking the tree a second time. */
static int line_rule_stub_run(const char *dir, const cfusa_config_t *cfg,
                               cfusa_report_t *rpt)
{
    (void)dir; (void)cfg; (void)rpt;
    return 0;
}

void cfusa_engine_register_line_rule(const cfusa_line_rule_t *rule)
{
    if (g_line_rule_count >= CFUSA_MAX_LINE_RULES) {
        fprintf(stderr, "cfusa: line-rule table full, cannot register %s\n", rule->id);
        return;
    }
    int idx = g_line_rule_count;
    g_line_rules[idx] = *rule;

    cfusa_rule_t *stub = &g_line_rule_stubs[idx];
    stub->id          = rule->id;
    stub->category     = rule->category;
    stub->name         = rule->name;
    stub->description  = rule->description;
    stub->standard_id  = rule->standard_id;
    stub->clause       = rule->clause;
    stub->run          = line_rule_stub_run;
    cfusa_engine_register(stub);

    g_line_rule_count++;
}

static int ext_matches_one(const char *path, const char * const *exts, int n_exts)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    for (int i = 0; i < n_exts; i++)
        if (strcmp(dot, exts[i]) == 0) return 1;
    return 0;
}

typedef struct {
    const cfusa_config_t *cfg;
    cfusa_report_t       *rpt;
    const char            *category; /* NULL = every registered line rule */
} line_walk_ctx_t;

static int line_walk_file_cb(const char *path, void *vctx)
{
    line_walk_ctx_t *wc = vctx;

    /* Which registered line rules actually apply to this one file? Decided
     * up front so the file is opened/read/lexed at most once even when
     * several rules match it, and not at all when none do. */
    int applicable[CFUSA_MAX_LINE_RULES];
    int n_applicable = 0;
    for (int i = 0; i < g_line_rule_count; i++) {
        const cfusa_line_rule_t *lr = &g_line_rules[i];
        if (wc->category && strcmp(lr->category, wc->category) != 0) continue;
        if (cfusa_config_is_rule_disabled(wc->cfg, lr->id)) continue;
        if (!ext_matches_one(path, lr->exts, lr->n_exts)) continue;
        applicable[n_applicable++] = i;
    }
    if (n_applicable == 0) return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    cfusa_lex_state_t lex;
    cfusa_lex_reset(&lex);
    char raw[4096], code[4096];
    int lineno = 0;
    while (fgets(raw, sizeof(raw), f)) {
        lineno++;
        size_t len = strlen(raw);
        if (len > 0 && raw[len - 1] == '\n') raw[len - 1] = '\0';
        cfusa_lex_strip_line(&lex, raw, code, sizeof(code));
        for (int k = 0; k < n_applicable; k++) {
            const cfusa_line_rule_t *lr = &g_line_rules[applicable[k]];
            lr->cb(path, lineno, code, wc->cfg, wc->rpt, lr->ctx);
        }
    }

    if (fclose(f) != 0)
        fprintf(stderr, "cfusa: warning: fclose failed for %s\n", path);
    return 0;
}

/* Runs the single-pass walk-and-dispatch for every currently-registered
 * line rule (or only those in `category`, when non-NULL) and returns the
 * number of findings it produced -- computed from rpt->count's delta
 * rather than threaded through every callback, since cfusa_report_add()
 * is the only place a line rule's finding count actually changes. */
static int cfusa_engine_run_line_rules(const char *category, const char *dir,
                                        const cfusa_config_t *cfg,
                                        cfusa_report_t *rpt)
{
    if (g_line_rule_count == 0) return 0;

    /* Union of every registered line rule's own extension list -- each
     * rule's OWN filter (checked per-file above) still scopes it to
     * exactly the extensions it asked for; this union just decides which
     * files are worth opening/lexing at all during the single walk. */
    const char *ext_union[16];
    int n_ext_union = 0;
    for (int i = 0; i < g_line_rule_count; i++) {
        const cfusa_line_rule_t *lr = &g_line_rules[i];
        for (int j = 0; j < lr->n_exts; j++) {
            int dup = 0;
            for (int k = 0; k < n_ext_union; k++)
                if (strcmp(ext_union[k], lr->exts[j]) == 0) { dup = 1; break; }
            if (!dup && n_ext_union < (int)(sizeof(ext_union) / sizeof(ext_union[0])))
                ext_union[n_ext_union++] = lr->exts[j];
        }
    }

    int before = rpt->count;
    line_walk_ctx_t wc = { cfg, rpt, category };
    cfusa_walk_sources(dir, ext_union, n_ext_union, line_walk_file_cb, &wc);
    return rpt->count - before;
}

int cfusa_engine_run_all(const char *dir, const cfusa_config_t *cfg,
                          cfusa_report_t *rpt)
{
    int total = 0;
    for (int i = 0; i < g_rule_count; i++) {
        if (!cfusa_config_is_rule_disabled(cfg, g_rules[i]->id))
            total += g_rules[i]->run(dir, cfg, rpt);
    }
    total += cfusa_engine_run_line_rules(NULL, dir, cfg, rpt);
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
    total += cfusa_engine_run_line_rules(category, dir, cfg, rpt);
    return total;
}
