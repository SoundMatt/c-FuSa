/*
 * cfusa safety-case — GSN (Goal Structuring Notation) safety-case argument,
 * per the GSN Community Standard (Assurance Case Working Group, v3, 2021),
 * x-FuSa spec §9.2.
 *
 * `--format json` writes safety-case.json: nodes[]/edges[]/completeness per
 * the six real GSN node types (goal/strategy/solution/context/assumption/
 * justification). A `solution` node only cites `evidence` for a file that
 * actually exists in the project — a claimed-but-absent evidence file is
 * worse than an honestly-missing solution (x-FuSa spec §9.2), and a goal
 * with no supporting chain is counted in `completeness.undeveloped` rather
 * than silently omitted.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/qualitybar.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

//cfusa:req REQ-SC001 REQ-SC002 REQ-SC003

typedef struct {
    const char *id, *type, *text, *evidence; /* evidence: NULL when not a solution */
    int has_evidence_file; /* only meaningful for type "solution" */
} gsn_node_t;

typedef struct { const char *from, *to, *type; } gsn_edge_t;

#define MAX_NODES 16
#define MAX_EDGES 16

int cmd_safety_case(int argc, char **argv)
{
    const char *dir      = ".";
    const char *output   = NULL;
    const char *fmt_s    = NULL; /* NULL -> markdown (legacy default output name) */
    const char *standard = NULL;
    const char *attest   = NULL;
    int gsn_only = 0, strict = 0, require_attestation = 0;

    static const struct option long_opts[] = {
        {"dir",                required_argument, NULL, 'd'},
        {"output",              required_argument, NULL, 'o'},
        {"format",              required_argument, NULL, 'f'},
        {"standard",            required_argument, NULL, 'S'},
        {"gsn",                 no_argument,       NULL, 'g'},
        {"strict",              no_argument,       NULL, 's'},
        {"require-attestation", no_argument,       NULL, 'A'},
        {"attest",              required_argument, NULL, 'T'},
        {"help",                no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:f:S:gsAT:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg; break;
        case 'o': output   = optarg; break;
        case 'f': fmt_s    = optarg; break;
        case 'S': standard = optarg; break;
        case 'g': gsn_only = 1;     break;
        case 's': strict = 1;      break;
        case 'A': require_attestation = 1; break;
        case 'T': attest = optarg; break;
        case 'h':
            printf("Usage: cfusa safety-case [--dir <path>] [--output safety-case.md]\n"
                   "                          [--format md|json] [--gsn]\n"
                   "                          [--standard iso26262|do178c|iec61508|iso21434|unece-r155]\n"
                   "                          [--strict] [--require-attestation] [--attest <reviewer>]\n\n"
                   "Generates a GSN safety case (GSN Community Standard v3).\n"
                   "--format json writes safety-case.json (nodes/edges/completeness).\n"
                   "Default (no --format) writes the markdown safety-case + evidence index.\n");
            return 0;
        default: return 2;
        }
    }
    if (strict) require_attestation = 1;

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    if (!standard) standard = cfg.standards_count ? cfg.standards[0] : "iso26262";

    char ts[32]; cfusa_timestamp_now(ts);

    /* Evidence files this safety case can cite — only ever cited when they
     * actually exist (x-FuSa spec §9.2 "real referents only"). */
    struct { const char *name; int present; } ev_hara = {"hara.md", 0},
        ev_check = {"cfusa-self-check.json", 0}, ev_fmea = {"fmea.json", 0},
        ev_tara = {"tara.json", 0}, ev_qualify = {"qualify-report.json", 0},
        ev_sci = {"sci.json", 0};
    struct { const char *name; int *present; } evs[] = {
        {ev_hara.name, &ev_hara.present}, {ev_check.name, &ev_check.present},
        {ev_fmea.name, &ev_fmea.present}, {ev_tara.name, &ev_tara.present},
        {ev_qualify.name, &ev_qualify.present}, {ev_sci.name, &ev_sci.present},
    };
    for (size_t i = 0; i < sizeof(evs)/sizeof(evs[0]); i++) {
        char p[512]; cfusa_path_join(p, sizeof(p), dir, evs[i].name);
        *evs[i].present = cfusa_file_exists(p);
    }

    char g1_text[384], c1_text[256], g11_text[320], g12_text[320], a1_text[256];
    snprintf(g1_text, sizeof(g1_text),
        "%s v%s has no unmitigated hazard from .fusa-hara.json and no unresolved "
        "ERROR finding from `cfusa check` at the %s analysis boundary",
        cfg.project, cfg.version, standard);
    snprintf(c1_text, sizeof(c1_text),
        "Scope: %s source under \"%s\", analyzed against %s by c-FuSa v%s",
        cfg.project, dir, standard, CFUSA_VERSION_STRING);
    snprintf(g11_text, sizeof(g11_text),
        "Every hazard recorded in .fusa-hara.json is eliminated or controlled to its "
        "assigned ASIL (ISO 26262-3 Clause 6)");
    snprintf(g12_text, sizeof(g12_text),
        "The %s development process gives justified confidence: static analysis, FMEA/TARA, "
        "and tool qualification evidence are current", cfg.project);
    snprintf(a1_text, sizeof(a1_text),
        "The underlying hardware/platform on which %s runs meets its own safety requirements "
        "independently of this software safety case", cfg.project);

    gsn_node_t nodes[MAX_NODES];
    int nn = 0;
    nodes[nn++] = (gsn_node_t){"G1",  "goal",       g1_text,  NULL, 0};
    nodes[nn++] = (gsn_node_t){"St1", "strategy",   "Argue over hazard elimination and process confidence separately", NULL, 0};
    nodes[nn++] = (gsn_node_t){"C1",  "context",    c1_text,  NULL, 0};
    nodes[nn++] = (gsn_node_t){"A1",  "assumption", a1_text,  NULL, 0};
    nodes[nn++] = (gsn_node_t){"G1.1","goal",       g11_text, NULL, 0};
    nodes[nn++] = (gsn_node_t){"G1.2","goal",       g12_text, NULL, 0};
    if (ev_hara.present)
        nodes[nn++] = (gsn_node_t){"Sn1", "solution", "Hazard analysis and risk assessment", "hara.md", 1};
    if (ev_check.present)
        nodes[nn++] = (gsn_node_t){"Sn2", "solution", "Static analysis / lint / cyber self-check results", "cfusa-self-check.json", 1};
    if (ev_fmea.present)
        nodes[nn++] = (gsn_node_t){"Sn3", "solution", "Design FMEA", "fmea.json", 1};
    if (ev_tara.present)
        nodes[nn++] = (gsn_node_t){"Sn4", "solution", "Threat analysis and risk assessment", "tara.json", 1};
    if (ev_qualify.present)
        nodes[nn++] = (gsn_node_t){"Sn5", "solution", "Tool qualification record", "qualify-report.json", 1};

    gsn_edge_t edges[MAX_EDGES];
    int ne = 0;
    edges[ne++] = (gsn_edge_t){"G1", "St1", "supportedBy"};
    edges[ne++] = (gsn_edge_t){"G1", "C1", "inContextOf"};
    edges[ne++] = (gsn_edge_t){"St1", "A1", "inContextOf"};
    edges[ne++] = (gsn_edge_t){"St1", "G1.1", "supportedBy"};
    edges[ne++] = (gsn_edge_t){"St1", "G1.2", "supportedBy"};
    if (ev_hara.present)    edges[ne++] = (gsn_edge_t){"G1.1", "Sn1", "supportedBy"};
    if (ev_check.present)   edges[ne++] = (gsn_edge_t){"G1.2", "Sn2", "supportedBy"};
    if (ev_fmea.present)    edges[ne++] = (gsn_edge_t){"G1.2", "Sn3", "supportedBy"};
    if (ev_tara.present)    edges[ne++] = (gsn_edge_t){"G1.2", "Sn4", "supportedBy"};
    if (ev_qualify.present) edges[ne++] = (gsn_edge_t){"G1.2", "Sn5", "supportedBy"};

    int total_goals = 0, goals_with_evidence = 0, undeveloped = 0;
    for (int i = 0; i < nn; i++) {
        if (strcmp(nodes[i].type, "goal") != 0) continue;
        total_goals++;
        int has_child = 0, has_solution = 0;
        for (int k = 0; k < ne; k++) {
            if (strcmp(edges[k].from, nodes[i].id) != 0) continue;
            if (strcmp(edges[k].type, "supportedBy") != 0) continue;
            has_child = 1;
            for (int j = 0; j < nn; j++)
                if (strcmp(nodes[j].id, edges[k].to) == 0 && strcmp(nodes[j].type, "solution") == 0)
                    has_solution = 1;
        }
        if (has_solution) goals_with_evidence++;
        if (!has_child) undeveloped++;
    }

    /* ---- canonical content hash + quality-bar scan ---- */
    char canonical[8192];
    size_t off = 0;
    off += (size_t)snprintf(canonical + off, sizeof(canonical) - off, "{\"edges\":[");
    for (int i = 0; i < ne; i++)
        off += (size_t)snprintf(canonical + off, off < sizeof(canonical) ? sizeof(canonical) - off : 0,
            "%s{\"from\":\"%s\",\"to\":\"%s\",\"type\":\"%s\"}",
            i ? "," : "", edges[i].from, edges[i].to, edges[i].type);
    off += (size_t)snprintf(canonical + off, off < sizeof(canonical) ? sizeof(canonical) - off : 0, "],\"nodes\":[");
    for (int i = 0; i < nn; i++) {
        char esc[512];
        cfusa_str_escape_json(nodes[i].text, esc, sizeof(esc));
        if (nodes[i].evidence)
            off += (size_t)snprintf(canonical + off, off < sizeof(canonical) ? sizeof(canonical) - off : 0,
                "%s{\"evidence\":\"%s\",\"id\":\"%s\",\"text\":\"%s\",\"type\":\"%s\"}",
                i ? "," : "", nodes[i].evidence, nodes[i].id, esc, nodes[i].type);
        else
            off += (size_t)snprintf(canonical + off, off < sizeof(canonical) ? sizeof(canonical) - off : 0,
                "%s{\"id\":\"%s\",\"text\":\"%s\",\"type\":\"%s\"}",
                i ? "," : "", nodes[i].id, esc, nodes[i].type);
    }
    off += (size_t)snprintf(canonical + off, off < sizeof(canonical) ? sizeof(canonical) - off : 0, "]}");
    if (off >= sizeof(canonical)) off = sizeof(canonical) - 1;

    char fresh_hash[80];
    cfusa_qb_content_hash(canonical, off, fresh_hash);

    char existing_path[512];
    cfusa_path_join(existing_path, sizeof(existing_path), dir, "safety-case.json");
    size_t existing_len = 0;
    char *existing_json = cfusa_read_file(existing_path, &existing_len);
    cfusa_attestation_t attestation;
    if (existing_json) cfusa_qb_attestation_read(existing_json, existing_len, &attestation);
    else memset(&attestation, 0, sizeof(attestation));
    free(existing_json);

    if (attest) {
        attestation.present = 1;
        strncpy(attestation.status, "reviewed", sizeof(attestation.status) - 1);
        strncpy(attestation.implementation_author, "auto", sizeof(attestation.implementation_author) - 1);
        strncpy(attestation.independent_reviewer, attest, sizeof(attestation.independent_reviewer) - 1);
        strncpy(attestation.reviewed_at, ts, sizeof(attestation.reviewed_at) - 1);
        strncpy(attestation.content_hash, fresh_hash, sizeof(attestation.content_hash) - 1);
    }

    const char *node_texts[MAX_NODES];
    for (int i = 0; i < nn; i++) node_texts[i] = nodes[i].text;
    int rule_a_hits = 0;
    for (int i = 0; i < nn; i++) if (cfusa_qb_is_stub_text(nodes[i].text)) rule_a_hits++;
    int rule_a_disposed = rule_a_hits > 0 && cfusa_qb_rule_disposed(dir, CFUSA_QB_RULE_A);
    if (rule_a_hits > 0)
        fprintf(stderr, "cfusa safety-case: %s: %d node(s) with placeholder-looking text%s\n",
                CFUSA_QB_RULE_A, rule_a_hits, rule_a_disposed ? " (disposed)" : "");
    int rule_b = cfusa_qb_rule_b_flagged(node_texts, nn);
    int reviewed = 0;
    if (rule_b) {
        reviewed = cfusa_qb_attestation_valid(&attestation, fresh_hash);
        fprintf(stderr, "cfusa safety-case: %s: node text shows low distinct-value ratio%s\n",
                CFUSA_QB_RULE_B, reviewed ? " (suppressed by a valid attestation)" : "");
    }
    int qb_gate = (rule_a_hits > 0 && !rule_a_disposed) ? 1
                : (require_attestation && rule_b && !reviewed) ? 1 : 0;

    /* ---- JSON output ---- */
    if (fmt_s && !strcmp(fmt_s, "json")) {
        char out_path[512];
        if (output) {
            if (output[0] == '/') strncpy(out_path, output, sizeof(out_path) - 1);
            else cfusa_path_join(out_path, sizeof(out_path), dir, output);
        } else {
            cfusa_path_join(out_path, sizeof(out_path), dir, "safety-case.json");
        }
        FILE *f = cfusa_fopen_write(out_path);
        if (!f) { perror(out_path); return 3; }

        fprintf(f,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"safety-case\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"project\": \"%s\",\n"
            "  \"standard\": \"%s\",\n"
            "  \"nodes\": [\n",
            ts, cfg.project, standard);
        for (int i = 0; i < nn; i++) {
            char esc[512];
            cfusa_str_escape_json(nodes[i].text, esc, sizeof(esc));
            if (nodes[i].evidence)
                fprintf(f, "    {\"id\": \"%s\", \"type\": \"%s\", \"text\": \"%s\", \"evidence\": \"%s\"}%s\n",
                        nodes[i].id, nodes[i].type, esc, nodes[i].evidence, (i < nn - 1) ? "," : "");
            else
                fprintf(f, "    {\"id\": \"%s\", \"type\": \"%s\", \"text\": \"%s\"}%s\n",
                        nodes[i].id, nodes[i].type, esc, (i < nn - 1) ? "," : "");
        }
        fprintf(f, "  ],\n  \"edges\": [\n");
        for (int i = 0; i < ne; i++)
            fprintf(f, "    {\"from\": \"%s\", \"to\": \"%s\", \"type\": \"%s\"}%s\n",
                    edges[i].from, edges[i].to, edges[i].type, (i < ne - 1) ? "," : "");
        fprintf(f, "  ],\n  \"completeness\": {\n"
                   "    \"totalGoals\": %d, \"goalsWithEvidence\": %d, \"undeveloped\": %d\n"
                   "  }",
                total_goals, goals_with_evidence, undeveloped);
        /* x-FuSa spec §1.6.2 MUST (carry-forward across regeneration): carry
         * a prior attestation forward verbatim whenever one was read back,
         * not only when it is still hash-valid — see cmd_fmea.c's
         * WRITE_ATTESTATION for the full rationale. */
        if (attestation.present) {
            fprintf(f,
                ",\n  \"attestation\": {\n"
                "    \"status\": \"%s\",\n"
                "    \"implementationAuthor\": \"%s\",\n"
                "    \"independentReviewer\": \"%s\",\n"
                "    \"reviewedAt\": \"%s\",\n"
                "    \"contentHash\": \"%s\"\n"
                "  }\n",
                attestation.status[0] ? attestation.status : "heuristic",
                attestation.implementation_author, attestation.independent_reviewer,
                attestation.reviewed_at, attestation.content_hash);
        } else {
            fprintf(f, "\n");
        }
        fprintf(f, "}\n");
        fclose(f);
        printf("Safety case written to %s\n", out_path);
        return qb_gate;
    }

    /* ---- Markdown output (default, legacy filename) ---- */
    char out_path[512];
    const char *out_name = output ? output : "safety-case.md";
    if (out_name[0]=='/') strncpy(out_path,out_name,sizeof(out_path)-1);
    else cfusa_path_join(out_path,sizeof(out_path),dir,out_name);

    FILE *f = cfusa_fopen_write(out_path);
    if (!f) { perror(out_path); return 3; }

    fprintf(f, "# Safety Case — %s v%s\n\n", cfg.project, cfg.version);
    fprintf(f, "**Standard:** %s  |  **Generated:** %s\n\n---\n\n", standard, ts);
    for (int i = 0; i < nn; i++) {
        fprintf(f, "## %s — %s\n\n> %s\n\n", nodes[i].id, nodes[i].type, nodes[i].text);
        if (nodes[i].evidence)
            fprintf(f, "Evidence: `%s`\n\n", nodes[i].evidence);
    }
    fprintf(f, "---\n\n## Argument Structure\n\n| From | To | Relation |\n|---|---|---|\n");
    for (int i = 0; i < ne; i++)
        fprintf(f, "| %s | %s | %s |\n", edges[i].from, edges[i].to, edges[i].type);
    fprintf(f, "\n_Completeness: %d goal(s), %d with cited evidence, %d undeveloped._\n",
            total_goals, goals_with_evidence, undeveloped);

    if (!gsn_only) {
        fprintf(f, "\n---\n\n## Evidence Index\n\n| File | Present | SHA-256 |\n|---|---|---|\n");

        static const char * const evidence_files[] = {
            "hara.md","safety-plan.md","tara.md","fmea.md",
            "test-evidence.md","sas.md",".fusa.json",NULL
        };
        static const char * const cyber_evidence[] = {
            "tara.json","vuln-report.json","cfusa-self-check.json",
            "cyber-plan.json","provenance.json",NULL
        };
        const char * const *extra = NULL;
        if (!strcmp(standard,"iso21434") || !strcmp(standard,"unece-r155"))
            extra = cyber_evidence;

        for (int i=0; evidence_files[i]; i++) {
            char ep[512];
            cfusa_path_join(ep, sizeof(ep), dir, evidence_files[i]);
            if (cfusa_file_exists(ep)) {
                char hex[65];
                cfusa_sha256_file(ep, hex);
                fprintf(f,"| %s | present | `%s` |\n", evidence_files[i], hex);
            } else {
                fprintf(f,"| %s | absent | — |\n", evidence_files[i]);
            }
        }
        if (extra) {
            for (int i=0; extra[i]; i++) {
                char ep[512];
                cfusa_path_join(ep, sizeof(ep), dir, extra[i]);
                if (cfusa_file_exists(ep)) {
                    char hex[65];
                    cfusa_sha256_file(ep, hex);
                    fprintf(f,"| %s | present | `%s` |\n", extra[i], hex);
                } else {
                    fprintf(f,"| %s | absent | — |\n", extra[i]);
                }
            }
        }
    }

    fclose(f);
    printf("Safety case written to %s\n", out_path);
    return qb_gate;
}
