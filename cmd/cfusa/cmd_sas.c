#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/qualitybar.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

//cfusa:req REQ-SAS001 REQ-SAS002 REQ-SAS-PREP001 REQ-SAS-STDOUT001

/* Software Accomplishment Summary (DO-178C §11.20), x-FuSa spec §9.3.
 *
 * `checklist[].present` reflects a real check for an expected evidence
 * file under --dir, rather than a hardcoded "pending" regardless of
 * project state — an empty `evidence` string is an honest "no single
 * file produces this evidence" rather than a fabricated reference. */

typedef struct {
    const char *id;
    const char *description;
    const char *evidence_type;
    const char *evidence_file; /* "" when no single file corresponds */
} sas_item_t;

static const sas_item_t SAS_ITEMS[] = {
    {"SAS-01", "System overview and SW functions",                      "Document",                    "README.md"},
    {"SAS-02", "Software level (DAL)",                                  "Document",                    ".fusa.json"},
    {"SAS-03", "SW development environment",                            "Tool qualification records",  "qualify-report.json"},
    {"SAS-04", "SW development process summary",                        "Process evidence",            ""},
    {"SAS-05", "SW verification process summary",                       "Test evidence",                "cfusa-self-check.json"},
    {"SAS-06", "SW configuration management process summary",           "CM records",                   "sci.json"},
    {"SAS-07", "SW quality assurance process summary",                  "QA records",                   ""},
    {"SAS-08", "Compliance statement for each SW life cycle data item",  "Traceability matrix",          ""},
    {"SAS-09", "Problem reports status",                                 "PR log",                       ""},
    {"SAS-10", "Changes and their classification",                       "Change log",                   "CHANGELOG.md"},
    {"SAS-11", "Deviations from plans/standards",                        "Deviation records",            ""},
    {"SAS-12", "Unresolved anomalies with justification",                "Anomaly log",                  ""},
    {"SAS-13", "SW verification results",                                "Test reports",                 "cfusa-self-check.json"},
    {"SAS-14", "Structural coverage results",                            "Coverage report",              "coverage.info"},
    {"SAS-15", "Additional considerations (partitioning, etc.)",         "Analysis report",              ""},
    {"SAS-16", "Summary of test environment qualification",              "Tool qual record",             "qualify-report.json"},
    {"SAS-17", "PSAC compliance",                                        "PSAC cross-reference",         ""},
    {"SAS-18", "PHAC data (if applicable)",                              "PHAC document",                ""},
    {"SAS-19", "COTS components used",                                   "COTS qualification data",     ""},
    {"SAS-20", "SW configuration index",                                 "SCI (cfusa sci)",              "sci.json"},
    {NULL, NULL, NULL, NULL}
};

static int item_present(const char *dir, const sas_item_t *it)
{
    if (!it->evidence_file[0]) return 0;
    char p[512]; cfusa_path_join(p, sizeof(p), dir, it->evidence_file);
    return cfusa_file_exists(p);
}

static void render_sas_markdown(FILE *f, const char *dir, const cfusa_config_t *cfg,
                                 const char *dal, const char *ts, const char *approver,
                                 int present_count, int total)
{
    fprintf(f,"# Software Accomplishment Summary (SAS)\n\n"
            "**Project:** %s v%s  |  **DAL:** %s  |  **Generated:** %s  |  **Standard:** DO-178C §11.20\n\n"
            "| ID | Description | Evidence | Present |\n|---|---|---|---|\n",
            cfg->project, cfg->version, dal, ts);
    for (int i=0;SAS_ITEMS[i].id;i++) {
        int present = item_present(dir, &SAS_ITEMS[i]);
        fprintf(f,"| %s | %s | %s | %s |\n",
                SAS_ITEMS[i].id, SAS_ITEMS[i].description,
                SAS_ITEMS[i].evidence_file[0] ? SAS_ITEMS[i].evidence_file : "(none)",
                present ? "yes" : "no");
    }
    fprintf(f,"\n---\n_%d/%d present_  \n_Prepared by: %s_\n", present_count, total, approver);
}

static size_t sas_canonical_content(const char *dir, char *buf, size_t bufsz)
{
    size_t off = 0;
    off += (size_t)snprintf(buf + off, bufsz - off, "{\"checklist\":[");
    for (int i = 0; SAS_ITEMS[i].id; i++) {
        int present = item_present(dir, &SAS_ITEMS[i]);
        off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0,
            "%s{\"clause\":\"11.20\",\"evidence\":\"%s\",\"item\":\"%s\",\"present\":%s}",
            i ? "," : "", SAS_ITEMS[i].evidence_file, SAS_ITEMS[i].description,
            present ? "true" : "false");
    }
    off += (size_t)snprintf(buf + off, off < bufsz ? bufsz - off : 0, "]}");
    return off;
}

int cmd_sas(int argc, char **argv)
{
    const char *dir         = ".";
    const char *output      = NULL;
    const char *fmt_s       = "md";
    const char *dal         = "DAL-B";
    const char *prepared_by = NULL;
    const char *attest      = NULL;
    int strict = 0, require_attestation = 0;

    static const struct option long_opts[] = {
        {"dir",                 required_argument, NULL, 'd'},
        {"output",              required_argument, NULL, 'o'},
        {"format",              required_argument, NULL, 'f'},
        {"dal",                 required_argument, NULL, 'D'},
        {"prepared-by",         required_argument, NULL, 'P'},
        {"strict",              no_argument,       NULL, 'S'},
        {"require-attestation", no_argument,       NULL, 'A'},
        {"attest",              required_argument, NULL, 'T'},
        {"help",                no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:o:f:D:P:SAT:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir         = optarg; break;
        case 'o': output      = optarg; break;
        case 'f': fmt_s       = optarg; break;
        case 'D': dal         = optarg; break;
        case 'P': prepared_by = optarg; break;
        case 'S': strict = 1; break;
        case 'A': require_attestation = 1; break;
        case 'T': attest = optarg; break;
        case 'h':
            printf("Usage: cfusa sas [--dir <path>] [--output <file>]\n"
                   "                 [--format md|text|json] [--dal DAL-A|B|C|D]\n"
                   "                 [--prepared-by <name>]\n"
                   "                 [--strict] [--require-attestation] [--attest <reviewer>]\n\n"
                   "Generates a Software Accomplishment Summary (DO-178C §11.20).\n"
                   "Use --output - to write to stdout.\n"
                   "A tool MUST also write sas.md (the human-readable companion); this command\n"
                   "does that whenever --format md/text is selected, and on request via --output.\n");
            return 0;
        default: return 2;
        }
    }
    if (strict) require_attestation = 1;

    /* Default --output path depends on --format when not given explicitly:
     * "sas.json" for --format json, "sas.md" for md/text/default — a single
     * hardcoded "sas.md" default regardless of format would (and previously
     * did) write JSON content into a file literally named sas.md, and fool
     * the "did we already write sas.md?" companion check below into
     * skipping the real Markdown companion (x-FuSa spec §9.3 MUST). */
    if (!output)
        output = !strcmp(fmt_s, "json") ? "sas.json" : "sas.md";

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char ts[32]; cfusa_timestamp_now(ts);
    const char *approver = prepared_by ? prepared_by : "(unspecified)";

    /* ---- quality bar + attestation ---- */
    char canonical[8192];
    size_t clen = sas_canonical_content(dir, canonical, sizeof(canonical));
    if (clen >= sizeof(canonical)) clen = sizeof(canonical) - 1;
    char fresh_hash[80];
    cfusa_qb_content_hash(canonical, clen, fresh_hash);

    char existing_path[512];
    cfusa_path_join(existing_path, sizeof(existing_path), dir, "sas.json");
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

    const char *item_texts[64];
    int nitems = 0;
    for (int i = 0; SAS_ITEMS[i].id; i++) item_texts[nitems++] = SAS_ITEMS[i].description;
    int rule_a_hits = 0;
    for (int i = 0; i < nitems; i++) if (cfusa_qb_is_stub_text(item_texts[i])) rule_a_hits++;
    int rule_a_disposed = rule_a_hits > 0 && cfusa_qb_rule_disposed(dir, CFUSA_QB_RULE_A);
    if (rule_a_hits > 0)
        fprintf(stderr, "cfusa sas: %s: %d checklist item(s) with placeholder-looking text%s\n",
                CFUSA_QB_RULE_A, rule_a_hits, rule_a_disposed ? " (disposed)" : "");
    int rule_b = cfusa_qb_rule_b_flagged(item_texts, nitems);
    int reviewed = 0;
    if (rule_b) {
        reviewed = cfusa_qb_attestation_valid(&attestation, fresh_hash);
        fprintf(stderr, "cfusa sas: %s: checklist item text shows low distinct-value ratio%s\n",
                CFUSA_QB_RULE_B, reviewed ? " (suppressed by a valid attestation)" : "");
    }
    int qb_gate = (rule_a_hits > 0 && !rule_a_disposed) ? 1
                : (require_attestation && rule_b && !reviewed) ? 1 : 0;

    int total = 0, present_count = 0;
    for (int i = 0; SAS_ITEMS[i].id; i++) {
        total++;
        if (item_present(dir, &SAS_ITEMS[i])) present_count++;
    }

    /* "--output without --format" is textually ambiguous here (unlike
     * qualify's --output-implies-json convention, sas's default format is
     * md, and md is also this tool's MUST-have human-readable companion —
     * see §9.3), so --format is honored independently of --output. */

    /* "--output -" → stdout; otherwise resolve path relative to --dir */
    FILE *f;
    int to_stdout = (output && output[0] == '-' && output[1] == '\0');
    char out_path[512];
    if (to_stdout) {
        f = stdout;
    } else {
        if (output[0] == '/') strncpy(out_path, output, sizeof(out_path) - 1);
        else cfusa_path_join(out_path, sizeof(out_path), dir, output);
        f = cfusa_fopen_write(out_path);
        if (!f) { perror(out_path); return 3; }
    }

    if (!strcmp(fmt_s,"json")) {
        fprintf(f,
                "{\n"
                "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
                "  \"kind\": \"sas\",\n"
                "  \"tool\": \"c-FuSa\",\n"
                "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
                "  \"language\": \"c\",\n"
                "  \"generatedAt\": \"%s\",\n"
                "  \"project\": \"%s\",\n"
                "  \"version\": \"%s\",\n"
                "  \"dal\": \"%s\",\n"
                "  \"preparedBy\": \"%s\",\n"
                "  \"checklist\": [\n",
                ts, cfg.project, cfg.version, dal, prepared_by ? prepared_by : "");
        for (int i=0; SAS_ITEMS[i].id; i++) {
            int present = item_present(dir, &SAS_ITEMS[i]);
            fprintf(f,"    {\"item\": \"%s\", \"clause\": \"11.20\", \"present\": %s, "
                    "\"evidence\": \"%s\"}%s\n",
                    SAS_ITEMS[i].description, present ? "true" : "false",
                    SAS_ITEMS[i].evidence_file,
                    SAS_ITEMS[i+1].id ? "," : "");
        }
        fprintf(f,"  ],\n  \"summary\": {\"total\": %d, \"present\": %d}", total, present_count);
        /* x-FuSa spec §1.6.2 MUST (carry-forward across regeneration): a
         * prior attestation is carried forward onto the regenerated
         * document verbatim whenever one was read back, not only when it
         * is still hash-valid — staleness is then automatic (a consumer
         * recomputes contentHash and falls back to "heuristic" on
         * mismatch), so gating *emission* on attestation_valid would
         * silently erase a real prior review the moment content changes. */
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
    } else if (!strcmp(fmt_s,"text")) {
        fprintf(f,"Software Accomplishment Summary (SAS)\n"
                "Project: %s v%s   DAL: %s   Generated: %s\nStandard: DO-178C §11.20\n"
                "Prepared by: %s\n\n",
                cfg.project, cfg.version, dal, ts, approver);
        for (int i=0;SAS_ITEMS[i].id;i++) {
            int present = item_present(dir, &SAS_ITEMS[i]);
            fprintf(f,"%-8s [%s] %-50s  Evidence: %s\n",
                    SAS_ITEMS[i].id, present ? "x" : " ", SAS_ITEMS[i].description,
                    SAS_ITEMS[i].evidence_file[0] ? SAS_ITEMS[i].evidence_file : "(none)");
        }
        fprintf(f, "\n%d/%d present\n", present_count, total);
    } else {
        /* Markdown default — this is c-FuSa's MUST-have human-readable
         * companion to sas.json (x-FuSa spec §9.3). */
        render_sas_markdown(f, dir, &cfg, dal, ts, approver, present_count, total);
    }

    if (!to_stdout) {
        fclose(f);
        printf("SAS written to %s\n", out_path);

        /* x-FuSa spec §9.3: "A tool MUST also write the human-readable
         * sas.md companion — sas.json is not a replacement for it." When
         * this invocation wrote something other than sas.md itself, make
         * sure the companion still gets produced alongside it. */
        int wrote_sas_md = (strcmp(out_path + (strlen(out_path) >= 7 ? strlen(out_path) - 7 : 0), "/sas.md") == 0) ||
                            (strcmp(out_path, "sas.md") == 0);
        if (!wrote_sas_md && strcmp(fmt_s, "md") != 0) {
            char companion_path[512];
            cfusa_path_join(companion_path, sizeof(companion_path), dir, "sas.md");
            FILE *cf = cfusa_fopen_write(companion_path);
            if (cf) {
                render_sas_markdown(cf, dir, &cfg, dal, ts, approver, present_count, total);
                fclose(cf);
                printf("SAS companion written to %s\n", companion_path);
            }
        }
    }
    return qb_gate;
}
