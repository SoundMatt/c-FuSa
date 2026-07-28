/*
 * cfusa "quality bar" — x-FuSa spec §1.6/§1.6.1/§1.6.2 implementation.
 * See include/cfusa/qualitybar.h for the contract.
 */
#include "cfusa/qualitybar.h"
#include "cfusa/utils.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Rule A: placeholder-text deny-list (x-FuSa spec §1.6.1 rule A) ---- */

static int qb_ci_contains(const char *hay, const char *needle)
{
    size_t hn = strlen(hay), nn = strlen(needle);
    if (nn == 0 || nn > hn) return 0;
    for (size_t i = 0; i + nn <= hn; i++) {
        size_t j = 0;
        for (; j < nn; j++)
            if (tolower((unsigned char)hay[i + j]) != tolower((unsigned char)needle[j]))
                break;
        if (j == nn) return 1;
    }
    return 0;
}

/* Bracket-wrapped instructional text: \[[A-Za-z][^\]]*\] */
static int qb_has_bracket_placeholder(const char *s)
{
    const char *p = s;
    while ((p = strchr(p, '[')) != NULL) {
        const char *q = p + 1;
        if (*q && isalpha((unsigned char)*q)) {
            const char *close = strchr(q, ']');
            if (close && close > q) return 1;
        }
        p++;
    }
    return 0;
}

int cfusa_qb_is_stub_text(const char *text)
{
    if (!text || !*text) return 0;

    static const char * const deny[] = {
        "replace with", "example hazard", "tbd", "lorem ipsum", "fill in", NULL
    };
    for (int i = 0; deny[i]; i++)
        if (qb_ci_contains(text, deny[i])) return 1;

    return qb_has_bracket_placeholder(text);
}

/* ---- Rule B: distinct-value-ratio (x-FuSa spec §1.6.1 rule B) ---- */

int cfusa_qb_rule_b_flagged(const char * const *values, int n)
{
    if (n < 10) return 0;

    /* O(n^2) distinct count. These artifacts run at most a few hundred
     * entries per project, so a hash set is not needed for correctness or
     * for practical runtime. */
    int distinct = 0;
    for (int i = 0; i < n; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++) {
            if (strcmp(values[i], values[j]) == 0) { dup = 1; break; }
        }
        if (!dup) distinct++;
    }
    double ratio = (double)distinct / (double)n;
    return ratio < 0.1;
}

/* ---- Attestation (x-FuSa spec §1.6.2) ---- */

static void qb_extract_string_field(const char *block, const char *key,
                                     char *out, size_t out_sz)
{
    out[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *fp = strstr(block, pat);
    if (!fp) return;
    fp += strlen(pat);
    while (*fp == ' ' || *fp == '\t' || *fp == '\n') fp++;
    if (*fp != '"') return;
    fp++;
    size_t k = 0;
    while (*fp && *fp != '"' && k < out_sz - 1) {
        if (*fp == '\\' && fp[1]) fp++;
        out[k++] = *fp++;
    }
    out[k] = '\0';
}

int cfusa_qb_attestation_read(const char *json, size_t len, cfusa_attestation_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!json || len == 0) return 0;

    const char *key = strstr(json, "\"attestation\"");
    if (!key) return 0;
    const char *brace = strchr(key, '{');
    if (!brace) return 0;

    /* Find the matching close brace, tracking string state so a literal
     * '{'/'}' inside a quoted value doesn't miscount depth. */
    int depth = 0;
    int in_str = 0;
    const char *p = brace;
    const char *end = NULL;
    const char *doc_end = json + len;
    for (; p < doc_end && *p; p++) {
        if (in_str) {
            if (*p == '\\') { p++; continue; }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) { end = p; break; } }
    }
    if (!end) return 0;

    size_t blocklen = (size_t)(end - brace) + 1;
    char *block = malloc(blocklen + 1);
    if (!block) return 0;
    memcpy(block, brace, blocklen);
    block[blocklen] = '\0';

    qb_extract_string_field(block, "status", out->status, sizeof(out->status));
    qb_extract_string_field(block, "implementationAuthor",
                             out->implementation_author, sizeof(out->implementation_author));
    qb_extract_string_field(block, "independentReviewer",
                             out->independent_reviewer, sizeof(out->independent_reviewer));
    qb_extract_string_field(block, "reviewedAt", out->reviewed_at, sizeof(out->reviewed_at));
    qb_extract_string_field(block, "contentHash", out->content_hash, sizeof(out->content_hash));

    free(block);
    out->present = 1;
    return 1;
}

static int qb_str_ieq_trim(const char *a, const char *b)
{
    while (isspace((unsigned char)*a)) a++;
    while (isspace((unsigned char)*b)) b++;
    size_t la = strlen(a), lb = strlen(b);
    while (la && isspace((unsigned char)a[la - 1])) la--;
    while (lb && isspace((unsigned char)b[lb - 1])) lb--;
    if (la != lb) return 0;
    for (size_t i = 0; i < la; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    return 1;
}

int cfusa_qb_attestation_valid(const cfusa_attestation_t *att, const char *fresh_hash)
{
    if (!att || !att->present) return 0;                    /* absent -> heuristic (fail-safe) */
    if (strcmp(att->status, "reviewed") != 0) return 0;      /* anything else -> heuristic */
    if (!att->independent_reviewer[0]) return 0;             /* MUST when status: reviewed */
    /* Same-identity self-attestation MUST downgrade to heuristic. An empty
     * implementationAuthor is not treated as "same identity" — it simply
     * means the producer didn't record one (e.g. a heuristic generator that
     * omitted it), which is a documentation gap, not a security bypass —
     * but is nonetheless untrustworthy without an author to differ from. */
    if (!att->implementation_author[0]) return 0;
    if (qb_str_ieq_trim(att->independent_reviewer, att->implementation_author)) return 0;
    if (!att->content_hash[0] || !fresh_hash || !fresh_hash[0]) return 0;
    if (strcmp(att->content_hash, fresh_hash) != 0) return 0; /* stale -> heuristic */
    return 1;
}

/* ---- Rule-level disposition lookup ---- */

int cfusa_qb_rule_disposed(const char *dir, const char *rule_id)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, ".fusa-dispositions.json");
    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        cfusa_path_join(path, sizeof(path), dir, ".cfusa-dispositions.json");
        content = cfusa_read_file(path, &len);
    }
    if (!content) return 0;

    int disposed = 0;
    char *p = content;
    while ((p = strstr(p, "\"rule\":")) != NULL) {
        char rule[32] = "";
        sscanf(p, "\"rule\":\"%31[^\"]", rule);
        if (strcmp(rule, rule_id) == 0) { disposed = 1; break; }
        p += 7;
    }
    free(content);
    return disposed;
}

/* ---- Canonical content hash ---- */

void cfusa_qb_content_hash(const char *canonical_json, size_t len, char hash_out[80])
{
    char hex[65];
    cfusa_sha256_buf((const unsigned char *)canonical_json, len, hex);
    snprintf(hash_out, 80, "sha256:%s", hex);
}
