#include <string.h>
#include "cfusa/lex.h"

void cfusa_lex_reset(cfusa_lex_state_t *st)
{
    st->in_block_comment = 0;
    st->if_depth         = 0;
    st->disabled_at       = -1;
}

/* issue #205: returns 1 if `cond` (positioned right after "#if "/"#elif "
 * and any following whitespace) is a literal, unconditionally-false "0"
 * -- optionally wrapped in one layer of parens ("(0)") -- 0 otherwise.
 * Deliberately does not evaluate anything beyond this one literal shape;
 * any macro name, expression, or defined(...) is left alone (returns 0,
 * i.e. "not provably dead"). */
static int cond_is_literal_zero(const char *cond)
{
    while (*cond == ' ' || *cond == '\t') cond++;
    int paren = 0;
    if (*cond == '(') {
        cond++;
        paren = 1;
        while (*cond == ' ' || *cond == '\t') cond++;
    }
    if (*cond != '0') return 0;
    cond++;
    while (*cond == ' ' || *cond == '\t') cond++;
    if (paren) {
        if (*cond != ')') return 0;
        cond++;
        while (*cond == ' ' || *cond == '\t') cond++;
    }
    return *cond == '\0' || *cond == '\r' ||
           (cond[0] == '/' && (cond[1] == '/' || cond[1] == '*'));
}

/* Returns 1 if `p` (already positioned past the directive keyword) is at
 * a real token boundary -- whitespace, end of line, '(' (only relevant
 * for #if/#elif), or a trailing comment opener -- so e.g. "#ifdefined"
 * (not a real directive) never matches "#ifdef" by accident. */
static int at_directive_boundary(const char *p, int allow_paren)
{
    return *p == '\0' || *p == ' ' || *p == '\t' || *p == '\r' ||
           (allow_paren && *p == '(') ||
           (p[0] == '/' && (p[1] == '/' || p[1] == '*'));
}

/* issue #205: updates `st->if_depth`/`st->disabled_at` from a single
 * preprocessor directive line. Only ever called when NOT already inside
 * a block comment (a directive-looking line inside an unterminated
 * comment is comment text, not a real directive). */
static void if0_update(cfusa_lex_state_t *st, const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '#') return;
    p++;
    while (*p == ' ' || *p == '\t') p++;

    if (strncmp(p, "ifdef", 5) == 0 && at_directive_boundary(p + 5, 0)) {
        st->if_depth++;
        return;
    }
    if (strncmp(p, "ifndef", 6) == 0 && at_directive_boundary(p + 6, 0)) {
        st->if_depth++;
        return;
    }
    if (strncmp(p, "if", 2) == 0 && at_directive_boundary(p + 2, 1)) {
        st->if_depth++;
        if (st->disabled_at == -1 && cond_is_literal_zero(p + 2))
            st->disabled_at = st->if_depth;
        return;
    }
    if (strncmp(p, "elif", 4) == 0 && at_directive_boundary(p + 4, 1)) {
        if (st->disabled_at == st->if_depth) {
            if (!cond_is_literal_zero(p + 4))
                st->disabled_at = -1; /* unknown condition: scan it */
        }
        return;
    }
    if (strncmp(p, "else", 4) == 0 && at_directive_boundary(p + 4, 0)) {
        if (st->disabled_at == st->if_depth)
            st->disabled_at = -1; /* #else of a known-false #if 0 is taken */
        return;
    }
    if (strncmp(p, "endif", 5) == 0 && at_directive_boundary(p + 5, 0)) {
        if (st->if_depth > 0) st->if_depth--;
        if (st->disabled_at != -1 && st->if_depth < st->disabled_at)
            st->disabled_at = -1;
        return;
    }
}

//cfusa:req REQ-UTIL020
void cfusa_lex_strip_line(cfusa_lex_state_t *st, const char *line,
                           char *out, size_t out_sz)
{
    if (out_sz == 0) return;

    int was_disabled = (st->disabled_at != -1);
    if (!st->in_block_comment) if0_update(st, line);
    int now_disabled = (st->disabled_at != -1);

    if (was_disabled && now_disabled) {
        /* Strictly inside a dead #if 0 span, including any directive
         * line nested inside it -- blank unconditionally, the same
         * length-preserving contract as comment/string content. The
         * bracketing #if 0 / #else / #elif / #endif lines themselves
         * are NOT blanked (see the was_disabled/now_disabled mismatch
         * cases below, which fall through to normal stripping). */
        size_t oi = 0;
        for (const char *p = line; *p && oi < out_sz - 1; p++) out[oi++] = ' ';
        out[oi] = '\0';
        return;
    }

    size_t oi = 0;
    int in_str = 0; /* inside "..." -- does NOT persist across lines */
    int in_chr = 0; /* inside '...' -- does NOT persist across lines */
    const char *p = line;

    while (*p && oi < out_sz - 1) {
        if (st->in_block_comment) {
            if (p[0] == '*' && p[1] == '/') {
                st->in_block_comment = 0;
                out[oi++] = ' ';
                if (oi < out_sz - 1) out[oi++] = ' ';
                p += 2;
            } else {
                out[oi++] = ' ';
                p++;
            }
            continue;
        }

        if (in_str) {
            if (*p == '\\' && p[1]) {
                out[oi++] = ' ';
                p++;
                if (oi < out_sz - 1) out[oi++] = ' ';
                p++;
                continue;
            }
            if (*p == '"') {
                in_str = 0;
                out[oi++] = *p++;
                continue;
            }
            out[oi++] = ' ';
            p++;
            continue;
        }

        if (in_chr) {
            if (*p == '\\' && p[1]) {
                out[oi++] = ' ';
                p++;
                if (oi < out_sz - 1) out[oi++] = ' ';
                p++;
                continue;
            }
            if (*p == '\'') {
                in_chr = 0;
                out[oi++] = *p++;
                continue;
            }
            out[oi++] = ' ';
            p++;
            continue;
        }

        /* Not inside a comment or a string/char literal -- check for the
         * start of one before treating this as ordinary code. */
        if (p[0] == '/' && p[1] == '*') {
            st->in_block_comment = 1;
            out[oi++] = ' ';
            if (oi < out_sz - 1) out[oi++] = ' ';
            p += 2;
            continue;
        }
        if (p[0] == '/' && p[1] == '/') {
            /* Rest of the physical line is a line comment. */
            while (*p && oi < out_sz - 1) { out[oi++] = ' '; p++; }
            break;
        }
        if (*p == '"') {
            in_str = 1;
            out[oi++] = *p++;
            continue;
        }
        if (*p == '\'') {
            in_chr = 1;
            out[oi++] = *p++;
            continue;
        }

        out[oi++] = *p++;
    }

    out[oi] = '\0';
}
