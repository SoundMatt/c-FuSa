#include "cfusa/lex.h"

void cfusa_lex_reset(cfusa_lex_state_t *st)
{
    st->in_block_comment = 0;
}

//cfusa:req REQ-UTIL020
void cfusa_lex_strip_line(cfusa_lex_state_t *st, const char *line,
                           char *out, size_t out_sz)
{
    if (out_sz == 0) return;

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
