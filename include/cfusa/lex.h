#ifndef CFUSA_LEX_H
#define CFUSA_LEX_H

#include <stddef.h>

/* ---- shared comment/string-literal-aware line stripping ----
 *
 * issue #203: in_block_comment/in_str tracking used to be hand-rolled
 * independently in at least half a dozen rules (l003_ctx_t, l004_ctx_t,
 * l006_ctx_t, coup_ctx_t, ...), added reactively each time an audit found
 * a comment/string false positive in one specific rule. Nearly every
 * false-positive bug fixed in the v0.6.1 sprint (#141-#182, #187) traced
 * back to this same root cause in different clothes. This header is the
 * one shared primitive every such rule should use instead.
 */

typedef struct {
    /* Persists across cfusa_lex_strip_line() calls within one file --
     * reset via cfusa_lex_reset() (or a zero-initializer) at the start of
     * each file, exactly like every ad hoc in_block_comment field this
     * consolidates did before. */
    int in_block_comment;

    /* issue #205: nesting depth of every #if/#ifdef/#ifndef directive
     * seen so far in this file (incremented on any of the three,
     * decremented on #endif) -- tracked unconditionally so a nested
     * directive inside an already-disabled #if 0 span still lands at
     * the right depth once the span's own #endif is reached. */
    int if_depth;

    /* The if_depth value of the #if 0 (or #elif 0) currently suppressing
     * content, or -1 when nothing is currently suppressed. Only a
     * LITERAL "0" condition is ever treated as unambiguously dead --
     * see cfusa_lex_strip_line()'s doc comment for what this
     * deliberately does NOT attempt. */
    int disabled_at;
} cfusa_lex_state_t;

/* Resets `st` for the start of a new file. Equivalent to
 * `cfusa_lex_state_t st = {0};` -- provided as a named call so callers
 * don't need to know the struct's fields, and so a future field added
 * here doesn't require every call site to be found and updated. */
void cfusa_lex_reset(cfusa_lex_state_t *st);

/* Writes a "code-only" view of `line` into `out` (size `out_sz`): every
 * character belonging to a "//"-style line comment, a block comment
 * (including continuation lines with no leading '*' -- a legal,
 * common C style that a "does this line START with '/' or '*'?" check
 * misses entirely), or the INTERIOR of a "..."/'...' literal is replaced
 * with a space, never deleted -- so column positions and token adjacency
 * are preserved exactly. This matters: a delete-based strip turns two
 * tokens separated only by an empty comment (e.g. `x`, then an empty
 * comment, then `y(`) into the incorrect glued-together `xy(`, a token
 * that was never adjacent in the source and could produce a false match
 * a space-preserving strip cannot. The opening/closing quote characters of
 * a string/char literal are themselves preserved (not blanked), so a
 * caller that still wants to see where a literal was still can.
 *
 * `st->in_block_comment` persists across calls within one file -- call
 * cfusa_lex_reset() (or zero-initialize `*st`) once at the start of each
 * file, then call this once per physical source line in order. String-
 * literal and char-literal state does NOT persist across lines (a C
 * string literal cannot span an unescaped newline), matching every prior
 * ad hoc implementation this consolidates.
 *
 * issue #205: a physical line entirely inside an unconditionally-
 * disabled `#if 0` ... `#endif` span (a common "commented out via the
 * preprocessor" idiom) is ALSO blanked, the same way comment/string
 * content is -- only a LITERAL "0" condition on `#if`/`#elif` is ever
 * treated as unambiguously dead; an `#else` (or `#elif` with any other
 * condition) following a disabling `#if 0` resumes normal scanning,
 * since that branch IS the one actually compiled. Any other `#if`/
 * `#ifdef`/`#ifndef` condition this can't evaluate is left alone
 * (scanned normally) -- this deliberately does NOT attempt general
 * conditional-compilation branch resolution, which needs real macro
 * definitions and is a different, much bigger problem; it only ever
 * suppresses content that is unambiguously, syntactically dead.
 *
 * `out` is always NUL-terminated. If `line` is longer than `out_sz - 1`
 * characters, the remainder is dropped, matching this codebase's existing
 * fixed-size-line-buffer convention elsewhere (e.g. cfusa_scan_lines()'s
 * 4096-byte buffer). `out` and `line` must not alias. */
//cfusa:req REQ-UTIL020
void cfusa_lex_strip_line(cfusa_lex_state_t *st, const char *line,
                           char *out, size_t out_sz);

#endif /* CFUSA_LEX_H */
