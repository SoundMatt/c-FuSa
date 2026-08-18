#ifndef CFUSA_UTILS_H
#define CFUSA_UTILS_H

#include <stddef.h>
#include <stdio.h>

/* ---- file walking ---- */
typedef int (*cfusa_file_cb)(const char *path, void *ctx);

int  cfusa_walk_sources(const char *dir, const char * const *exts, int n_exts,
                         cfusa_file_cb cb, void *ctx);

/* ---- file I/O ---- */
char *cfusa_read_file(const char *path, size_t *len_out);
int   cfusa_file_exists(const char *path);
int   cfusa_dir_exists(const char *path);

/* Looks for a regular file named `name` directly under `dir`, matching
 * case-insensitively (issue #97: cmd_safety_case.c used to hardcode exact
 * lowercase evidence filenames like "hara.md"/"safety-plan.md" and
 * cfusa_file_exists() is a plain stat() — case-sensitive on the Linux
 * runners CI/release actually use — so a project naming its evidence
 * HARA.md/SAFETY_PLAN.md (a defensible, common convention) silently read
 * as "no evidence" on Linux while appearing fine on a case-insensitive
 * dev filesystem like macOS/Windows). Scans the directory listing (no
 * shell-out, no fixed casing-variant guesswork) so any casing of `name`
 * is found. On a match, joins `dir`/<actual on-disk name> into
 * `out_path` (size `out_sz`) and returns 1; returns 0 (out_path
 * untouched) when `dir` can't be opened or no case-insensitive match
 * exists. */
int cfusa_find_file_ci(const char *dir, const char *name,
                        char *out_path, size_t out_sz);
int   cfusa_mkdir_p(const char *path);

/* Opens `path` for writing (truncating) with explicit 0600 permissions —
 * unlike fopen(path, "w"), whose actual mode depends on the process umask
 * and so may create a world-writable file. Returns NULL (errno set) on
 * failure, exactly like fopen(). */
FILE *cfusa_fopen_write(const char *path);

/* ---- line scanning ---- */
typedef void (*cfusa_line_cb)(const char *path, int lineno,
                               const char *line, void *ctx);
void cfusa_scan_lines(const char *path, cfusa_line_cb cb, void *ctx);

/* ---- string helpers ---- */
const char *cfusa_basename(const char *path);
const char *cfusa_extension(const char *path);
int         cfusa_str_contains(const char *haystack, const char *needle);
int         cfusa_str_starts_with(const char *s, const char *prefix);
char       *cfusa_str_trim(char *s);
void        cfusa_str_escape_json(const char *in, char *out, size_t out_sz);

/* Extracts the string value of `"key": "value"` from `json`, tolerant of
 * any whitespace (space/tab/newline/CR) between the key's closing quote,
 * the colon, and the value's opening quote — ordinary pretty-printed JSON
 * (`json.dump(..., indent=2)`, `jq .`, most editors' format-on-save) puts
 * a space there, and a rigid `sscanf(p, "\"key\":\"%N[^\"]", ...)`-style
 * literal-adjacency match silently fails to extract it (issue #97-class
 * audit findings: this exact bug independently broke disposition
 * loading, the qualitybar placeholder-text gate, and HARA fssrRefs
 * dangling-reference detection — see cmd/cfusa/cmd_disposition.c,
 * src/qualitybar.c, cmd/cfusa/cmd_hara.c history). Also reverses the
 * escaping cfusa_str_escape_json() applies (\", \\, \n, \r, \t), so a
 * value written by this codebase's own writer round-trips correctly.
 * `dst` is always NUL-terminated; on no match, `dst[0]` is left
 * untouched by the caller's own zero-initialization (mirrors
 * config.c's extract_string() convention — callers zero/clear `dst`
 * first). Matches only the FIRST occurrence of `"key"` in `json`. */
//cfusa:req REQ-UTIL018
void cfusa_json_extract_string(const char *json, const char *key,
                                char *dst, size_t dsz);

/* ---- path helpers ---- */
void cfusa_path_join(char *out, size_t sz, const char *a, const char *b);

/* Relativizes `path` against `root` — the same --dir value (relative or
 * absolute, exactly as given, NOT run through realpath()) that was passed
 * to cfusa_walk_sources() to produce `path` in the first place — so the
 * result satisfies x-FuSa spec §4's "location.file MUST be project-
 * relative" rule. Deliberately does NOT resolve symlinks: since
 * cfusa_walk_sources() builds every `path` by literally concatenating
 * `root` with each traversed entry, `root` is always already the correct
 * literal prefix to strip, and running it through realpath() first would
 * silently break relativization whenever the two disagree on a symlink
 * (e.g. macOS aliases /tmp -> /private/tmp, so realpath("/tmp/x") no
 * longer prefixes a `path` built from the literal "/tmp/x"). Handles a
 * trailing slash on `root` and strips any remaining leading "./" once
 * `path` is already relative. This is the one canonical implementation of
 * the relativization logic `check`/`trace` already used (previously
 * duplicated ad hoc in cfusa_report_add() and cmd_trace.c) — every command
 * producing a project-relative `file` field SHOULD reuse it. */
void cfusa_relativize_path(const char *root, const char *path, char *out, size_t out_sz);

/* Returns 1 when `path`'s basename looks like this project's test-source
 * naming convention (`test_*.c` or `*_test.c`), 0 otherwise. Shared by
 * `trace --func-coverage` (§1.4.1), `fmea`, and `tara` so all three
 * commands' component/asset denominators are scoped to the same
 * non-test-source tree (x-FuSa spec §1.6 rule 4 implementation note) rather
 * than each maintaining its own narrower, independently-drifting copy. */
int cfusa_is_test_source_file(const char *path);

/* Returns a pointer to the first un-quoted occurrence of `ch` in `line` (a
 * single line of C source), or NULL when every occurrence is inside a
 * string literal (or there is none). Uses the same in-string tracking
 * algorithm as cfusa_match_outside_string(), generalised to return a
 * position instead of a boolean token match — used to avoid mistaking a
 * `(` found inside a quoted string (e.g. a test-case description literal)
 * for a real call/definition site (x-FuSa spec §1.6 rule 4). */
const char *cfusa_find_outside_string(const char *line, char ch);

/* Returns 1 when `name` is a well-known C standard-library/CRT function
 * (printf, malloc, strcpy, ...), 0 otherwise. A scanner building
 * fmea/tara-style entries from source text SHOULD exclude these from
 * "components in project" — a call to a stdlib function is not a project
 * symbol (x-FuSa spec §1.6 rule 4). */
int cfusa_is_stdlib_call(const char *name);

/* Scans a single line of C source for something that looks like a real
 * call/definition site — `<identifier>(` — outside a string literal, not a
 * control-flow/storage-class keyword, and not a standard-library call, and
 * copies the identifier into `out` (which must be at least 2 bytes).
 * Returns 1 on a match, 0 otherwise. Centralises the heuristic previously
 * duplicated (and independently under-guarded) in cmd_fmea.c's fmea_line()
 * and cmd_tara.c's asset_line() — x-FuSa spec §1.6 rule 4. */
int cfusa_extract_call_name(const char *line, char *out, size_t out_sz);

/* ---- SHA-256 ---- */
void cfusa_sha256_file(const char *path, char hex_out[65]);
void cfusa_sha256_buf(const unsigned char *buf, size_t len, char hex_out[65]);

/* ---- HMAC-SHA-256 ---- */
void cfusa_hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        char hex_out[65]);

/* ---- timestamp ---- */
void cfusa_timestamp_now(char buf[32]);

/* ---- source counting ---- */
int cfusa_count_c_files(const char *dir);
int cfusa_count_lines_in_file(const char *path);

/* ---- pattern matching ---- */
/* Returns 1 if token appears on the line outside a C string literal, 0 otherwise. */
int cfusa_match_outside_string(const char *line, const char *token);

#endif /* CFUSA_UTILS_H */
