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
int   cfusa_mkdir_p(const char *path);

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

/* ---- path helpers ---- */
void cfusa_path_join(char *out, size_t sz, const char *a, const char *b);

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
