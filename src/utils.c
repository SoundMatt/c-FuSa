/* open()/fdopen() are POSIX; required on Linux with -std=c99 (same fix as
 * cmd_capabilities.c/cmd_qualify.c/cmd_impact.c/cmd_release.c/
 * cmd_audit_pack.c) — without it, strict ISO C99 glibc headers hide
 * fdopen()'s prototype, gcc implicitly declares it returning `int`, and the
 * truncated 32-bit "pointer" assigned to a FILE* segfaults on first use. */
#if defined(__linux__) || defined(__unix__)
#  define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "cfusa/utils.h"

/* ---- file walker ---- */

static int ext_matches(const char *path, const char * const *exts, int n)
{
    const char *e = cfusa_extension(path);
    if (!e) return 0;
    for (int i = 0; i < n; i++)
        if (strcmp(e, exts[i]) == 0) return 1;
    return 0;
}

//cfusa:req REQ-UTIL004 REQ-UTIL005
int cfusa_walk_sources(const char *dir, const char * const *exts, int n_exts,
                        cfusa_file_cb cb, void *ctx)
{
    DIR *d = opendir(dir);
    if (!d) return -1;

    int ret = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char path[512];
        cfusa_path_join(path, sizeof(path), dir, ent->d_name);

        struct stat st;
        if (stat(path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* Skip well-known non-source directories. Matches this
             * project's own .gitignore convention (a "build" directory, or
             * anything named "build-something"/"build_something") rather
             * than a fixed enum of names -- a local working tree commonly
             * has several build-type variants side by side (build-asan,
             * build-release, build_fortify, ...), and a generated file
             * inside any of them (e.g. CMake's own CompilerIdC probe,
             * which defines a real main function) is not project source.
             * Scanning one in was a real x-FuSa spec section 1.6 rule 4
             * violation found while dogfooding the fmea/tara scanners
             * against this repo's own (gitignored, untracked) build
             * directories. */
            const char *bn = ent->d_name;
            if (strcmp(bn,"build")==0 || strcmp(bn,"vendor")==0 ||
                strcmp(bn,"node_modules")==0 ||
                strncmp(bn,"build-",6)==0 || strncmp(bn,"build_",6)==0)
                continue;
            ret += cfusa_walk_sources(path, exts, n_exts, cb, ctx);
        } else if (S_ISREG(st.st_mode)) {
            if (n_exts == 0 || ext_matches(path, exts, n_exts))
                ret += cb(path, ctx);
        }
    }
    closedir(d);
    return ret;
}

/* ---- file I/O ---- */

char *cfusa_read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Guard against ftell failure (-1) and absurd sizes before allocating:
     * a negative/huge value would otherwise wrap in (size_t)sz + 1 and cause a
     * heap overflow or DoS on a crafted/unseekable file (CWE-190/CWE-789). */
    if (sz < 0 || (unsigned long)sz > (1UL << 31)) { fclose(f); return NULL; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    buf[got] = '\0';
    fclose(f);
    if (len_out) *len_out = got;
    return buf;
}

FILE *cfusa_fopen_write(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return NULL; }
    return f;
}

int cfusa_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int cfusa_dir_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Case-insensitive equality — kept local rather than pulling in
 * strcasecmp() (POSIX, not C99), matching the project's existing
 * convention (see severity.c's str_ieq(), qualitybar.c's
 * qb_str_ieq_trim()). */
static int utils_str_ieq(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

int cfusa_find_file_ci(const char *dir, const char *name,
                        char *out_path, size_t out_sz)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    int found = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!utils_str_ieq(ent->d_name, name)) continue;
        char candidate[512];
        cfusa_path_join(candidate, sizeof(candidate), dir, ent->d_name);
        struct stat st;
        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            cfusa_path_join(out_path, out_sz, dir, ent->d_name);
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

int cfusa_mkdir_p(const char *path)
{
    char tmp[512];
    strncpy(tmp, path, sizeof(tmp) - 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

/* ---- line scanning ---- */

void cfusa_scan_lines(const char *path, cfusa_line_cb cb, void *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[4096];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        cb(path, lineno, line, ctx);
    }
    fclose(f);
}

//cfusa:req REQ-UTIL010 REQ-UTIL011 REQ-UTIL012
/* ---- string helpers ---- */

const char *cfusa_basename(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

const char *cfusa_extension(const char *path)
{
    const char *base = cfusa_basename(path);
    const char *dot  = strrchr(base, '.');
    return dot;
}

int cfusa_str_contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

int cfusa_str_starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

char *cfusa_str_trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t'
                    || end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
    return s;
}

void cfusa_str_escape_json(const char *in, char *out, size_t out_sz)
{
    size_t i = 0;
    while (*in && i + 2 < out_sz) {
        if (*in == '"' || *in == '\\') {
            out[i++] = '\\';
            out[i++] = *in++;
        } else if (*in == '\n') {
            out[i++] = '\\'; out[i++] = 'n'; in++;
        } else if (*in == '\r') {
            out[i++] = '\\'; out[i++] = 'r'; in++;
        } else if (*in == '\t') {
            out[i++] = '\\'; out[i++] = 't'; in++;
        } else {
            out[i++] = *in++;
        }
    }
    out[i] = '\0';
}

//cfusa:req REQ-UTIL018
void cfusa_json_extract_string(const char *json, const char *key,
                                char *dst, size_t dsz)
{
    if (dsz == 0) return;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') p++;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < dsz - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': dst[i++] = '\n'; break;
            case 'r': dst[i++] = '\r'; break;
            case 't': dst[i++] = '\t'; break;
            default:  dst[i++] = *p;   break; /* \" \\ and any other escape */
            }
            p++;
        } else {
            dst[i++] = *p++;
        }
    }
    dst[i] = '\0';
}

void cfusa_path_join(char *out, size_t sz, const char *a, const char *b)
{
    size_t alen = strlen(a);
    if (alen && a[alen - 1] == '/')
        snprintf(out, sz, "%s%s", a, b);
    else
        snprintf(out, sz, "%s/%s", a, b);
}

/* x-FuSa spec §4: location.file MUST be project-relative regardless of
 * whether --dir was given as a relative or an absolute path. This is the
 * single canonical implementation of the relativization logic previously
 * duplicated ad hoc in cfusa_report_add() (src/report.c) and cmd_trace.c's
 * add_tag()/funcfile_cb() — see the "deliberately does NOT resolve
 * symlinks" note in the header. */
void cfusa_relativize_path(const char *root, const char *path, char *out, size_t out_sz)
{
    const char *rel = path;
    if (root && root[0]) {
        size_t rlen = strlen(root);
        while (rlen > 1 && root[rlen - 1] == '/') rlen--; /* tolerate a trailing slash on root */
        if (strncmp(path, root, rlen) == 0 &&
            (path[rlen] == '/' || path[rlen] == '\0'))
            rel = path + rlen + (path[rlen] == '/');
    }
    while (rel[0] == '.' && rel[1] == '/') rel += 2;
    if (!rel[0]) rel = ".";
    strncpy(out, rel, out_sz - 1);
    out[out_sz - 1] = '\0';
}

int cfusa_is_test_source_file(const char *path)
{
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (strncmp(b, "test_", 5) == 0) return 1;
    size_t n = strlen(b);
    return n > 7 && strcmp(b + n - 7, "_test.c") == 0;
}

const char *cfusa_find_outside_string(const char *line, char ch)
{
    int in_str = 0;
    const char *p = line;
    while (*p) {
        if (*p == '"' && (p == line || p[-1] != '\\')) {
            in_str = !in_str;
        } else if (!in_str && *p == ch) {
            return p;
        }
        p++;
    }
    return NULL;
}

/* Non-exhaustive but broad deny-list of C standard-library / CRT function
 * names, sorted for readability (linear scan — this list is short enough
 * that a call-site table isn't worth the complexity). A call to any of
 * these is never a project-defined "component"/"asset" for fmea/tara
 * purposes (x-FuSa spec §1.6 rule 4). */
int cfusa_is_stdlib_call(const char *name)
{
    static const char * const stdlib_fns[] = {
        "abort", "abs", "access", "asctime", "assert", "atexit", "atof",
        "atoi", "atol", "atoll",
        "bsearch",
        "calloc", "chdir", "chmod", "clock", "closedir", "close",
        "ctime",
        "difftime", "dup", "dup2",
        "errno", "execve", "execvp", "exit",
        "fclose", "fdopen", "feof", "ferror", "fflush", "fgetc", "fgets",
        "fopen", "fork", "fprintf", "fputc", "fputs", "fread", "free",
        "freopen", "fscanf", "fseek", "fstat", "ftell", "fwrite",
        "getchar", "getcwd", "getc", "getenv", "getline",
        "isalnum", "isalpha", "iscntrl", "isdigit", "isgraph", "islower",
        "isprint", "ispunct", "isspace", "isupper", "isxdigit",
        "labs", "llabs", "localtime", "lseek", "lstat",
        "malloc", "memchr", "memcmp", "memcpy", "memmove", "memset",
        "mkdir", "mkstemp", "mktime",
        "open", "opendir",
        "perror", "pipe", "printf", "putchar", "putc",
        "qsort",
        "rand", "random", "read", "readdir", "realloc", "realpath",
        "remove", "rename", "rewind", "rmdir",
        "scanf", "setenv", "snprintf", "sprintf", "srand", "sscanf",
        "stat", "strcasecmp", "strcat", "strchr", "strcmp", "strcpy",
        "strdup", "strerror", "strftime", "strlen", "strncasecmp",
        "strncat", "strncmp", "strncpy", "strndup", "strrchr", "strstr",
        "strtod", "strtof", "strtok_r", "strtok", "strtol", "strtoul",
        "system",
        "time", "tmpfile", "tmpnam", "tolower", "toupper",
        "unlink",
        "vfprintf", "vfscanf", "vprintf", "vscanf", "vsnprintf",
        "vsprintf", "vsscanf",
        "write",
        NULL
    };
    for (int i = 0; stdlib_fns[i]; i++)
        if (strcmp(name, stdlib_fns[i]) == 0) return 1;
    return 0;
}

/* Word-boundary check: does `p` start with keyword `kw` followed by a
 * non-identifier character (or end of string)? Handles both "if (" and
 * "if(" (the previous per-caller skip-lists only matched the former, a
 * separate bug this consolidation also fixes). */
static int starts_with_kw(const char *p, const char *kw)
{
    size_t l = strlen(kw);
    if (strncmp(p, kw, l) != 0) return 0;
    unsigned char after = (unsigned char)p[l];
    return !(isalnum(after) || after == '_');
}

static int starts_with_any_kw(const char *p)
{
    static const char * const kws[] = {
        "if", "for", "while", "switch", "return", "else", "case",
        "default", "typedef", "struct", "enum", "union", "static",
        "extern", "inline", "sizeof", "defined", "do", "goto", "break",
        "continue", "const", "volatile", "register", NULL
    };
    for (int i = 0; kws[i]; i++)
        if (starts_with_kw(p, kws[i])) return 1;
    return 0;
}

int cfusa_extract_call_name(const char *line, char *out, size_t out_sz)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p || *p == '/' || *p == '#' || *p == '*' || *p == '}') return 0;
    if (starts_with_any_kw(p)) return 0;

    const char *end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' ||
                           end[-1] == '\n' || end[-1] == '\r')) end--;
    if (end > line && end[-1] == ';') return 0;

    /* The '(' (and a ')' somewhere on the line) must be real code, not text
     * sitting inside a quoted string literal (x-FuSa spec §1.6 rule 4). */
    const char *paren = cfusa_find_outside_string(p, '(');
    if (!paren) return 0;
    if (!cfusa_find_outside_string(p, ')')) return 0;

    const char *ident_end = paren;
    while (ident_end > p && (ident_end[-1] == ' ' || ident_end[-1] == '\t' ||
                              ident_end[-1] == '*')) ident_end--;
    const char *ident_start = ident_end;
    while (ident_start > p && (isalnum((unsigned char)ident_start[-1]) ||
                                ident_start[-1] == '_')) ident_start--;

    size_t n = (size_t)(ident_end - ident_start);
    if (n < 2 || n >= out_sz) return 0;
    if (!isalpha((unsigned char)ident_start[0]) && ident_start[0] != '_') return 0;

    memcpy(out, ident_start, n);
    out[n] = '\0';

    if (cfusa_is_stdlib_call(out)) return 0;
    return 1;
}

/* ---- SHA-256 ---- */

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)(ROTR32(x,  7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)(ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t *data)
{
    uint32_t a,b,c,d,e,f,g,h,i,t1,t2,m[64];
    for (i = 0; i < 16; i++)
        m[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)
              |((uint32_t)data[i*4+2]<<8)|data[i*4+3];
    for (; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx_t *ctx)
{
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32])
{
    uint32_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (ctx->datalen < 56) {
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63]=(uint8_t)(ctx->bitlen);
    ctx->data[62]=(uint8_t)(ctx->bitlen>>8);
    ctx->data[61]=(uint8_t)(ctx->bitlen>>16);
    ctx->data[60]=(uint8_t)(ctx->bitlen>>24);
    ctx->data[59]=(uint8_t)(ctx->bitlen>>32);
    ctx->data[58]=(uint8_t)(ctx->bitlen>>40);
    ctx->data[57]=(uint8_t)(ctx->bitlen>>48);
    ctx->data[56]=(uint8_t)(ctx->bitlen>>56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]    =(ctx->state[0]>>(24-i*8))&0xff;
        hash[i+4]  =(ctx->state[1]>>(24-i*8))&0xff;
        hash[i+8]  =(ctx->state[2]>>(24-i*8))&0xff;
        hash[i+12] =(ctx->state[3]>>(24-i*8))&0xff;
        hash[i+16] =(ctx->state[4]>>(24-i*8))&0xff;
        hash[i+20] =(ctx->state[5]>>(24-i*8))&0xff;
        hash[i+24] =(ctx->state[6]>>(24-i*8))&0xff;
        hash[i+28] =(ctx->state[7]>>(24-i*8))&0xff;
    }
}

//cfusa:req REQ-UTIL015 REQ-UTIL016 REQ-UTIL017
void cfusa_sha256_buf(const unsigned char *buf, size_t len, char hex_out[65])
{
    sha256_ctx_t ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, buf, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++)
        snprintf(hex_out + i*2, 3, "%02x", hash[i]);
    hex_out[64] = '\0';
}

void cfusa_sha256_file(const char *path, char hex_out[65])
{
    FILE *f = fopen(path, "rb");
    if (!f) { memset(hex_out, '0', 64); hex_out[64]='\0'; return; }
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, n);
    fclose(f);
    uint8_t hash[32];
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++)
        snprintf(hex_out + i*2, 3, "%02x", hash[i]);
    hex_out[64] = '\0';
}

/* ---- HMAC-SHA-256 ---- */

void cfusa_hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        char hex_out[65])
{
    uint8_t k[64], ipad[64], opad[64];
    uint8_t inner_hash[32], final_hash[32];
    memset(k, 0, 64);

    if (klen > 64) {
        cfusa_sha256_buf(key, klen, hex_out); /* simplification: hash the key */
        /* convert hex back to bytes */
        for (int i = 0; i < 32; i++) {
            unsigned int v;
            sscanf(hex_out + i*2, "%02x", &v);
            k[i] = (uint8_t)v;
        }
    } else {
        memcpy(k, key, klen);
    }

    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, mlen);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, final_hash);

    for (int i = 0; i < 32; i++)
        snprintf(hex_out + i*2, 3, "%02x", final_hash[i]);
    hex_out[64] = '\0';
}

/* ---- timestamp ---- */

void cfusa_timestamp_now(char buf[32])
{
    time_t t = time(NULL);
    struct tm *tm_info = gmtime(&t);
    strftime(buf, 32, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

/* ---- source counting ---- */

static int count_cb(const char *path, void *ctx)
{
    (void)path;
    (*(int *)ctx)++;
    return 0;
}

//cfusa:req REQ-UTIL013 REQ-UTIL014
int cfusa_count_c_files(const char *dir)
{
    int n = 0;
    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, count_cb, &n);
    return n;
}

int cfusa_count_lines_in_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int lines = 0;
    int c;
    while ((c = fgetc(f)) != EOF)
        if (c == '\n') lines++;
    fclose(f);
    return lines;
}

//cfusa:req REQ-UTIL001 REQ-UTIL002 REQ-UTIL003
int cfusa_match_outside_string(const char *line, const char *token)
{
    int in_str = 0;
    const char *p = line;
    size_t tlen = strlen(token);
    while (*p) {
        if (*p == '"' && (p == line || p[-1] != '\\'))
            in_str = !in_str;
        if (!in_str && strncmp(p, token, tlen) == 0)
            return 1;
        p++;
    }
    return 0;
}

//cfusa:req REQ-UTIL019
const char *cfusa_find_token_outside_string(const char *line, const char *token)
{
    int in_str = 0;
    const char *p = line;
    size_t tlen = strlen(token);
    while (*p) {
        if (*p == '"' && (p == line || p[-1] != '\\'))
            in_str = !in_str;
        if (!in_str && strncmp(p, token, tlen) == 0) {
            int boundary_ok = (p == line) ||
                !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
            if (boundary_ok) return p;
        }
        p++;
    }
    return NULL;
}
