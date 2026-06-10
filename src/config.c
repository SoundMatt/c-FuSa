#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

//cfusa:req REQ-CFG001 REQ-CFG002 REQ-CFG003 REQ-CFG004 REQ-CFG005 REQ-CFG006
void cfusa_config_defaults(cfusa_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->project, "my-project", sizeof(cfg->project) - 1);
    strncpy(cfg->version, "0.1.0",      sizeof(cfg->version) - 1);
    cfg->max_function_lines = 50;
    cfg->strict             = 0;

    strncpy(cfg->src_exts[0], ".c", 7);
    strncpy(cfg->src_exts[1], ".h", 7);
    cfg->ext_count = 2;

    strncpy(cfg->standards[0], "iso26262",   31);
    strncpy(cfg->standards[1], "misra-c",    31);
    cfg->standards_count = 2;

    strncpy(cfg->exclude_dirs[0], "build",  255);
    strncpy(cfg->exclude_dirs[1], "vendor", 255);
    strncpy(cfg->exclude_dirs[2], ".git",   255);
    cfg->exclude_count = 3;
}

/* Minimal JSON key-value extractor — handles flat string/int/bool/array */
static void extract_string(const char *json, const char *key,
                            char *dst, size_t dsz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < dsz - 1)
        dst[i++] = *p++;
    dst[i] = '\0';
}

static int extract_int(const char *json, const char *key, int def)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return def;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == 't') return 1;  /* true */
    if (*p == 'f') return 0;  /* false */
    if (*p >= '0' && *p <= '9') return atoi(p);
    return def;
}

static void extract_str_array_n(const char *json, const char *key,
                                 char *dst, int elem_sz, int max, int *count)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p = strchr(p, '[');
    if (!p) return;
    p++;
    *count = 0;
    while (*p && *p != ']' && *count < max) {
        while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\r') p++;
        if (*p == '"') {
            p++;
            char *elem = dst + (*count) * elem_sz;
            int i = 0;
            while (*p && *p != '"' && i < elem_sz - 1)
                elem[i++] = *p++;
            elem[i] = '\0';
            (*count)++;
            if (*p == '"') p++;
        } else if (*p == ']') {
            break;
        } else {
            p++;
        }
    }
}

int cfusa_config_load(const char *dir, cfusa_config_t *cfg)
{
    cfusa_config_defaults(cfg);

    char path[512];
    cfusa_path_join(path, sizeof(path), dir, CFUSA_CONFIG_FILE);

    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) {
        /* §1.2 fallback: try legacy .cfusa.json with deprecation warning */
        cfusa_path_join(path, sizeof(path), dir, CFUSA_CONFIG_FILE_LEGACY);
        json = cfusa_read_file(path, &len);
        if (json)
            fprintf(stderr, "cfusa: WARNING: %s is deprecated; rename to %s\n",
                    CFUSA_CONFIG_FILE_LEGACY, CFUSA_CONFIG_FILE);
    }
    if (!json) return -1;

    /* §1.2.1: accept both flat "project":"name" and nested "project":{"name":…} */
    {
        const char *p = strstr(json, "\"project\"");
        if (p) {
            p += 9; while (*p == ' ' || *p == ':') p++;
            if (*p == '{') {
                /* nested form: extract "name" and "version" */
                const char *bs = p;
                const char *be = strchr(bs, '}');
                if (be) {
                    char obj[256] = "";
                    size_t ol = (size_t)(be - bs + 1);
                    if (ol > sizeof(obj) - 1) ol = sizeof(obj) - 1;
                    memcpy(obj, bs, ol);
                    extract_string(obj, "name",    cfg->project, sizeof(cfg->project));
                    extract_string(obj, "version", cfg->version, sizeof(cfg->version));
                }
            } else {
                /* flat form */
                extract_string(json, "project", cfg->project, sizeof(cfg->project));
                extract_string(json, "version", cfg->version, sizeof(cfg->version));
            }
        }
    }
    /* Also try top-level "version" for legacy flat configs */
    if (!cfg->version[0])
        extract_string(json, "version", cfg->version, sizeof(cfg->version));
    cfg->strict             = extract_int(json, "strict", cfg->strict);
    cfg->max_function_lines = extract_int(json, "max_function_lines",
                                          cfg->max_function_lines);

    /* §1.2.1 "standard" (single canonical id) — also accept old "standards" array */
    {
        char std1[32] = "";
        extract_string(json, "standard", std1, sizeof(std1));
        if (std1[0]) {
            strncpy(cfg->standards[0], std1, 31);
            cfg->standards_count = 1;
        } else {
            extract_str_array_n(json, "standards", (char *)cfg->standards,
                                (int)sizeof(cfg->standards[0]),
                                CFUSA_MAX_STANDARDS, &cfg->standards_count);
        }
    }

    /* §1.2.1 "excludePatterns" — strip trailing glob suffix for internal storage */
    {
        int count = 0;
        char raw[CFUSA_MAX_EXCLUDES][256];
        extract_str_array_n(json, "excludePatterns", (char *)raw,
                            256, CFUSA_MAX_EXCLUDES, &count);
        if (count > 0) {
            cfg->exclude_count = count;
            for (int i = 0; i < count; i++) {
                char *sl = strstr(raw[i], "/**");
                if (sl) *sl = '\0';
                strncpy(cfg->exclude_dirs[i], raw[i], 255);
            }
        } else {
            extract_str_array_n(json, "exclude_dirs", (char *)cfg->exclude_dirs,
                                (int)sizeof(cfg->exclude_dirs[0]),
                                CFUSA_MAX_EXCLUDES, &cfg->exclude_count);
        }
    }

    free(json);
    return 0;
}

int cfusa_config_save(const char *dir, const cfusa_config_t *cfg)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, CFUSA_CONFIG_FILE);

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }

    /* §1.2.1 conformant schema (configVersion is its own series, stays "1.0") */
    fprintf(f, "{\n");
    fprintf(f, "  \"configVersion\": \"1.0\",\n");
    fprintf(f, "  \"project\": {\"name\": \"%s\", \"version\": \"%s\"},\n",
            cfg->project, cfg->version[0] ? cfg->version : "0.1.0");
    /* primary standard (first in the list) */
    if (cfg->standards_count > 0)
        fprintf(f, "  \"standard\": \"%s\",\n", cfg->standards[0]);
    fprintf(f, "  \"strict\": %s,\n", cfg->strict ? "true" : "false");
    /* tool-defined extension: keep max_function_lines for internal use */
    fprintf(f, "  \"max_function_lines\": %d,\n", cfg->max_function_lines);

    fprintf(f, "  \"sourceDirs\": [\".\"],\n");

    fprintf(f, "  \"excludePatterns\": [");
    for (int i = 0; i < cfg->exclude_count; i++)
        fprintf(f, "%s\"%s/**\"", i ? ", " : "", cfg->exclude_dirs[i]);
    fprintf(f, "]\n");

    fprintf(f, "}\n");
    fclose(f);
    return 0;
}

int cfusa_config_is_excluded(const cfusa_config_t *cfg, const char *path)
{
    for (int i = 0; i < cfg->exclude_count; i++) {
        if (strstr(path, cfg->exclude_dirs[i]))
            return 1;
    }
    return 0;
}
