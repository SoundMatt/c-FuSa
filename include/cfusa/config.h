#ifndef CFUSA_CONFIG_H
#define CFUSA_CONFIG_H

#define CFUSA_CONFIG_FILE   ".cfusa.json"
#define CFUSA_MAX_EXCLUDES  64
#define CFUSA_MAX_STANDARDS 8
#define CFUSA_MAX_EXTS      8

typedef struct {
    char project[128];
    char version[32];
    char standards[CFUSA_MAX_STANDARDS][32];
    int  standards_count;
    char exclude_dirs[CFUSA_MAX_EXCLUDES][256];
    int  exclude_count;
    char src_exts[CFUSA_MAX_EXTS][8];
    int  ext_count;
    int  strict;
    int  max_function_lines;
} cfusa_config_t;

void cfusa_config_defaults(cfusa_config_t *cfg);
int  cfusa_config_load(const char *dir, cfusa_config_t *cfg);
int  cfusa_config_save(const char *dir, const cfusa_config_t *cfg);
int  cfusa_config_is_excluded(const cfusa_config_t *cfg, const char *path);

#endif /* CFUSA_CONFIG_H */
