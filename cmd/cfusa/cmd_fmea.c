/*
 * cfusa fmea — Design FMEA skeleton generator.
 *
 * Scans C source for function definitions and emits a template FMEA table
 * in Markdown, JSON, or CSV format (IEC 60812 / ISO 26262 Part 5).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/report.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

#define MAX_FUNS 1024

typedef struct {
    char name[128];
    char file[256];
    int  line;
    char sig[256];
    int  severity;   /* 1–10, inferred from function profile */
} fn_entry_t;

static fn_entry_t g_fns[MAX_FUNS];
static int        g_fn_count = 0;

/* Heuristic: elevated severity if name contains safety-critical keywords */
static int infer_severity(const char *name)
{
    static const char * const hi[] = {
        "brake","steer","throttle","safety","shutdown","critical",
        "halt","fault","error","emergency","protect","watchdog", NULL
    };
    static const char * const med[] = {
        "init","config","check","validate","monitor","log", NULL
    };
    for (int i = 0; hi[i]; i++)
        if (strstr(name, hi[i])) return 9;
    for (int i = 0; med[i]; i++)
        if (strstr(name, med[i])) return 5;
    return 3;
}

static const char *sev_string(int s)
{
    if (s >= 8) return "High";
    if (s >= 5) return "Medium";
    return "Low";
}

static void fmea_line(const char *path, int lineno, const char *line, void *vctx)
{
    (void)vctx;
    if (g_fn_count >= MAX_FUNS) return;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p || *p == '/' || *p == '#' || *p == '*' || *p == '}') return;
    static const char * const skip_kw[] = {
        "if ","for ","while ","switch ","return ","else ","case ",
        "typedef ","struct ","enum ","union ","static ","extern ","inline ",NULL
    };
    for (int i = 0; skip_kw[i]; i++)
        if (strncmp(p, skip_kw[i], strlen(skip_kw[i])) == 0) return;
    if (!strstr(line,"(") || !strstr(line,")")) return;
    const char *end = line + strlen(line);
    while (end > line && (end[-1]==' '||end[-1]=='\t'||end[-1]=='\n'||end[-1]=='\r')) end--;
    if (end > line && end[-1] == ';') return;

    char *paren = strchr((char*)p, '(');
    if (!paren) return;
    char before[128] = "";
    size_t bl = (size_t)(paren - p);
    if (bl == 0 || bl >= 128) return;
    strncpy(before, p, bl); before[bl] = '\0';
    char *sp = strrchr(before, ' ');
    char *fn_name = sp ? sp + 1 : before;
    while (*fn_name == '*') fn_name++;
    if (!*fn_name || strlen(fn_name) < 2) return;

    strncpy(g_fns[g_fn_count].name, fn_name, 127);
    strncpy(g_fns[g_fn_count].file, path,    255);
    strncpy(g_fns[g_fn_count].sig,  p,       255);
    g_fns[g_fn_count].line     = lineno;
    g_fns[g_fn_count].severity = infer_severity(fn_name);
    g_fn_count++;
}

static int fmea_file(const char *path, void *v)
{ cfusa_scan_lines(path, fmea_line, v); return 0; }

int cmd_fmea(int argc, char **argv)
{
    const char *dir      = ".";
    const char *out_dir  = NULL;   /* --output-dir (go-FuSa style) */
    const char *fmt_s    = NULL;   /* NULL → both json+csv; "md"/"json"/"csv" → single */
    int with_cyber       = 0;

    static const struct option lo[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"output-dir", required_argument, NULL, 'D'},
        {"format",     required_argument, NULL, 'f'},
        {"cyber",      no_argument,       NULL, 'c'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int ch; optind = 1;
    while ((ch = getopt_long(argc, argv, "d:D:f:ch", lo, NULL)) != -1) {
        switch (ch) {
        case 'd': dir      = optarg; break;
        case 'D': out_dir  = optarg; break;
        case 'f': fmt_s    = optarg; break;
        case 'c': with_cyber = 1;    break;
        case 'h':
            printf("Usage: cfusa fmea [--dir <path>] [--output-dir <dir>]\n"
                   "                  [--format md|json|csv] [--cyber]\n\n"
                   "Generates a design FMEA skeleton from function signatures.\n"
                   "Default: generates both fmea.json and fmea.csv (IEC 60812 / ISO 26262-5).\n"
                   "--format md  generates fmea.md instead.\n"
                   "--cyber      enriches entries with cybersecurity failure modes.\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);
    g_fn_count = 0;

    static const char * const exts[] = {".c"};
    cfusa_walk_sources(dir, exts, 1, fmea_file, NULL);

    const char *base = out_dir ? out_dir : dir;
    char ts[32]; cfusa_timestamp_now(ts);

    /* Helper: open output file relative to base directory */
#define OPEN_OUT(name, var)  do { \
    char _p[512]; cfusa_path_join(_p, sizeof(_p), base, (name)); \
    (var) = fopen(_p, "w"); \
    if (!(var)) { perror(_p); return 1; } \
    printf("FMEA written to %s  (%d functions)\n", _p, g_fn_count); \
} while(0)

    if (!fmt_s) {
        /* Default: generate both fmea.json and fmea.csv (go-FuSa style) */
        FILE *jf, *cf;
        OPEN_OUT("fmea.json", jf);
        OPEN_OUT("fmea.csv",  cf);

        /* JSON */
        fprintf(jf,
            "{\n"
            "  \"tool\": \"cfusa fmea\",\n"
            "  \"project\": \"%s\",\n"
            "  \"version\": \"%s\",\n"
            "  \"generated\": \"%s\",\n"
            "  \"standard\": \"IEC 60812 / ISO 26262-5\",\n"
            "  \"entries\": [\n",
            cfg.project, cfg.version, ts);
        /* CSV header */
        if (with_cyber)
            fprintf(cf, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,RPN,Action,Cyber Failure Mode\n");
        else
            fprintf(cf, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,RPN,Action\n");

        int high = 0, med_cnt = 0, low = 0;
        for (int i = 0; i < g_fn_count; i++) {
            int s = g_fns[i].severity;
            const char *sv = sev_string(s);
            if (s >= 8) high++; else if (s >= 5) med_cnt++; else low++;
            /* JSON entry */
            fprintf(jf,
                "    {\n"
                "      \"id\": \"FM-%03d\",\n"
                "      \"function\": \"%s\",\n"
                "      \"file\": \"%s\",\n"
                "      \"line\": %d,\n"
                "      \"failure_mode\": \"\",\n"
                "      \"effect\": \"\",\n"
                "      \"cause\": \"\",\n"
                "      \"severity\": \"%s\",\n"
                "      \"occurrence\": 1,\n"
                "      \"detection\": 1,\n"
                "      \"rpn\": %d%s\n"
                "    }%s\n",
                i + 1, g_fns[i].name,
                cfusa_basename(g_fns[i].file), g_fns[i].line,
                sv, s,
                with_cyber ? ",\n      \"cyber_failure_mode\": \"\"" : "",
                (i < g_fn_count - 1) ? "," : "");
            /* CSV row */
            fprintf(cf, "FM-%03d,\"%s\",\"%s\",%d,,,,\"%s\",1,1,%d,",
                    i + 1, g_fns[i].name,
                    cfusa_basename(g_fns[i].file), g_fns[i].line, sv, s);
            if (with_cyber) fprintf(cf, ",\n"); else fprintf(cf, "\n");
        }
        fprintf(jf, "  ]\n}\n");
        fclose(jf); fclose(cf);
        printf("Severity: %d high, %d medium, %d low\n", high, med_cnt, low);
        return 0;
    }

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    const char *def_name = (fmt == FMT_JSON) ? "fmea.json" :
                           (fmt == FMT_CSV)  ? "fmea.csv"  : "fmea.md";
    FILE *f;
    OPEN_OUT(def_name, f);

    if (fmt == FMT_JSON) {
        fprintf(f,
            "{\n"
            "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
            "  \"kind\": \"fmea\",\n"
            "  \"tool\": \"c-FuSa\",\n"
            "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
            "  \"language\": \"c\",\n"
            "  \"generatedAt\": \"%s\",\n"
            "  \"project\": \"%s\",\n"
            "  \"version\": \"%s\",\n"
            "  \"standard\": \"IEC 60812 / ISO 26262-5\",\n"
            "  \"entries\": [\n",
            ts, cfg.project, cfg.version);
        for (int i = 0; i < g_fn_count; i++) {
            int s = g_fns[i].severity;
            const char *sv = sev_string(s);
            fprintf(f,
                "    {\n"
                "      \"id\": \"FM-%03d\",\n"
                "      \"function\": \"%s\",\n"
                "      \"file\": \"%s\",\n"
                "      \"line\": %d,\n"
                "      \"failure_mode\": \"\",\n"
                "      \"effect\": \"\",\n"
                "      \"cause\": \"\",\n"
                "      \"severity\": \"%s\",\n"
                "      \"occurrence\": 1,\n"
                "      \"detection\": 1,\n"
                "      \"rpn\": %d%s\n"
                "    }%s\n",
                i + 1, g_fns[i].name,
                cfusa_basename(g_fns[i].file), g_fns[i].line,
                sv, s,
                with_cyber ? ",\n      \"cyber_failure_mode\": \"\"" : "",
                (i < g_fn_count - 1) ? "," : "");
        }
        fprintf(f, "  ]\n}\n");
    } else if (fmt == FMT_CSV) {
        if (with_cyber)
            fprintf(f, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,RPN,Action,Cyber Failure Mode\n");
        else
            fprintf(f, "ID,Function,File,Line,Failure Mode,Effect,Cause,Severity,O,D,RPN,Action\n");
        for (int i = 0; i < g_fn_count; i++) {
            int s = g_fns[i].severity;
            const char *sv = sev_string(s);
            fprintf(f, "FM-%03d,\"%s\",\"%s\",%d,,,,\"%s\",1,1,%d,",
                    i + 1, g_fns[i].name,
                    cfusa_basename(g_fns[i].file), g_fns[i].line, sv, s);
            if (with_cyber) fprintf(f, ",\n"); else fprintf(f, "\n");
        }
    } else {
        /* Markdown */
        fprintf(f,
            "# Design FMEA — %s v%s\n"
            "Generated: %s  |  Standard: IEC 60812 / ISO 26262 Part 5\n\n"
            "**Instructions:** For each function, identify failure modes and effects. "
            "S/O/D rated 1-10; RPN = S*O*D.\n\n",
            cfg.project, cfg.version, ts);
        fprintf(f,
            "| ID | Function | File | Failure Mode | Effect | "
            "Cause | S | O | D | RPN | Action |");
        if (with_cyber) fprintf(f, " Cyber Failure Mode |");
        fprintf(f, "\n|---|---|---|---|---|---|---|---|---|---|---|");
        if (with_cyber) fprintf(f, "---|");
        fprintf(f, "\n");
        for (int i = 0; i < g_fn_count; i++) {
            fprintf(f,
                "| FM-%03d | `%s` | %s:%d | [describe] | [effect] | [cause] "
                "| %d | 1 | 1 | %d | [action] |",
                i + 1, g_fns[i].name,
                cfusa_basename(g_fns[i].file), g_fns[i].line,
                g_fns[i].severity, g_fns[i].severity);
            if (with_cyber) fprintf(f, " [cyber] |");
            fprintf(f, "\n");
        }
        fprintf(f,
            "\n---\n"
            "_Total functions analysed: %d_  \n"
            "_Review: [name / date]_\n", g_fn_count);
    }

    fclose(f);
    return 0;
#undef OPEN_OUT
}
