/*
 * cfusa req — Requirements registry management.
 *
 * With no IDs: lists all requirements from .cfusa-reqs.json with their
 * source and test locations.
 * With one or more IDs: shows details and locations for those requirements.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

#define REQS_FILE  ".cfusa-reqs.json"
#define MAX_REQS   1024
#define MAX_TAGS   4096
#define MAX_ID     64
#define MAX_TITLE  128

#define KIND_IMPL     0
#define KIND_TEST     1
#define KIND_SEC_TEST 2

typedef struct { char id[MAX_ID]; char title[MAX_TITLE];
                 char text[512];  char standard[64];
                 char level[32];  } req_t;
typedef struct { char req_id[MAX_ID]; char file[256];
                 int  line; int kind; } tag_t;

static req_t g_reqs[MAX_REQS]; static int g_req_count;
static tag_t g_tags[MAX_TAGS]; static int g_tag_count;

static void jfield(const char *obj, const char *key, char *out, size_t sz)
{
    out[0] = '\0';
    char pat[96]; snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(obj, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ') p++;
    if (*p != '"') return; p++;
    size_t i = 0;
    while (*p && *p != '"' && i < sz - 1) {
        if (*p == '\\') { p++; if (!*p) break; }
        out[i++] = *p++;
    }
    out[i] = '\0';
}

static void load_reqs(const char *dir)
{
    char path[512]; cfusa_path_join(path, sizeof(path), dir, REQS_FILE);
    size_t len; char *json = cfusa_read_file(path, &len);
    if (!json) return;
    const char *p = strstr(json, "\"requirements\"");
    if (p) p = strchr(p, '[');
    if (!p) { free(json); return; }
    p++;
    while (*p && *p != ']' && g_req_count < MAX_REQS) {
        const char *bs = strchr(p, '{'); if (!bs) break;
        const char *be = strchr(bs, '}'); if (!be) break;
        char obj[2048] = "";
        size_t ol = (size_t)(be - bs + 1);
        if (ol > sizeof(obj) - 1) ol = sizeof(obj) - 1;
        memcpy(obj, bs, ol);
        jfield(obj, "id",       g_reqs[g_req_count].id,       MAX_ID);
        jfield(obj, "title",    g_reqs[g_req_count].title,    MAX_TITLE);
        jfield(obj, "text",     g_reqs[g_req_count].text,     512);
        jfield(obj, "standard", g_reqs[g_req_count].standard, 64);
        jfield(obj, "level",    g_reqs[g_req_count].level,    32);
        if (g_reqs[g_req_count].id[0]) g_req_count++;
        p = be + 1;
    }
    free(json);
}

/* Valid req IDs are non-empty alphanumeric + '-'/'_' (e.g. REQ-LINT001) */
static int is_valid_req_id(const char *s)
{
    if (!s || !*s || *s == '"' || *s == '(' || *s == ')') return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!isalnum(c) && c != '-' && c != '_') return 0;
    }
    return 1;
}

static void add_tag(const char *path, int lineno, const char *ids, int kind)
{
    char buf[512]; strncpy(buf, ids, sizeof(buf) - 1);
    char *end = strpbrk(buf, "\n\r\""); if (end) *end = '\0';
    char *tok = strtok(buf, " \t,");
    while (tok && g_tag_count < MAX_TAGS) {
        char *t = cfusa_str_trim(tok);
        if (is_valid_req_id(t)) {
            strncpy(g_tags[g_tag_count].req_id, t,    MAX_ID - 1);
            strncpy(g_tags[g_tag_count].file,   path, 255);
            g_tags[g_tag_count].line = lineno;
            g_tags[g_tag_count].kind = kind;
            g_tag_count++;
        }
        tok = strtok(NULL, " \t,");
    }
}

static void scan_line(const char *path, int lineno,
                       const char *line, void *vctx)
{
    (void)vctx;
    const char *p;
    if ((p = strstr(line, "//cfusa:req ")))
        add_tag(path, lineno, p + 12, KIND_IMPL);
    if ((p = strstr(line, "//cfusa:test ")))
        add_tag(path, lineno, p + 13, KIND_TEST);
    if ((p = strstr(line, "//cfusa:sec-test ")))
        add_tag(path, lineno, p + 17, KIND_SEC_TEST);
    /* legacy */
    if ((p = strstr(line, "REQ:"))) {
        p += 4;
        while (*p == ' ' || *p == '\t') p++;
        char buf[512]; strncpy(buf, p, sizeof(buf) - 1);
        char *e = strpbrk(buf, "*/\n"); if (e) *e = '\0';
        char *tok = strtok(buf, ", \t");
        while (tok && g_tag_count < MAX_TAGS) {
            char *t = cfusa_str_trim(tok);
            if (*t) add_tag(path, lineno, t, KIND_IMPL);
            tok = strtok(NULL, ", \t");
        }
    }
}

static int scan_file(const char *path, void *v)
{ cfusa_scan_lines(path, scan_line, v); return 0; }

/* XML helper: escape < > & " for attribute/element text */
static void xml_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '<':  fputs("&lt;",   f); break;
        case '>':  fputs("&gt;",   f); break;
        case '&':  fputs("&amp;",  f); break;
        case '"':  fputs("&quot;", f); break;
        default:   fputc(*s, f);      break;
        }
    }
}

static void do_req_export(const char *dir, const char *output, const char *fmt)
{
    g_req_count = g_tag_count = 0;
    load_reqs(dir);

    if (g_req_count == 0) {
        fprintf(stderr, "cfusa req export: no requirements in %s/%s\n",
                dir, REQS_FILE);
        return;
    }

    FILE *f = output ? fopen(output, "w") : stdout;
    if (!f) { perror(output); return; }

    if (fmt && !strcmp(fmt, "doors")) {
        /* ReqIF XML (minimal) */
        fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        fprintf(f, "<REQ-IF>\n  <CORE-CONTENT>\n    <SPEC-OBJECTS>\n");
        for (int i = 0; i < g_req_count; i++) {
            fprintf(f, "      <SPEC-OBJECT>\n        <VALUES>\n");
            fprintf(f, "          <ATTRIBUTE-VALUE-STRING THE-VALUE=\"");
            xml_escape(f, g_reqs[i].id);    fprintf(f, "\">"
                       "<DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>attr-id</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>"
                       "</ATTRIBUTE-VALUE-STRING>\n");
            fprintf(f, "          <ATTRIBUTE-VALUE-STRING THE-VALUE=\"");
            xml_escape(f, g_reqs[i].title); fprintf(f, "\">"
                       "<DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>attr-title</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>"
                       "</ATTRIBUTE-VALUE-STRING>\n");
            fprintf(f, "          <ATTRIBUTE-VALUE-STRING THE-VALUE=\"");
            xml_escape(f, g_reqs[i].text);  fprintf(f, "\">"
                       "<DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>attr-text</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>"
                       "</ATTRIBUTE-VALUE-STRING>\n");
            fprintf(f, "        </VALUES>\n      </SPEC-OBJECT>\n");
        }
        fprintf(f, "    </SPEC-OBJECTS>\n  </CORE-CONTENT>\n</REQ-IF>\n");
    } else if (fmt && !strcmp(fmt, "polarion")) {
        /* Polarion XML */
        fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<workitems>\n");
        for (int i = 0; i < g_req_count; i++) {
            fprintf(f, "  <workitem id=\""); xml_escape(f, g_reqs[i].id); fprintf(f, "\">\n");
            fprintf(f, "    <title>"); xml_escape(f, g_reqs[i].title); fprintf(f, "</title>\n");
            if (g_reqs[i].text[0])
                { fprintf(f, "    <description>"); xml_escape(f, g_reqs[i].text); fprintf(f, "</description>\n"); }
            if (g_reqs[i].level[0]) {
                fprintf(f, "    <customFields>\n");
                fprintf(f, "      <customField id=\"level\" value=\""); xml_escape(f, g_reqs[i].level); fprintf(f, "\"/>\n");
                fprintf(f, "    </customFields>\n");
            }
            fprintf(f, "  </workitem>\n");
        }
        fprintf(f, "</workitems>\n");
    } else if (fmt && !strcmp(fmt, "codebeamer")) {
        /* Codebeamer XML */
        fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<tracker>\n");
        for (int i = 0; i < g_req_count; i++) {
            fprintf(f, "  <item id=\""); xml_escape(f, g_reqs[i].id); fprintf(f, "\">\n");
            fprintf(f, "    <summary>"); xml_escape(f, g_reqs[i].title); fprintf(f, "</summary>\n");
            if (g_reqs[i].text[0])
                { fprintf(f, "    <description>"); xml_escape(f, g_reqs[i].text); fprintf(f, "</description>\n"); }
            if (g_reqs[i].level[0]) {
                fprintf(f, "    <customFields>\n");
                fprintf(f, "      <customField id=\"level\" value=\""); xml_escape(f, g_reqs[i].level); fprintf(f, "\"/>\n");
                fprintf(f, "    </customFields>\n");
            }
            fprintf(f, "  </item>\n");
        }
        fprintf(f, "</tracker>\n");
    } else if (fmt && !strcmp(fmt, "jama")) {
        /* Jama Connect XML */
        fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items>\n");
        for (int i = 0; i < g_req_count; i++) {
            fprintf(f, "  <item id=\""); xml_escape(f, g_reqs[i].id); fprintf(f, "\" itemType=\"requirement\">\n");
            fprintf(f, "    <name>"); xml_escape(f, g_reqs[i].title); fprintf(f, "</name>\n");
            if (g_reqs[i].text[0])
                { fprintf(f, "    <description>"); xml_escape(f, g_reqs[i].text); fprintf(f, "</description>\n"); }
            if (g_reqs[i].level[0]) {
                fprintf(f, "    <fields>\n");
                fprintf(f, "      <field id=\"level\" value=\""); xml_escape(f, g_reqs[i].level); fprintf(f, "\"/>\n");
                fprintf(f, "    </fields>\n");
            }
            fprintf(f, "  </item>\n");
        }
        fprintf(f, "</items>\n");
    } else {
        /* CSV (default) */
        fprintf(f, "id,title,text,standard,level\n");
        for (int i = 0; i < g_req_count; i++) {
            fprintf(f, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                    g_reqs[i].id, g_reqs[i].title, g_reqs[i].text,
                    g_reqs[i].standard, g_reqs[i].level);
        }
    }

    if (output) fclose(f);
    if (output) printf("Exported %d requirement(s) to %s\n", g_req_count, output);
}

/* ---- ALM format parsers ------------------------------------------ */

/* Write one entry into new_entries[], return updated length */
static size_t append_entry(char *buf, size_t buf_sz, size_t cur_len,
                            const char *id, const char *title,
                            const char *text, const char *standard,
                            const char *level, int *count)
{
    char entry[1024];
    int n = snprintf(entry, sizeof(entry),
        "    {\"id\":\"%s\",\"title\":\"%s\",\"text\":\"%s\","
        "\"standard\":\"%s\",\"level\":\"%s\"}",
        id, title, text, standard, level);
    if (n <= 0) return cur_len;
    if (cur_len + (size_t)n + 4 >= buf_sz) return cur_len;
    if (cur_len > 0) { strcat(buf, ",\n"); cur_len += 2; }
    strcat(buf, entry);
    (*count)++;
    return cur_len + (size_t)n;
}

/* Polarion/DOORS ReqIF XML: extract <ATTRIBUTE-VALUE-XHTML> and
 * <ATTRIBUTE-DEFINITION-XHTML> patterns — simple heuristic. */
static int import_reqif(const char *path, const char *dir,
                         char *new_entries, size_t buf_sz,
                         size_t *ne_len_out, int *imported)
{
    size_t flen;
    char *xml = cfusa_read_file(path, &flen);
    if (!xml) { perror(path); return 3; }

    /* Walk SPEC-OBJECT elements */
    const char *p = xml;
    int idx = 0;
    while ((p = strstr(p, "<SPEC-OBJECT")) != NULL) {
        char id[MAX_ID]     = "";
        char title[MAX_TITLE] = "";
        char text[512]      = "";

        /* Scan up to next </SPEC-OBJECT> for ATTRIBUTE-VALUE blocks */
        const char *end_obj = strstr(p, "</SPEC-OBJECT>");
        if (!end_obj) break;
        size_t obj_len = (size_t)(end_obj - p);
        char *obj = (char *)malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, p, obj_len); obj[obj_len] = '\0';

        /* Try to extract LONG-NAME (title) */
        const char *ln = strstr(obj, "LONG-NAME=\"");
        if (ln) {
            ln += 11;
            size_t i = 0;
            while (*ln && *ln != '"' && i < MAX_TITLE - 1) title[i++] = *ln++;
            title[i] = '\0';
        }

        /* Extract first THE-VALUE content as text */
        const char *tv = strstr(obj, "<THE-VALUE>");
        if (tv) {
            tv += 11;
            const char *tve = strstr(tv, "</THE-VALUE>");
            if (tve) {
                size_t tl = (size_t)(tve - tv);
                if (tl >= sizeof(text)) tl = sizeof(text) - 1;
                memcpy(text, tv, tl); text[tl] = '\0';
            }
        }

        if (id[0] == '\0')
            snprintf(id, sizeof(id), "REQ-%04d", ++idx);
        if (title[0] == '\0' && text[0] != '\0')
            strncpy(title, text, MAX_TITLE - 1);

        *ne_len_out = append_entry(new_entries, buf_sz, *ne_len_out,
                                   id, title, text, "", "", imported);
        free(obj);
        p = end_obj + 1;
    }
    free(xml);
    (void)dir;
    return 0;
}

/* Codebeamer CSV: columns differ from cfusa CSV */
static size_t import_cb_csv(FILE *f, char *new_entries, size_t buf_sz,
                              size_t ne_len, int *imported)
{
    /* Expected header: "tracker item id","summary","description","category","priority"... */
    char line[1024];
    if (!fgets(line, sizeof(line), f)) return ne_len; /* header */

    /* Map known column names */
    char cols_hdr[16][64];
    int ncols = 0;
    int col_id = -1, col_title = -1, col_text = -1;
    {
        int in_q = 0; size_t ci = 0;
        for (const char *cp = line; *cp && ncols < 16; cp++) {
            if (*cp == '"') { in_q = !in_q; continue; }
            if (*cp == ',' && !in_q) {
                cols_hdr[ncols][ci] = '\0'; ncols++; ci = 0; continue;
            }
            if (*cp == '\n' || *cp == '\r') break;
            if (ci < 63) cols_hdr[ncols][ci++] = *cp;
        }
        cols_hdr[ncols][ci] = '\0';
        if (ci) ncols++;
    }
    for (int i = 0; i < ncols; i++) {
        if (strstr(cols_hdr[i], "item id") || strstr(cols_hdr[i], "Item Id")
            || !strcmp(cols_hdr[i], "id"))
            col_id = i;
        if (strstr(cols_hdr[i], "summary") || strstr(cols_hdr[i], "Summary"))
            col_title = i;
        if (strstr(cols_hdr[i], "description") || strstr(cols_hdr[i], "Description"))
            col_text = i;
    }
    if (col_id < 0)   col_id   = 0;
    if (col_title < 0) col_title = (ncols > 1) ? 1 : 0;
    if (col_text < 0)  col_text  = (ncols > 2) ? 2 : 0;

    while (fgets(line, sizeof(line), f)) {
        char vals[16][512] = {{0}};
        int col = 0; int in_q = 0; size_t ci = 0;
        for (const char *cp = line; *cp && col < 16; cp++) {
            if (*cp == '"') { in_q = !in_q; continue; }
            if (*cp == ',' && !in_q) { vals[col][ci] = '\0'; col++; ci = 0; continue; }
            if (*cp == '\n' || *cp == '\r') break;
            if (ci < 511) vals[col][ci++] = *cp;
        }
        vals[col][ci] = '\0';
        if (!vals[col_id][0]) continue;

        char id[MAX_ID]; snprintf(id, sizeof(id), "CB-%s", vals[col_id]);
        ne_len = append_entry(new_entries, buf_sz, ne_len,
                              id, vals[col_title], vals[col_text],
                              "", "", imported);
    }
    return ne_len;
}

/* Jama CSV: columns: "ID","Name","Description","Status","Release" */
static size_t import_jama_csv(FILE *f, char *new_entries, size_t buf_sz,
                               size_t ne_len, int *imported)
{
    char line[1024];
    if (!fgets(line, sizeof(line), f)) return ne_len; /* header */

    /* Map Jama columns: ID, Name, Description */
    char cols_hdr[16][64];
    int ncols = 0;
    int col_id = -1, col_title = -1, col_text = -1;
    {
        int in_q = 0; size_t ci = 0;
        for (const char *cp = line; *cp && ncols < 16; cp++) {
            if (*cp == '"') { in_q = !in_q; continue; }
            if (*cp == ',' && !in_q) { cols_hdr[ncols][ci] = '\0'; ncols++; ci = 0; continue; }
            if (*cp == '\n' || *cp == '\r') break;
            if (ci < 63) cols_hdr[ncols][ci++] = *cp;
        }
        cols_hdr[ncols][ci] = '\0';
        if (ci) ncols++;
    }
    for (int i = 0; i < ncols; i++) {
        if (!strcmp(cols_hdr[i], "ID") || !strcmp(cols_hdr[i], "id"))
            col_id = i;
        if (!strcmp(cols_hdr[i], "Name") || !strcmp(cols_hdr[i], "name"))
            col_title = i;
        if (!strcmp(cols_hdr[i], "Description") || !strcmp(cols_hdr[i], "description"))
            col_text = i;
    }
    if (col_id < 0)    col_id    = 0;
    if (col_title < 0) col_title = (ncols > 1) ? 1 : 0;
    if (col_text < 0)  col_text  = (ncols > 2) ? 2 : 0;

    while (fgets(line, sizeof(line), f)) {
        char vals[16][512] = {{0}};
        int col = 0; int in_q = 0; size_t ci = 0;
        for (const char *cp = line; *cp && col < 16; cp++) {
            if (*cp == '"') { in_q = !in_q; continue; }
            if (*cp == ',' && !in_q) { vals[col][ci] = '\0'; col++; ci = 0; continue; }
            if (*cp == '\n' || *cp == '\r') break;
            if (ci < 511) vals[col][ci++] = *cp;
        }
        vals[col][ci] = '\0';
        if (!vals[col_id][0]) continue;

        char id[MAX_ID]; snprintf(id, sizeof(id), "JAMA-%s", vals[col_id]);
        ne_len = append_entry(new_entries, buf_sz, ne_len,
                              id, vals[col_title], vals[col_text],
                              "", "", imported);
    }
    return ne_len;
}

static void do_req_import(const char *dir, const char *input_file,
                          const char *fmt)
{
    /* Auto-detect format from extension if not specified */
    if (!fmt || !fmt[0]) {
        const char *ext = strrchr(input_file, '.');
        if (ext) {
            if (!strcmp(ext, ".xml") || !strcmp(ext, ".reqif") || !strcmp(ext, ".reqifz"))
                fmt = "doors";
            else
                fmt = "csv";
        } else {
            fmt = "csv";
        }
    }

    /* Read existing content */
    char reqs_path[512];
    cfusa_path_join(reqs_path, sizeof(reqs_path), dir, REQS_FILE);

    size_t elen = 0;
    char *existing = cfusa_read_file(reqs_path, &elen);

    char ts[32]; cfusa_timestamp_now(ts); (void)ts;

    int existing_count = 0;
    if (existing) {
        const char *p = existing;
        while ((p = strstr(p, "\"id\"")) != NULL) { existing_count++; p++; }
    }

    int imported = 0;
    char new_entries[65536] = "";
    size_t ne_len = 0;

    if (!strcmp(fmt, "doors") || !strcmp(fmt, "polarion")) {
        import_reqif(input_file, dir, new_entries, sizeof(new_entries),
                     &ne_len, &imported);
    } else if (!strcmp(fmt, "codebeamer")) {
        FILE *f = fopen(input_file, "r");
        if (!f) { perror(input_file); free(existing); return; }
        ne_len = import_cb_csv(f, new_entries, sizeof(new_entries), ne_len, &imported);
        fclose(f);
    } else if (!strcmp(fmt, "jama")) {
        FILE *f = fopen(input_file, "r");
        if (!f) { perror(input_file); free(existing); return; }
        ne_len = import_jama_csv(f, new_entries, sizeof(new_entries), ne_len, &imported);
        fclose(f);
    } else {
        /* csv (default) */
        FILE *f = fopen(input_file, "r");
        if (!f) { perror(input_file); free(existing); return; }

        char line[1024];
        if (!fgets(line, sizeof(line), f)) { fclose(f); free(existing); return; }

        while (fgets(line, sizeof(line), f)) {
            char cols[5][512] = {{0}};
            int col = 0, in_q = 0;
            size_t ci = 0;
            for (const char *p = line; *p && col < 5; p++) {
                if (*p == '"') { in_q = !in_q; continue; }
                if (*p == ',' && !in_q) { cols[col][ci] = '\0'; col++; ci = 0; continue; }
                if (*p == '\n' || *p == '\r') break;
                if (ci < 511) cols[col][ci++] = *p;
            }
            cols[col][ci] = '\0';
            if (!cols[0][0]) continue;
            ne_len = append_entry(new_entries, sizeof(new_entries), ne_len,
                                  cols[0], cols[1], cols[2], cols[3], cols[4],
                                  &imported);
        }
        fclose(f);
    }

    if (imported == 0) {
        fprintf(stderr, "cfusa req import: no valid rows found in %s\n", input_file);
        free(existing);
        return;
    }

    /* Write merged file */
    FILE *out = fopen(reqs_path, "w");
    if (!out) { perror(reqs_path); free(existing); return; }

    fprintf(out, "{\n  \"requirements\": [\n");

    /* Emit existing entries */
    if (existing) {
        const char *start = strstr(existing, "\"requirements\"");
        const char *arr   = start ? strchr(start, '[') : NULL;
        if (arr) {
            arr++;
            const char *end = strrchr(arr, ']');
            if (end) {
                /* trim trailing whitespace */
                while (end > arr && (end[-1]==' '||end[-1]=='\n'||end[-1]=='\r'))
                    end--;
                if (end > arr) {
                    fwrite(arr, 1, (size_t)(end - arr), out);
                    if (imported > 0) fprintf(out, ",\n");
                }
            }
        }
        free(existing);
    }

    fprintf(out, "%s\n  ]\n}\n", new_entries);
    fclose(out);

    printf("Imported %d requirement(s) into %s (existing: %d)\n",
           imported, reqs_path, existing_count);
}

int cmd_req(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = NULL;
    const char *subcmd = NULL;
    const char *fmt    = NULL;  /* import format */

    /* Check for subcommand first */
    if (argc >= 2 && (!strcmp(argv[1],"export") || !strcmp(argv[1],"import"))) {
        subcmd = argv[1];
        argv++; argc--;
    }

    static const struct option lo[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'F'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c; optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:F:h", lo, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'F': fmt    = optarg; break;
        case 'h':
            printf("Usage: cfusa req [--dir <path>] [REQ-ID ...]\n"
                   "       cfusa req export [--format csv|doors|polarion|codebeamer|jama] [--output <file>]\n"
                   "       cfusa req import [--format csv|doors|polarion|codebeamer|jama] <file>\n\n"
                   "List requirements and their source/test locations.\n"
                   "With no IDs, lists all requirements from .cfusa-reqs.json.\n"
                   "With IDs, filters to the named requirements.\n"
                   "export: write requirements (csv default, doors/polarion=ReqIF XML, codebeamer, jama)\n"
                   "import: read ALM export and merge into .cfusa-reqs.json\n"
                   "  Format is auto-detected from file extension if not specified.\n");
            return 0;
        default: return 2;
        }
    }

    if (subcmd && !strcmp(subcmd, "export")) {
        do_req_export(dir, output, fmt);
        return 0;
    }
    if (subcmd && !strcmp(subcmd, "import")) {
        const char *infile = (optind < argc) ? argv[optind] : NULL;
        if (!infile) {
            fprintf(stderr, "cfusa req import: requires a file argument\n");
            return 1;
        }
        do_req_import(dir, infile, fmt);
        return 0;
    }

    g_req_count = g_tag_count = 0;
    load_reqs(dir);

    static const char * const exts[] = {".c", ".h"};
    cfusa_walk_sources(dir, exts, 2, scan_file, NULL);

    /* build filter set from remaining args */
    int nfilter = argc - optind;
    char **filter = &argv[optind];

    if (g_req_count == 0) {
        /* No registry — fall back to showing all tags */
        if (g_tag_count == 0) {
            printf("No requirements found. Create %s/%s to register requirements.\n",
                   dir, REQS_FILE);
            return 1;
        }
        printf("Annotations (no %s):\n\n", REQS_FILE);
        for (int j = 0; j < g_tag_count; j++) {
            const char *k = g_tags[j].kind == KIND_IMPL ? "impl" :
                            g_tags[j].kind == KIND_TEST ? "test" : "sec-test";
            printf("  %-20s  [%s]  %s:%d\n",
                   g_tags[j].req_id, k,
                   cfusa_basename(g_tags[j].file), g_tags[j].line);
        }
        return 0;
    }

    int printed = 0, rc = 0;
    for (int i = 0; i < g_req_count; i++) {
        /* apply filter */
        if (nfilter > 0) {
            int match = 0;
            for (int k = 0; k < nfilter; k++)
                if (!strcmp(filter[k], g_reqs[i].id)) { match = 1; break; }
            if (!match) continue;
        }
        printed++;
        printf("%s  %s\n", g_reqs[i].id, g_reqs[i].title);
        if (g_reqs[i].text[0])
            printf("  %s\n", g_reqs[i].text);
        if (g_reqs[i].standard[0]) {
            printf("  Standard: %s", g_reqs[i].standard);
            if (g_reqs[i].level[0])
                printf("  Level: %s", g_reqs[i].level);
            printf("\n");
        }
        int any = 0;
        for (int j = 0; j < g_tag_count; j++) {
            if (!strcmp(g_tags[j].req_id, g_reqs[i].id)) {
                const char *k = g_tags[j].kind == KIND_IMPL ? "impl" :
                                g_tags[j].kind == KIND_TEST ? "test" : "sec-test";
                printf("  %-10s  %s:%d\n", k,
                       g_tags[j].file, g_tags[j].line);
                any = 1;
            }
        }
        if (!any) printf("  (no annotations found)\n");
        printf("\n");
    }

    if (nfilter > 0 && printed == 0) {
        for (int k = 0; k < nfilter; k++)
            fprintf(stderr, "cfusa req: requirement %s not found\n", filter[k]);
        rc = 1;
    }
    if (printed == 0 && nfilter == 0) {
        printf("No requirements in %s/%s\n", dir, REQS_FILE);
        rc = 1;
    }
    return rc;
}
