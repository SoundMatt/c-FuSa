#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * Compares two cfusa JSON reports and shows introduced/resolved/unchanged findings.
 * Reads the "findings" array from each file and diffs by rule_id+file+line.
 */

#define MAX_IDS 4096
#define ID_LEN  256

typedef struct {
    char key[ID_LEN]; /* rule_id:file:line */
    char msg[512];
    char sev[16];
} report_entry_t;

static int parse_report(const char *path, report_entry_t *entries, int max)
{
    size_t len;
    char *json = cfusa_read_file(path, &len);
    if (!json) { perror(path); return -1; }

    int count = 0;
    const char *p = strstr(json, "\"findings\"");
    if (!p) { free(json); return 0; }
    p = strchr(p, '[');
    if (!p) { free(json); return 0; }
    p++;

    while (*p && *p != ']' && count < max) {
        if (*p != '{') { p++; continue; }
        char rule[32]="", file[256]="", msg[512]="", sev[16]="";
        int  line=0;
        const char *fp;
        if ((fp=strstr(p,"\"rule_id\":\"")))  sscanf(fp,"\"rule_id\":\"%31[^\"]",rule);
        if ((fp=strstr(p,"\"file\":\"")))      sscanf(fp,"\"file\":\"%255[^\"]",file);
        if ((fp=strstr(p,"\"line\":")))        sscanf(fp,"\"line\": %d",&line);
        if ((fp=strstr(p,"\"message\":\"")))   sscanf(fp,"\"message\":\"%511[^\"]",msg);
        if ((fp=strstr(p,"\"severity\":\"")))  sscanf(fp,"\"severity\":\"%15[^\"]",sev);

        snprintf(entries[count].key, ID_LEN, "%s:%s:%d", rule, file, line);
        strncpy(entries[count].msg, msg, 511);
        strncpy(entries[count].sev, sev, 15);
        count++;
        p = strchr(p, '}');
        if (p) p++;
    }
    free(json);
    return count;
}

static int find_key(const report_entry_t *arr, int n, const char *key)
{
    for (int i=0; i<n; i++)
        if (!strcmp(arr[i].key, key)) return i;
    return -1;
}

int cmd_diff(int argc, char **argv)
{
    const char *report_a = NULL;
    const char *report_b = NULL;
    const char *fmt_s    = "text";

    static const struct option long_opts[] = {
        {"format", required_argument, NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "f:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'f': fmt_s = optarg; break;
        case 'h':
            printf("Usage: cfusa diff <report-a.json> <report-b.json>\n"
                   "                  [--format text|json]\n\n"
                   "Compares two cfusa JSON reports: shows introduced, resolved,\n"
                   "and unchanged findings.\n");
            return 0;
        default: return 2;
        }
    }
    if (argc - optind < 2) {
        fprintf(stderr,"cfusa diff: two report files required\n");
        return 1;
    }
    report_a = argv[optind];
    report_b = argv[optind+1];

    static report_entry_t a_entries[MAX_IDS];
    static report_entry_t b_entries[MAX_IDS];
    int a_count = parse_report(report_a, a_entries, MAX_IDS);
    int b_count = parse_report(report_b, b_entries, MAX_IDS);
    if (a_count < 0 || b_count < 0) return 1;

    int introduced=0, resolved=0, unchanged=0;

    if (!strcmp(fmt_s,"json")) {
        char ts[32]; cfusa_timestamp_now(ts);
        printf("{\n"
               "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
               "  \"kind\": \"diff\",\n"
               "  \"tool\": \"c-FuSa\",\n"
               "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
               "  \"language\": \"c\",\n"
               "  \"generatedAt\": \"%s\",\n"
               "  \"reportA\": \"%s\",\n"
               "  \"reportB\": \"%s\",\n"
               "  \"introduced\": [", ts, report_a, report_b);
        int first=1;
        for (int i=0;i<b_count;i++) {
            if (find_key(a_entries,a_count,b_entries[i].key)<0) {
                printf("%s{\"key\":\"%s\",\"severity\":\"%s\",\"message\":\"%s\"}",
                        first?"":",",b_entries[i].key,b_entries[i].sev,b_entries[i].msg);
                first=0; introduced++;
            }
        }
        printf("],\n  \"resolved\": [");
        first=1;
        for (int i=0;i<a_count;i++) {
            if (find_key(b_entries,b_count,a_entries[i].key)<0) {
                printf("%s{\"key\":\"%s\"}",first?"":",",a_entries[i].key);
                first=0; resolved++;
            } else unchanged++;
        }
        printf("],\n  \"counts\": {\"introduced\":%d,\"resolved\":%d,\"unchanged\":%d}\n}\n",
               introduced,resolved,unchanged);
    } else {
        printf("Report diff: %s  vs  %s\n\n", report_a, report_b);
        printf("INTRODUCED findings:\n");
        for (int i=0;i<b_count;i++) {
            if (find_key(a_entries,a_count,b_entries[i].key)<0) {
                printf("  + [%s] %s  %s\n",b_entries[i].sev,b_entries[i].key,b_entries[i].msg);
                introduced++;
            }
        }
        printf("\nRESOLVED findings:\n");
        for (int i=0;i<a_count;i++) {
            if (find_key(b_entries,b_count,a_entries[i].key)<0) {
                printf("  - %s\n",a_entries[i].key);
                resolved++;
            } else unchanged++;
        }
        printf("\nSummary: %d introduced, %d resolved, %d unchanged\n",
               introduced,resolved,unchanged);
    }
    return introduced > 0 ? 1 : 0;
}
