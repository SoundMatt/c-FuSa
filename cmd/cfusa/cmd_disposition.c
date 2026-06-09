#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Finding disposition tracking.
 * Stores accepted/waived findings in .cfusa-dispositions.json.
 *
 * Subcommands: add, list, show
 */

#define DISP_FILE ".cfusa-dispositions.json"

static void write_dispositions_header(FILE *f)
{
    fprintf(f, "{\n  \"dispositions\": [\n");
}

static void write_dispositions_footer(FILE *f)
{
    fprintf(f, "  ]\n}\n");
}

static int count_dispositions(const char *path)
{
    int n = 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[2048];
    while (fgets(line, sizeof(line), f))
        if (strstr(line, "\"id\"")) n++;
    fclose(f);
    return n;
}

static void do_add(const char *dir, const char *rule, const char *rationale,
                   const char *disposition, const char *owner)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    /* Read existing content */
    size_t len = 0;
    char *existing = cfusa_read_file(path, &len);

    int id_num = count_dispositions(path) + 1;
    char ts[32]; cfusa_timestamp_now(ts);

    char esc_rat[512], esc_owner[128], esc_rule[64];
    cfusa_str_escape_json(rationale, esc_rat,   sizeof(esc_rat));
    cfusa_str_escape_json(owner,     esc_owner,  sizeof(esc_owner));
    cfusa_str_escape_json(rule,      esc_rule,   sizeof(esc_rule));

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); free(existing); return; }

    write_dispositions_header(f);

    /* Re-emit existing entries without the closing bracket */
    if (existing) {
        char *start = strstr(existing, "\"dispositions\"");
        char *arr   = start ? strchr(start, '[') : NULL;
        if (arr) {
            arr++;
            char *end = strrchr(arr, ']');
            if (end) {
                /* trim trailing whitespace/newlines from the array body */
                while (end > arr && (end[-1] == ' ' || end[-1] == '\n' || end[-1] == '\r'))
                    end--;
                if (end > arr) {
                    fwrite(arr, 1, (size_t)(end - arr), f);
                    fprintf(f, ",\n");
                }
            }
        }
        free(existing);
    }

    fprintf(f,
        "    {\"id\":\"DISP-%04d\",\"rule\":\"%s\","
        "\"disposition\":\"%s\",\"rationale\":\"%s\","
        "\"owner\":\"%s\",\"created\":\"%s\"}\n",
        id_num, esc_rule, disposition, esc_rat, esc_owner, ts);

    write_dispositions_footer(f);
    fclose(f);

    printf("Added DISP-%04d: rule=%s disposition=%s\n", id_num, rule, disposition);
}

static void do_list(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        printf("No dispositions found.\n");
        return;
    }

    printf("%-12s %-18s %-12s %-20s %s\n",
           "ID", "Rule", "Disposition", "Owner", "Created");
    printf("%-12s %-18s %-12s %-20s %s\n",
           "------------", "------------------", "------------",
           "--------------------", "-------");

    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16]="", rule[32]="", disp[16]="", owner[64]="", created[32]="";
        char *fp;
        if ((fp = strstr(p, "\"id\":")))          sscanf(fp, "\"id\":\"%15[^\"]", id);
        if ((fp = strstr(p, "\"rule\":")))         sscanf(fp, "\"rule\":\"%31[^\"]", rule);
        if ((fp = strstr(p, "\"disposition\":")))  sscanf(fp, "\"disposition\":\"%15[^\"]", disp);
        if ((fp = strstr(p, "\"owner\":")))        sscanf(fp, "\"owner\":\"%63[^\"]", owner);
        if ((fp = strstr(p, "\"created\":")))      sscanf(fp, "\"created\":\"%31[^\"]", created);
        printf("%-12s %-18s %-12s %-20s %s\n", id, rule, disp, owner, created);
        p++;
    }
    free(content);
}

static void do_show(const char *dir, const char *disp_id)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) { fprintf(stderr, "cfusa disposition: no %s found\n", DISP_FILE); return; }

    char *p = content;
    int found = 0;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16] = "";
        char *fp = p;
        sscanf(fp, "\"id\":\"%15[^\"]", id);
        if (!strcmp(id, disp_id)) {
            char rule[32]="", disp[16]="", rat[512]="", owner[64]="", created[32]="";
            if ((fp = strstr(p, "\"rule\":")))        sscanf(fp, "\"rule\":\"%31[^\"]", rule);
            if ((fp = strstr(p, "\"disposition\":"))) sscanf(fp, "\"disposition\":\"%15[^\"]", disp);
            if ((fp = strstr(p, "\"rationale\":")))   sscanf(fp, "\"rationale\":\"%511[^\"]", rat);
            if ((fp = strstr(p, "\"owner\":")))       sscanf(fp, "\"owner\":\"%63[^\"]", owner);
            if ((fp = strstr(p, "\"created\":")))     sscanf(fp, "\"created\":\"%31[^\"]", created);

            printf("Disposition %s\n", id);
            printf("  Rule:        %s\n", rule);
            printf("  Disposition: %s\n", disp);
            printf("  Owner:       %s\n", owner);
            printf("  Created:     %s\n", created);
            printf("  Rationale:   %s\n", rat);
            found = 1;
            break;
        }
        p++;
    }
    free(content);

    if (!found)
        fprintf(stderr, "cfusa disposition: '%s' not found\n", disp_id);
}

int cmd_disposition(int argc, char **argv)
{
    const char *subcmd     = "list";
    const char *dir        = ".";
    const char *rule       = NULL;
    const char *rationale  = "(no rationale provided)";
    const char *disp_type  = "accepted"; /* accepted | waived | false-positive */
    const char *owner      = "unknown";
    const char *show_id    = NULL;

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"rule",       required_argument, NULL, 'r'},
        {"rationale",  required_argument, NULL, 'R'},
        {"disposition",required_argument, NULL, 'D'},
        {"owner",      required_argument, NULL, 'o'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    if (argc >= 2 && argv[1][0] != '-') {
        subcmd = argv[1];
        argv++; argc--;
    }
    if (!strcmp(subcmd, "show") && argc >= 2 && argv[1][0] != '-') {
        show_id = argv[1];
        argv++; argc--;
    }

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:r:R:D:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir       = optarg; break;
        case 'r': rule      = optarg; break;
        case 'R': rationale = optarg; break;
        case 'D': disp_type = optarg; break;
        case 'o': owner     = optarg; break;
        case 'h':
            printf("Usage: cfusa disposition <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  add   --rule <ID> --disposition accepted|waived|false-positive\n"
                   "        --rationale <text> --owner <name>\n"
                   "  list  Show all dispositions\n"
                   "  show  <DISP-ID>  Show single disposition detail\n\n"
                   "Stored in .cfusa-dispositions.json\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "add")) {
        if (!rule) {
            fprintf(stderr, "cfusa disposition add: --rule is required\n");
            return 1;
        }
        do_add(dir, rule, rationale, disp_type, owner);
    } else if (!strcmp(subcmd, "show")) {
        if (!show_id) {
            fprintf(stderr, "cfusa disposition show: requires a DISP-ID argument\n");
            return 1;
        }
        do_show(dir, show_id);
    } else {
        do_list(dir);
    }

    return 0;
}
