#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Finding disposition tracking.
 * Stores accepted/fixed findings in .fusa-dispositions.json.
 *
 * Subcommands: add, list, show
 * Flags align with go-FuSa: --reviewer, --action accept|fix, --ref
 */

#define DISP_FILE        ".fusa-dispositions.json"
#define DISP_FILE_LEGACY ".cfusa-dispositions.json"

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
                   const char *action, const char *reviewer, const char *ref)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    size_t len = 0;
    char *existing = cfusa_read_file(path, &len);

    int id_num = count_dispositions(path) + 1;
    char ts[32]; cfusa_timestamp_now(ts);

    char esc_rat[512], esc_rev[128], esc_rule[64], esc_ref[128];
    cfusa_str_escape_json(rationale, esc_rat,  sizeof(esc_rat));
    cfusa_str_escape_json(reviewer,  esc_rev,  sizeof(esc_rev));
    cfusa_str_escape_json(rule,      esc_rule, sizeof(esc_rule));
    cfusa_str_escape_json(ref,       esc_ref,  sizeof(esc_ref));

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); free(existing); return; }

    write_dispositions_header(f);

    if (existing) {
        char *start = strstr(existing, "\"dispositions\"");
        char *arr   = start ? strchr(start, '[') : NULL;
        if (arr) {
            arr++;
            char *end = strrchr(arr, ']');
            if (end) {
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
        "\"action\":\"%s\",\"rationale\":\"%s\","
        "\"reviewer\":\"%s\",\"ref\":\"%s\",\"createdAt\":\"%s\"}\n",
        id_num, esc_rule, action, esc_rat, esc_rev, esc_ref, ts);

    write_dispositions_footer(f);
    fclose(f);

    printf("Added DISP-%04d: rule=%s action=%s\n", id_num, rule, action);
}

static void do_list(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, DISP_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) {
        printf("No dispositions found.\n");
        return;
    }

    printf("%-12s %-18s %-8s %-20s %s\n",
           "ID", "Rule", "Action", "Reviewer", "Created");
    printf("%-12s %-18s %-8s %-20s %s\n",
           "------------", "------------------", "--------",
           "--------------------", "-------");

    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16]="", rule[32]="", action[16]="", reviewer[64]="", created[32]="";
        char *fp;
        if ((fp = strstr(p, "\"id\":")))         sscanf(fp, "\"id\":\"%15[^\"]", id);
        if ((fp = strstr(p, "\"rule\":")))        sscanf(fp, "\"rule\":\"%31[^\"]", rule);
        if ((fp = strstr(p, "\"action\":")))      sscanf(fp, "\"action\":\"%15[^\"]", action);
        if ((fp = strstr(p, "\"reviewer\":")))    sscanf(fp, "\"reviewer\":\"%63[^\"]", reviewer);
        /* accept both createdAt (new) and created (old) */
        if ((fp = strstr(p, "\"createdAt\":")))   sscanf(fp, "\"createdAt\":\"%31[^\"]", created);
        else if ((fp = strstr(p, "\"created\":"))) sscanf(fp, "\"created\":\"%31[^\"]", created);
        printf("%-12s %-18s %-8s %-20s %s\n", id, rule, action, reviewer, created);
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
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, DISP_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) { fprintf(stderr, "cfusa disposition: no %s found\n", DISP_FILE); return; }

    char *p = content;
    int found = 0;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16] = "";
        char *fp = p;
        sscanf(fp, "\"id\":\"%15[^\"]", id);
        if (!strcmp(id, disp_id)) {
            char rule[32]="", action[16]="", rat[512]="", reviewer[64]="", ref[128]="", created[32]="";
            if ((fp = strstr(p, "\"rule\":")))      sscanf(fp, "\"rule\":\"%31[^\"]", rule);
            if ((fp = strstr(p, "\"action\":")))    sscanf(fp, "\"action\":\"%15[^\"]", action);
            if ((fp = strstr(p, "\"rationale\":"))) sscanf(fp, "\"rationale\":\"%511[^\"]", rat);
            if ((fp = strstr(p, "\"reviewer\":")))  sscanf(fp, "\"reviewer\":\"%63[^\"]", reviewer);
            if ((fp = strstr(p, "\"ref\":")))       sscanf(fp, "\"ref\":\"%127[^\"]", ref);
            if ((fp = strstr(p, "\"createdAt\":"))) sscanf(fp, "\"createdAt\":\"%31[^\"]", created);
            else if ((fp = strstr(p, "\"created\":"))) sscanf(fp, "\"created\":\"%31[^\"]", created);

            printf("Disposition %s\n", id);
            printf("  Rule:        %s\n", rule);
            printf("  Action:      %s\n", action);
            printf("  Reviewer:    %s\n", reviewer);
            if (ref[0]) printf("  Ref:         %s\n", ref);
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
    const char *subcmd    = "list";
    const char *dir       = ".";
    const char *rule      = NULL;
    const char *rationale = "(no rationale provided)";
    const char *action    = "accept";
    const char *reviewer  = "unknown";
    const char *ref       = "";
    const char *show_id   = NULL;

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"rule",       required_argument, NULL, 'r'},
        {"rationale",  required_argument, NULL, 'R'},
        {"action",     required_argument, NULL, 'a'},
        {"reviewer",   required_argument, NULL, 'v'},
        {"ref",        required_argument, NULL, 'e'},
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
    while ((c = getopt_long(argc, argv, "d:r:R:a:v:e:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg; break;
        case 'r': rule     = optarg; break;
        case 'R': rationale = optarg; break;
        case 'a': action   = optarg; break;
        case 'v': reviewer = optarg; break;
        case 'e': ref      = optarg; break;
        case 'h':
            printf("Usage: cfusa disposition <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  add   --rule <ID> --action accept|fix\n"
                   "        --rationale <text> --reviewer <name> [--ref <ticket>]\n"
                   "  list  Show all dispositions\n"
                   "  show  <DISP-ID>  Show single disposition detail\n\n"
                   "Stored in .fusa-dispositions.json\n");
            return 0;
        default: return 2;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "add")) {
        if (!rule) {
            fprintf(stderr, "cfusa disposition add: --rule is required\n");
            return 1;
        }
        do_add(dir, rule, rationale, action, reviewer, ref);
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
