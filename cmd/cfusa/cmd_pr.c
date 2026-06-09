#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

/*
 * Problem Report CRUD log (DO-178C §11.17 / ISO 26262-8 §8).
 * Stores PRs in .cfusa_prs.jsonl (newline-delimited JSON).
 */

#define PR_LOG_FILE ".cfusa_prs.jsonl"

static void new_pr(const char *dir, const char *title,
                   const char *severity, const char *description)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, PR_LOG_FILE);

    /* Count existing PRs to generate ID */
    int n = 0;
    FILE *rdr = fopen(path,"r");
    if (rdr) {
        char line[1024];
        while (fgets(line,sizeof(line),rdr)) n++;
        fclose(rdr);
    }

    char ts[32]; cfusa_timestamp_now(ts);

    FILE *f = fopen(path,"a");
    if (!f) { perror(path); return; }

    char esc_title[256], esc_desc[512];
    cfusa_str_escape_json(title,       esc_title, sizeof(esc_title));
    cfusa_str_escape_json(description, esc_desc,  sizeof(esc_desc));

    fprintf(f,
        "{\"id\":\"PR-%04d\",\"title\":\"%s\","
        "\"severity\":\"%s\",\"status\":\"open\","
        "\"created\":\"%s\",\"description\":\"%s\"}\n",
        n+1, esc_title, severity, ts, esc_desc);
    fclose(f);

    printf("Created PR-%04d: %s  [%s]\n", n+1, title, severity);
}

static void list_prs(const char *dir, const char *filter_status)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, PR_LOG_FILE);

    FILE *f = fopen(path,"r");
    if (!f) {
        printf("No problem reports found.\n");
        return;
    }
    printf("%-10s %-12s %-12s %-30s\n","ID","STATUS","SEVERITY","TITLE");
    printf("%-10s %-12s %-12s %-30s\n","----------","------------","------------",
           "------------------------------");
    char line[2048];
    while (fgets(line,sizeof(line),f)) {
        /* Simple field extraction */
        char id[16]="", status[16]="", sev[16]="", title[128]="";
        char *p;
        if ((p=strstr(line,"\"id\":\"")))    sscanf(p,"\"id\":\"%15[^\"]",id);
        if ((p=strstr(line,"\"status\":\"")))  sscanf(p,"\"status\":\"%15[^\"]",status);
        if ((p=strstr(line,"\"severity\":\"")))sscanf(p,"\"severity\":\"%15[^\"]",sev);
        if ((p=strstr(line,"\"title\":\"")))   sscanf(p,"\"title\":\"%127[^\"]",title);
        if (filter_status && strcmp(status,filter_status)!=0) continue;
        printf("%-10s %-12s %-12s %-30s\n",id,status,sev,title);
    }
    fclose(f);
}

static void close_pr(const char *dir, const char *pr_id, const char *resolution)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, PR_LOG_FILE);

    size_t len;
    char *content = cfusa_read_file(path, &len);
    if (!content) { fprintf(stderr,"cfusa pr: no PRs found\n"); return; }

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    FILE *out = fopen(tmp_path,"w");
    if (!out) { free(content); perror(tmp_path); return; }

    char ts[32]; cfusa_timestamp_now(ts);
    char *p = content;
    char *nl;
    int found = 0;
    while ((nl = strchr(p,'\n')) != NULL) {
        *nl = '\0';
        if (strstr(p, pr_id)) {
            /* Rewrite line with closed status */
            char id[16]="",sev[16]="",title[128]="",created[32]="",desc[256]="";
            char *fp;
            if((fp=strstr(p,"\"id\":\"")))      sscanf(fp,"\"id\":\"%15[^\"]",id);
            if((fp=strstr(p,"\"severity\":\""))) sscanf(fp,"\"severity\":\"%15[^\"]",sev);
            if((fp=strstr(p,"\"title\":\"")))    sscanf(fp,"\"title\":\"%127[^\"]",title);
            if((fp=strstr(p,"\"created\":\"")))  sscanf(fp,"\"created\":\"%31[^\"]",created);
            if((fp=strstr(p,"\"description\":\"")))sscanf(fp,"\"description\":\"%255[^\"]",desc);
            char esc_res[256];
            cfusa_str_escape_json(resolution, esc_res, sizeof(esc_res));
            fprintf(out,
                "{\"id\":\"%s\",\"title\":\"%s\",\"severity\":\"%s\","
                "\"status\":\"closed\",\"created\":\"%s\","
                "\"closed\":\"%s\",\"resolution\":\"%s\","
                "\"description\":\"%s\"}\n",
                id,title,sev,created,ts,esc_res,desc);
            found = 1;
        } else {
            fprintf(out,"%s\n",p);
        }
        p = nl+1;
    }
    fclose(out);
    free(content);

    if (!found) {
        fprintf(stderr,"cfusa pr: PR '%s' not found\n",pr_id);
        remove(tmp_path);
        return;
    }
    remove(path);
    rename(tmp_path, path);
    printf("Closed %s\n", pr_id);
}

int cmd_pr(int argc, char **argv)
{
    const char *dir        = ".";
    const char *action     = "list";  /* new | list | close */
    const char *title      = "(untitled)";
    const char *severity   = "minor"; /* minor | major | critical */
    const char *description= "";
    const char *pr_id      = NULL;
    const char *resolution = "(resolved)";
    const char *filter     = NULL;

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"new",        no_argument,       NULL, 'n'},
        {"list",       no_argument,       NULL, 'l'},
        {"close",      required_argument, NULL, 'C'},
        {"title",      required_argument, NULL, 't'},
        {"severity",   required_argument, NULL, 's'},
        {"description",required_argument, NULL, 'D'},
        {"resolution", required_argument, NULL, 'r'},
        {"status",     required_argument, NULL, 'S'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:nlC:t:s:D:r:S:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir         = optarg; break;
        case 'n': action      = "new";  break;
        case 'l': action      = "list"; break;
        case 'C': action="close"; pr_id=optarg; break;
        case 't': title       = optarg; break;
        case 's': severity    = optarg; break;
        case 'D': description = optarg; break;
        case 'r': resolution  = optarg; break;
        case 'S': filter      = optarg; break;
        case 'h':
            printf("Usage: cfusa pr [--new --title <t> --severity minor|major|critical]\n"
                   "       cfusa pr [--list] [--status open|closed]\n"
                   "       cfusa pr --close <PR-ID> [--resolution <text>]\n\n"
                   "Problem report CRUD log per DO-178C §11.17 / ISO 26262-8 §8.\n"
                   "Stored in .cfusa_prs.jsonl\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(action,"new"))
        new_pr(dir, title, severity, description);
    else if (!strcmp(action,"close"))
        close_pr(dir, pr_id, resolution);
    else
        list_prs(dir, filter);

    return 0;
}
