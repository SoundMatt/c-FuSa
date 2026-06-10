#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/* Software Accomplishment Summary (DO-178C §11.20) */

typedef struct {
    const char *id;
    const char *description;
    const char *evidence_type;
} sas_item_t;

static const sas_item_t SAS_ITEMS[] = {
    {"SAS-01", "System overview and SW functions",                      "Document"},
    {"SAS-02", "Software level (DAL)",                                  "Document"},
    {"SAS-03", "Software development environment",                      "Tool qualification records"},
    {"SAS-04", "SW development process summary",                        "Process evidence"},
    {"SAS-05", "SW verification process summary",                       "Test evidence"},
    {"SAS-06", "SW configuration management process summary",           "CM records"},
    {"SAS-07", "SW quality assurance process summary",                  "QA records"},
    {"SAS-08", "Compliance statement for each SW life cycle data item",  "Traceability matrix"},
    {"SAS-09", "Problem reports status",                                 "PR log"},
    {"SAS-10", "Changes and their classification",                       "Change log"},
    {"SAS-11", "Deviations from plans/standards",                        "Deviation records"},
    {"SAS-12", "Unresolved anomalies with justification",                "Anomaly log"},
    {"SAS-13", "SW verification results",                                "Test reports"},
    {"SAS-14", "Structural coverage results",                            "Coverage report"},
    {"SAS-15", "Additional considerations (partitioning, etc.)",         "Analysis report"},
    {"SAS-16", "Summary of test environment qualification",              "Tool qual record"},
    {"SAS-17", "PSAC compliance",                                        "PSAC cross-reference"},
    {"SAS-18", "PHAC data (if applicable)",                              "PHAC document"},
    {"SAS-19", "COTS components used",                                   "COTS qualification data"},
    {"SAS-20", "SW configuration index",                                 "SCI (cfusa sci)"},
    {NULL, NULL, NULL}
};

int cmd_sas(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = "sas.md";
    const char *fmt_s  = "md";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"output", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'f'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:o:f:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'o': output = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'h':
            printf("Usage: cfusa sas [--dir <path>] [--output sas.md]\n"
                   "                 [--format md|text|json]\n\n"
                   "Generates a Software Accomplishment Summary skeleton (DO-178C §11.20).\n");
            return 0;
        default: return 1;
        }
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    char out_path[512];
    if (output[0]=='/') strncpy(out_path,output,sizeof(out_path)-1);
    else cfusa_path_join(out_path,sizeof(out_path),dir,output);

    FILE *f = fopen(out_path,"w");
    if (!f) { perror(out_path); return 1; }

    char ts[32]; cfusa_timestamp_now(ts);

    if (!strcmp(fmt_s,"json")) {
        fprintf(f,
                "{\n"
                "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
                "  \"kind\": \"sas\",\n"
                "  \"tool\": \"c-FuSa\",\n"
                "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
                "  \"language\": \"c\",\n"
                "  \"generatedAt\": \"%s\",\n"
                "  \"project\": \"%s\",\n"
                "  \"version\": \"%s\",\n"
                "  \"items\": [\n",
                ts, cfg.project, cfg.version);
        for (int i=0; SAS_ITEMS[i].id; i++)
            fprintf(f,"    {\"id\": \"%s\", \"description\": \"%s\","
                    " \"evidence_type\": \"%s\", \"status\": \"pending\"}%s\n",
                    SAS_ITEMS[i].id, SAS_ITEMS[i].description,
                    SAS_ITEMS[i].evidence_type,
                    SAS_ITEMS[i+1].id ? "," : "");
        fprintf(f,"  ]\n}\n");
    } else if (!strcmp(fmt_s,"text")) {
        fprintf(f,"Software Accomplishment Summary (SAS)\n"
                "Project: %s v%s   Generated: %s\nStandard: DO-178C §11.20\n\n",
                cfg.project, cfg.version, ts);
        for (int i=0;SAS_ITEMS[i].id;i++)
            fprintf(f,"%-8s [ ] PENDING  %-50s  Evidence: %s\n",
                    SAS_ITEMS[i].id, SAS_ITEMS[i].description,
                    SAS_ITEMS[i].evidence_type);
    } else {
        /* Markdown default */
        fprintf(f,"# Software Accomplishment Summary (SAS)\n\n"
                "**Project:** %s v%s  |  **Generated:** %s  |  **Standard:** DO-178C §11.20\n\n"
                "| ID | Description | Evidence Type | Status |\n|---|---|---|---|\n",
                cfg.project, cfg.version, ts);
        for (int i=0;SAS_ITEMS[i].id;i++)
            fprintf(f,"| %s | %s | %s | [ ] Pending |\n",
                    SAS_ITEMS[i].id, SAS_ITEMS[i].description,
                    SAS_ITEMS[i].evidence_type);
        fprintf(f,"\n---\n_Approved by: [name / date]_\n");
    }

    fclose(f);
    printf("SAS written to %s\n", out_path);
    return 0;
}
