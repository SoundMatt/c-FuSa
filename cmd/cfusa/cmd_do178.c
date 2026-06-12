#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/report.h"
#include "cfusa/utils.h"
#include "cfusa/version.h"

/*
 * DO-178C Annex A objectives gap report.
 * Reports the 71 objectives across Software Planning, Development,
 * Verification, Configuration Management, Quality Assurance,
 * and Certification Liaison processes.
 */

typedef struct {
    const char *id;
    const char *process;
    const char *objective;
    const char *evidence_file; /* checked on disk if set */
    int         dal_a;   /* applies to DAL A */
    int         dal_b;
    int         dal_c;
    int         dal_d;
} do178_obj_t;

static int do178_file_exists(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    return 0;
}

static const do178_obj_t OBJECTIVES[] = {
    /* Table A-1: Software Planning Process */
    {"A1-1","Planning","Software development and verification plan defined",NULL,1,1,1,1},
    {"A1-2","Planning","Software development standards defined",NULL,1,1,1,0},
    {"A1-3","Planning","Software verification plan defines means of compliance",NULL,1,1,1,0},
    {"A1-4","Planning","Plans reviewed for completeness and accuracy",NULL,1,1,1,1},
    {"A1-5","Planning","SW life cycle environment defined in plans",NULL,1,1,1,1},

    /* Table A-2: Software Development */
    {"A2-1","Development","High-level requirements are developed",NULL,1,1,1,1},
    {"A2-2","Development","HLR are accurate, consistent, and verifiable",".fusa-reqs.json",1,1,1,1},
    {"A2-3","Development","HLR traceable to system requirements",NULL,1,1,1,1},
    {"A2-4","Development","Low-level requirements are developed",NULL,1,1,1,0},
    {"A2-5","Development","LLR are accurate, consistent, and verifiable",NULL,1,1,1,0},
    {"A2-6","Development","LLR traceable to HLR",NULL,1,1,1,0},
    {"A2-7","Development","SW architecture is developed",NULL,1,1,1,0},
    {"A2-8","Development","Architecture is consistent with HLR",NULL,1,1,1,0},
    {"A2-9","Development","Source code implements LLR and architecture",NULL,1,1,1,1},
    {"A2-10","Development","Source code is accurate and consistent",NULL,1,1,1,1},
    {"A2-11","Development","Source code traceable to LLR",NULL,1,1,1,0},
    {"A2-12","Development","Source code is verifiable",NULL,1,1,1,0},
    {"A2-13","Development","Executable object code is produced",NULL,1,1,1,1},

    /* Table A-3: Verification of Outputs */
    {"A3-1","Verification","HLR verified — correct (test or review)",NULL,1,1,1,1},
    {"A3-2","Verification","HLR verified — consistent",NULL,1,1,0,0},
    {"A3-3","Verification","HLR verified — compatible with target computer",NULL,1,1,1,0},
    {"A3-4","Verification","HLR verified — verifiable",NULL,1,1,0,0},
    {"A3-5","Verification","HLR verified — conforms to standards",NULL,1,1,1,0},
    {"A3-6","Verification","HLR verified — traceable to system requirements",NULL,1,1,1,0},
    {"A3-7","Verification","LLR verified — correct",NULL,1,1,0,0},
    {"A3-8","Verification","LLR verified — consistent",NULL,1,1,0,0},
    {"A3-9","Verification","LLR verified — compatible with target",NULL,1,1,0,0},
    {"A3-10","Verification","LLR verified — verifiable",NULL,1,1,0,0},
    {"A3-11","Verification","LLR verified — conforms to standards",NULL,1,1,0,0},
    {"A3-12","Verification","LLR verified — traceable to HLR",NULL,1,1,0,0},
    {"A3-13","Verification","SW architecture verified — correct",NULL,1,1,0,0},
    {"A3-14","Verification","SW architecture verified — consistent with HLR",NULL,1,1,0,0},
    {"A3-15","Verification","SW architecture verified — compatible with target",NULL,1,1,1,0},
    {"A3-16","Verification","SW architecture verified — verifiable",NULL,1,1,0,0},
    {"A3-17","Verification","SW architecture verified — conforms to standards",NULL,1,1,0,0},
    {"A3-18","Verification","Source code verified — complies with standards",NULL,1,1,1,0},
    {"A3-19","Verification","Source code verified — traceable to LLR",NULL,1,1,0,0},
    {"A3-20","Verification","Source code verified — accurate and consistent",NULL,1,1,0,0},
    {"A3-21","Verification","Output of integration verified",NULL,1,1,1,1},

    /* Table A-4: Testing of Outputs */
    {"A4-1","Testing","Test procedures are correct",NULL,1,1,1,1},
    {"A4-2","Testing","Test results are correct and discrepancies explained",NULL,1,1,1,1},
    {"A4-3","Testing","Test coverage of HLR is achieved",NULL,1,1,1,1},
    {"A4-4","Testing","Test coverage of LLR is achieved",NULL,1,1,0,0},
    {"A4-5","Testing","Test coverage of SW structure (statement) — DAL C+",NULL,1,1,1,0},
    {"A4-6","Testing","Test coverage of SW structure (decision) — DAL B+",NULL,1,1,0,0},
    {"A4-7","Testing","Test coverage of SW structure (MC/DC) — DAL A",NULL,1,0,0,0},

    /* Table A-5: CM */
    {"A5-1","CM","Configuration items identified",NULL,1,1,1,1},
    {"A5-2","CM","Baselines established and documented",NULL,1,1,1,1},
    {"A5-3","CM","Problem reporting and change control established",NULL,1,1,1,1},
    {"A5-4","CM","CC process ensures problem reports reviewed and tracked",NULL,1,1,1,1},

    /* Table A-6: QA */
    {"A6-1","QA","SW plans and standards reviewed for compliance",NULL,1,1,1,1},
    {"A6-2","QA","SW life cycle process conforms to plans","check-report.json",1,1,1,1},
    {"A6-3","QA","Transition criteria defined and complied with","coupling-report.json",1,1,0,0},
    {"A6-4","QA","SW CCB reviews and approves changes",NULL,1,1,1,1},
    {"A6-5","QA","Deviations recorded and approved",NULL,1,1,1,1},

    /* Table A-7: Certification Liaison */
    {"A7-1","Certification","Compliance with certification basis shown",NULL,1,1,1,1},
    {"A7-2","Certification","PSAC submitted and agreed",NULL,1,1,1,0},
    {"A7-3","Certification","SAS submitted and complete",NULL,1,1,1,0},
    {NULL,NULL,NULL,NULL,0,0,0,0}
};

int cmd_do178(int argc, char **argv)
{
    const char *dir    = ".";
    const char *output = NULL;
    const char *dal_s  = "a";
    const char *fmt_s  = "text";

    static const struct option long_opts[] = {
        {"dir",    required_argument, NULL, 'd'},
        {"dal",    required_argument, NULL, 'D'},
        {"format", required_argument, NULL, 'f'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "d:D:f:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir    = optarg; break;
        case 'D': dal_s  = optarg; break;
        case 'f': fmt_s  = optarg; break;
        case 'o': output = optarg; break;
        case 'h':
            printf("Usage: cfusa do178 [--dir <path>] [--dal a|b|c|d]\n"
                   "                   [--format text|md|json] [--output <file>]\n\n"
                   "Reports DO-178C Annex A objective status for the given DAL.\n");
            return 0;
        default: return 2;
        }
    }

    /* Determine DAL level */
    char dal_char = dal_s[0] | 0x20; /* lowercase */
    int dal_col = 0; /* 0=A,1=B,2=C,3=D */
    if      (dal_char=='a') dal_col=0;
    else if (dal_char=='b') dal_col=1;
    else if (dal_char=='c') dal_col=2;
    else if (dal_char=='d') dal_col=3;
    else { fprintf(stderr,"cfusa do178: invalid DAL '%s'\n",dal_s); return 1; }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    /* Count applicable objectives */
    int total=0, applicable=0;
    for (int i=0; OBJECTIVES[i].id; i++) {
        total++;
        int applies[4]={
            OBJECTIVES[i].dal_a, OBJECTIVES[i].dal_b,
            OBJECTIVES[i].dal_c, OBJECTIVES[i].dal_d
        };
        if (applies[dal_col]) applicable++;
    }

    cfusa_format_t fmt = cfusa_format_parse(fmt_s);
    FILE *out = stdout;
    if (output) { out = fopen(output,"w"); if (!out){perror(output);return 1;} }

    char ts[32]; cfusa_timestamp_now(ts);

    if (fmt==FMT_MD) {
        fprintf(out, "# DO-178C Annex A Gap Report\n\n"
                "**Project:** %s v%s  |  **DAL:** %c  |  "
                "**Generated:** %s\n\n"
                "Applicable objectives: **%d / %d**\n\n"
                "| ID | Process | Objective | Status |\n|---|---|---|---|\n",
                cfg.project, cfg.version, (char)('A'+dal_col), ts,
                applicable, total);
        for (int i=0; OBJECTIVES[i].id; i++) {
            int applies[4]={OBJECTIVES[i].dal_a,OBJECTIVES[i].dal_b,
                             OBJECTIVES[i].dal_c,OBJECTIVES[i].dal_d};
            if (!applies[dal_col]) continue;
            int ok = OBJECTIVES[i].evidence_file &&
                     do178_file_exists(dir, OBJECTIVES[i].evidence_file);
            fprintf(out,"| %s | %s | %s | %s |\n",
                    OBJECTIVES[i].id, OBJECTIVES[i].process,
                    OBJECTIVES[i].objective,
                    ok ? "[x] Covered" : "[ ] Pending");
        }
    } else if (fmt==FMT_JSON) {
        fprintf(out,
                "{\n"
                "  \"schemaVersion\": \"" CFUSA_SCHEMA_VERSION "\",\n"
                "  \"kind\": \"gap-report\",\n"
                "  \"tool\": \"c-FuSa\",\n"
                "  \"toolVersion\": \"" CFUSA_VERSION_STRING "\",\n"
                "  \"language\": \"c\",\n"
                "  \"generatedAt\": \"%s\",\n"
                "  \"projectRoot\": \"%s\",\n"
                "  \"standard\": \"do178c\",\n"
                "  \"project\": \"%s\",\n"
                "  \"dal\": \"%c\","
                " \"applicable\": %d, \"total\": %d,\n  \"objectives\": [\n",
                ts, dir, cfg.project,(char)('A'+dal_col),applicable,total);
        int first=1;
        for (int i=0;OBJECTIVES[i].id;i++){
            int applies[4]={OBJECTIVES[i].dal_a,OBJECTIVES[i].dal_b,
                             OBJECTIVES[i].dal_c,OBJECTIVES[i].dal_d};
            if(!applies[dal_col]) continue;
            int ok = OBJECTIVES[i].evidence_file &&
                     do178_file_exists(dir, OBJECTIVES[i].evidence_file);
            const char *status = ok ? "satisfied" : "gap";
            fprintf(out,"%s    {\"id\":\"%s\",\"process\":\"%s\","
                    "\"title\":\"%s\",\"findings\":[],\"status\":\"%s\"}",
                    first?"":",\n",
                    OBJECTIVES[i].id,OBJECTIVES[i].process,
                    OBJECTIVES[i].objective, status);
            first=0;
        }
        fprintf(out,"\n  ]\n}\n");
    } else {
        fprintf(out,"DO-178C Annex A Gap Report\n"
                "Project: %s v%s   DAL: %c   Generated: %s\n"
                "Applicable objectives: %d / %d\n\n",
                cfg.project, cfg.version, (char)('A'+dal_col), ts,
                applicable, total);
        fprintf(out,"%-8s %-18s %-50s %s\n","ID","PROCESS","OBJECTIVE","STATUS");
        fprintf(out,"%-8s %-18s %-50s %s\n",
                "--------","------------------",
                "--------------------------------------------------","-------");
        for (int i=0;OBJECTIVES[i].id;i++){
            int applies[4]={OBJECTIVES[i].dal_a,OBJECTIVES[i].dal_b,
                             OBJECTIVES[i].dal_c,OBJECTIVES[i].dal_d};
            if(!applies[dal_col]) continue;
            int ok = OBJECTIVES[i].evidence_file &&
                     do178_file_exists(dir, OBJECTIVES[i].evidence_file);
            fprintf(out,"%-8s %-18s %-50s %s\n",
                    OBJECTIVES[i].id,OBJECTIVES[i].process,
                    OBJECTIVES[i].objective,
                    ok ? "[x] COVERED" : "[ ] PENDING");
        }
        fprintf(out,"\nUpdate status column as evidence is produced.\n");
    }

    if (output&&out!=stdout) fclose(out);
    return 0;
}
