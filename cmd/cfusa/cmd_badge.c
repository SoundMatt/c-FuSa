#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

int cmd_badge(int argc, char **argv)
{
    const char *report = NULL;
    const char *output = "cfusa-badge.svg";
    const char *label  = "cfusa";

    static const struct option long_opts[] = {
        {"report", required_argument, NULL, 'r'},
        {"output", required_argument, NULL, 'o'},
        {"label",  required_argument, NULL, 'l'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "r:o:l:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'r': report = optarg; break;
        case 'o': output = optarg; break;
        case 'l': label  = optarg; break;
        case 'h':
            printf("Usage: cfusa badge [--report <report.json>] "
                   "[--output cfusa-badge.svg] [--label cfusa]\n\n"
                   "Generates an SVG status badge from a cfusa JSON report.\n");
            return 0;
        default: return 2;
        }
    }

    /* Positional argument: optional report file */
    if (optind < argc) {
        if (argc - optind > 1) {
            fprintf(stderr, "cfusa badge: too many arguments (expected at most one report file)\n");
            return 3;
        }
        report = argv[optind];
    }

    /* Read score from JSON report if provided */
    double score = 100.0;
    int errors = 0, warnings = 0;
    if (report) {
        size_t len;
        char *json = cfusa_read_file(report, &len);
        if (json) {
            const char *p;
            if ((p = strstr(json,"\"score\":"))) sscanf(p,"\"score\": %lf",&score);
            if ((p = strstr(json,"\"errors\":")))  sscanf(p,"\"errors\": %d",&errors);
            if ((p = strstr(json,"\"warnings\":")))sscanf(p,"\"warnings\": %d",&warnings);
            free(json);
        }
    }

    const char *color;
    const char *status;
    if (errors > 0)       { color="#e05d44"; status="failing"; }
    else if (warnings > 0){ color="#fe7d37"; status="warning"; }
    else                   { color="#4c1";    status="passing"; }

    char value[32];
    snprintf(value, sizeof(value), "%.0f%%  %s", score, status);

    int label_w  = (int)(strlen(label)  * 6 + 10);
    int value_w  = (int)(strlen(value) * 6 + 10);
    int total_w  = label_w + value_w;

    FILE *f = fopen(output,"w");
    if (!f) { perror(output); return 3; }

    fprintf(f,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"20\">\n"
        "  <linearGradient id=\"s\" x2=\"0\" y2=\"100%%\">\n"
        "    <stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>\n"
        "    <stop offset=\"1\" stop-opacity=\".1\"/>\n"
        "  </linearGradient>\n"
        "  <rect rx=\"3\" width=\"%d\" height=\"20\" fill=\"#555\"/>\n"
        "  <rect rx=\"3\" x=\"%d\" width=\"%d\" height=\"20\" fill=\"%s\"/>\n"
        "  <rect rx=\"3\" width=\"%d\" height=\"20\" fill=\"url(#s)\"/>\n"
        "  <g fill=\"#fff\" text-anchor=\"middle\" font-family=\"DejaVu Sans,Verdana,Geneva,sans-serif\" font-size=\"11\">\n"
        "    <text x=\"%d\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">%s</text>\n"
        "    <text x=\"%d\" y=\"14\">%s</text>\n"
        "    <text x=\"%d\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">%s</text>\n"
        "    <text x=\"%d\" y=\"14\">%s</text>\n"
        "  </g>\n"
        "</svg>\n",
        total_w,
        total_w,
        label_w, value_w, color,
        total_w,
        label_w/2, label,
        label_w/2, label,
        label_w + value_w/2, value,
        label_w + value_w/2, value);

    fclose(f);
    printf("Badge written to %s  (score=%.0f%%, status=%s)\n", output, score, status);
    return 0;
}
