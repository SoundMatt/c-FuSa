#include "cfusa/asil.h"

/*
 * ISO 26262-3:2018 Table 4 ASIL determination with C0 extension.
 * Indices: [S1-S3][E1-E4][C0-C3]
 */
static const char *asil_table[3][4][4] = {
    /* S1: slight to moderate injuries */
    {
        {"QM","QM","QM","QM"},         /* E1: C0,C1,C2,C3 */
        {"QM","QM","QM","QM"},         /* E2 */
        {"QM","QM","QM","ASIL-A"},     /* E3 */
        {"QM","QM","ASIL-A","ASIL-B"}  /* E4 */
    },
    /* S2: severe/life-threatening injuries, survival probable */
    {
        {"QM","QM","QM","QM"},                 /* E1: 3,4,5,6 pts */
        {"QM","QM","QM","ASIL-A"},             /* E2: 4,5,6,7 pts */
        {"QM","QM","ASIL-A","ASIL-B"},         /* E3: 5,6,7,8 pts */
        {"QM","ASIL-A","ASIL-B","ASIL-C"}      /* E4: 6,7,8,9 pts */
    },
    /* S3: life-threatening injuries, survival uncertain / fatal */
    {
        {"QM","QM","QM","ASIL-A"},             /* E1: 4,5,6,7 pts */
        {"QM","QM","ASIL-A","ASIL-B"},         /* E2: 5,6,7,8 pts */
        {"QM","ASIL-A","ASIL-B","ASIL-C"},     /* E3: 6,7,8,9 pts */
        {"ASIL-A","ASIL-B","ASIL-C","ASIL-D"}  /* E4: 7,8,9,10 pts */
    }
};

const char *cfusa_compute_asil(int s, int e, int c)
{
    if (s < 1 || s > 3 || e < 1 || e > 4 || c < 0 || c > 3) return "QM";
    if (c == 0) return "QM";  /* ISO 26262-3:2018 4.3.5: C0 "controllable in general" -> QM regardless of S/E */
    return asil_table[s - 1][e - 1][c];
}
