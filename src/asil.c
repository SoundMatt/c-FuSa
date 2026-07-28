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
        {"QM","QM","QM","QM"},              /* E1 */
        {"QM","QM","ASIL-A","ASIL-B"},      /* E2 */
        {"QM","ASIL-A","ASIL-B","ASIL-C"},  /* E3 */
        {"ASIL-A","ASIL-B","ASIL-C","ASIL-D"}  /* E4 */
    },
    /* S3: life-threatening injuries, survival uncertain / fatal */
    {
        {"QM","ASIL-A","ASIL-B","ASIL-C"},     /* E1 */
        {"ASIL-A","ASIL-B","ASIL-C","ASIL-D"}, /* E2 */
        {"ASIL-B","ASIL-C","ASIL-D","ASIL-D"}, /* E3 */
        {"ASIL-C","ASIL-D","ASIL-D","ASIL-D"}  /* E4 */
    }
};

const char *cfusa_compute_asil(int s, int e, int c)
{
    if (s < 1 || s > 3 || e < 1 || e > 4 || c < 0 || c > 3) return "QM";
    return asil_table[s - 1][e - 1][c];
}
