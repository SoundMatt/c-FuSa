/*
 * Exhaustive tests for ISO 26262-3:2018 Table 4 ASIL determination.
 * All 36 valid S/E/C combinations are verified for the EXACT derived ASIL
 * band (points = S+E+C: <=6->QM, 7->A, 8->B, 9->C, 10->D), not merely exit 0.
 */
#include <stdio.h>
#include <string.h>
#include "../vendor/unity/unity.h"

/* Exercise the command path for exit-0 coverage ... */
extern int cmd_hara(int argc, char **argv);
/* ... and assert the derived value directly against the engine. */
extern const char *cfusa_compute_asil(int s, int e, int c);

void setUp(void) {}
void tearDown(void) {}

/* Helper: call cmd_hara asil and assert no error */
static int call_asil(int s, int e, int c)
{
    char ss[4], es[4], cs[4];
    snprintf(ss, sizeof(ss), "%d", s);
    snprintf(es, sizeof(es), "%d", e);
    snprintf(cs, sizeof(cs), "%d", c);
    char *argv[] = {"cfusa","asil",
                    "--severity", ss, "--exposure", es,
                    "--controllability", cs, NULL};
    return cmd_hara(8, argv);
}

/* Assert both: command exits 0, AND the derived ASIL equals `exp`. */
#define ASSERT_ASIL(s,e,c,exp) do {                                  \
    TEST_ASSERT_EQUAL(0, call_asil((s),(e),(c)));                    \
    TEST_ASSERT_EQUAL_STRING((exp), cfusa_compute_asil((s),(e),(c)));\
} while (0)

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s1(void) {
    ASSERT_ASIL(1,1,1,"QM");     ASSERT_ASIL(1,1,2,"QM");     ASSERT_ASIL(1,1,3,"QM");
    ASSERT_ASIL(1,2,1,"QM");     ASSERT_ASIL(1,2,2,"QM");     ASSERT_ASIL(1,2,3,"QM");
    ASSERT_ASIL(1,3,1,"QM");     ASSERT_ASIL(1,3,2,"QM");     ASSERT_ASIL(1,3,3,"ASIL-A");
    ASSERT_ASIL(1,4,1,"QM");     ASSERT_ASIL(1,4,2,"ASIL-A"); ASSERT_ASIL(1,4,3,"ASIL-B");
}

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s2(void) {
    ASSERT_ASIL(2,1,1,"QM");     ASSERT_ASIL(2,1,2,"QM");     ASSERT_ASIL(2,1,3,"QM");
    ASSERT_ASIL(2,2,1,"QM");     ASSERT_ASIL(2,2,2,"QM");     ASSERT_ASIL(2,2,3,"ASIL-A");
    ASSERT_ASIL(2,3,1,"QM");     ASSERT_ASIL(2,3,2,"ASIL-A"); ASSERT_ASIL(2,3,3,"ASIL-B");
    ASSERT_ASIL(2,4,1,"ASIL-A"); ASSERT_ASIL(2,4,2,"ASIL-B"); ASSERT_ASIL(2,4,3,"ASIL-C");
}

//cfusa:req REQ-HARA001
//cfusa:test REQ-HARA001
void test_asil_s3(void) {
    ASSERT_ASIL(3,1,1,"QM");     ASSERT_ASIL(3,1,2,"QM");     ASSERT_ASIL(3,1,3,"ASIL-A");
    ASSERT_ASIL(3,2,1,"QM");     ASSERT_ASIL(3,2,2,"ASIL-A"); ASSERT_ASIL(3,2,3,"ASIL-B");
    ASSERT_ASIL(3,3,1,"ASIL-A"); ASSERT_ASIL(3,3,2,"ASIL-B"); ASSERT_ASIL(3,3,3,"ASIL-C");
    ASSERT_ASIL(3,4,1,"ASIL-B"); ASSERT_ASIL(3,4,2,"ASIL-C"); ASSERT_ASIL(3,4,3,"ASIL-D");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_asil_s1);
    RUN_TEST(test_asil_s2);
    RUN_TEST(test_asil_s3);
    return UNITY_END();
}
