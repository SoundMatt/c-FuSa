/* Unity Test Framework v2.5.2 — ThrowTheSwitch.org — MIT License */
#ifndef UNITY_FRAMEWORK_H
#define UNITY_FRAMEWORK_H

#include <stdint.h>
#include <stddef.h>

/* ---- Configuration ---- */
#ifndef UNITY_OUTPUT_CHAR
#  include <stdio.h>
#  define UNITY_OUTPUT_CHAR(a) putchar(a)
#endif

/* ---- Types ---- */
typedef unsigned int  UNITY_UINT;
typedef int           UNITY_INT;
typedef unsigned char UNITY_BOOL;

/* ---- State ---- */
typedef struct {
    const char *TestFile;
    const char *CurrentTestName;
    UNITY_UINT  CurrentTestLineNumber;
    UNITY_UINT  NumberOfTests;
    UNITY_UINT  TestFailures;
    UNITY_UINT  TestIgnores;
    UNITY_BOOL  CurrentTestFailed;
    UNITY_BOOL  CurrentTestIgnored;
} UNITY_STORAGE_T;

extern UNITY_STORAGE_T Unity;

/* ---- Internals ---- */
void UnityBegin(const char *filename);
int  UnityEnd(void);
void UnityPrint(const char *string);
void UnityPrintNumber(UNITY_INT number);
void UnityPrintNumberUnsigned(UNITY_UINT number);
void UnityConcludeTest(void);

void UnityAssertEqualInt(UNITY_INT expected, UNITY_INT actual,
                          const char *msg, UNITY_UINT line);
void UnityAssertEqualUInt(UNITY_UINT expected, UNITY_UINT actual,
                           const char *msg, UNITY_UINT line);
void UnityAssertEqualString(const char *expected, const char *actual,
                             const char *msg, UNITY_UINT line);
void UnityAssertNotNull(const void *pointer, const char *msg, UNITY_UINT line);
void UnityAssertNull(const void *pointer, const char *msg, UNITY_UINT line);
void UnityAssertTrue(int condition, const char *msg, UNITY_UINT line);
void UnityAssertFalse(int condition, const char *msg, UNITY_UINT line);

void UnityFail(const char *msg, UNITY_UINT line);
void UnityIgnore(const char *msg, UNITY_UINT line);

/* ---- Public Macros ---- */
#define TEST_ASSERT_TRUE(cond)   UnityAssertTrue((int)(cond),  NULL, __LINE__)
#define TEST_ASSERT_FALSE(cond)  UnityAssertFalse((int)(cond), NULL, __LINE__)

#define TEST_ASSERT_EQUAL_INT(e,a)   UnityAssertEqualInt((UNITY_INT)(e),(UNITY_INT)(a),NULL,__LINE__)
#define TEST_ASSERT_EQUAL_UINT(e,a)  UnityAssertEqualUInt((UNITY_UINT)(e),(UNITY_UINT)(a),NULL,__LINE__)
#define TEST_ASSERT_EQUAL(e,a)       TEST_ASSERT_EQUAL_INT(e,a)

#define TEST_ASSERT_EQUAL_STRING(e,a) UnityAssertEqualString((e),(a),NULL,__LINE__)

#define TEST_ASSERT_NULL(ptr)      UnityAssertNull((ptr),     NULL, __LINE__)
#define TEST_ASSERT_NOT_NULL(ptr)  UnityAssertNotNull((ptr),  NULL, __LINE__)

#define TEST_ASSERT_MESSAGE(cond, msg) UnityAssertTrue((int)(cond),(msg),__LINE__)
#define TEST_FAIL_MESSAGE(msg)         UnityFail((msg), __LINE__)
#define TEST_IGNORE_MESSAGE(msg)       UnityIgnore((msg), __LINE__)

/* ---- setUp/tearDown (define in test file; defaults provided in unity.c) ---- */
void setUp(void);
void tearDown(void);

/* ---- Test runner helpers ---- */
#define UNITY_BEGIN()   UnityBegin(__FILE__)
#define UNITY_END()     UnityEnd()

#define RUN_TEST(func) do { \
    setUp(); \
    Unity.CurrentTestName = #func; \
    Unity.CurrentTestLineNumber = __LINE__; \
    Unity.NumberOfTests++; \
    Unity.CurrentTestFailed = 0; \
    Unity.CurrentTestIgnored = 0; \
    func(); \
    tearDown(); \
    UnityConcludeTest(); \
} while(0)

#endif /* UNITY_FRAMEWORK_H */
