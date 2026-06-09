/* Unity Test Framework v2.5.2 — ThrowTheSwitch.org — MIT License */
#include "unity.h"
#include <string.h>
#include <stdio.h>

UNITY_STORAGE_T Unity;

void UnityBegin(const char *filename)
{
    Unity.TestFile           = filename;
    Unity.CurrentTestName    = NULL;
    Unity.NumberOfTests      = 0;
    Unity.TestFailures       = 0;
    Unity.TestIgnores        = 0;
    Unity.CurrentTestFailed  = 0;
    Unity.CurrentTestIgnored = 0;
}

int UnityEnd(void)
{
    printf("\n%u Tests  %u Failures  %u Ignored\n",
           Unity.NumberOfTests, Unity.TestFailures, Unity.TestIgnores);
    if (Unity.TestFailures == 0)
        puts("OK");
    else
        puts("FAIL");
    return (int)Unity.TestFailures;
}

void UnityPrint(const char *string)
{
    const char *p = string;
    if (!p) { fputs("<null>", stdout); return; }
    while (*p) UNITY_OUTPUT_CHAR(*p++);
}

void UnityPrintNumber(UNITY_INT number)
{
    printf("%d", number);
}

void UnityPrintNumberUnsigned(UNITY_UINT number)
{
    printf("%u", number);
}

static void unity_fail_msg(const char *msg, UNITY_UINT line)
{
    printf("%s:%u:%s:FAIL",
           Unity.TestFile ? Unity.TestFile : "?",
           line,
           Unity.CurrentTestName ? Unity.CurrentTestName : "?");
    if (msg) { printf(": %s", msg); }
    putchar('\n');
    Unity.CurrentTestFailed = 1;
}

void UnityConcludeTest(void)
{
    if (Unity.CurrentTestIgnored) {
        Unity.TestIgnores++;
        printf("%s:%s:IGNORE\n",
               Unity.TestFile ? Unity.TestFile : "?",
               Unity.CurrentTestName ? Unity.CurrentTestName : "?");
    } else if (!Unity.CurrentTestFailed) {
        printf("%s:%s:PASS\n",
               Unity.TestFile ? Unity.TestFile : "?",
               Unity.CurrentTestName ? Unity.CurrentTestName : "?");
    } else {
        Unity.TestFailures++;
    }
}

void UnityFail(const char *msg, UNITY_UINT line)
{
    unity_fail_msg(msg, line);
}

void UnityIgnore(const char *msg, UNITY_UINT line)
{
    (void)line;
    (void)msg;
    Unity.CurrentTestIgnored = 1;
}

void UnityAssertTrue(int condition, const char *msg, UNITY_UINT line)
{
    if (!condition)
        unity_fail_msg(msg ? msg : "Expected TRUE", line);
}

void UnityAssertFalse(int condition, const char *msg, UNITY_UINT line)
{
    if (condition)
        unity_fail_msg(msg ? msg : "Expected FALSE", line);
}

void UnityAssertEqualInt(UNITY_INT expected, UNITY_INT actual,
                          const char *msg, UNITY_UINT line)
{
    if (expected != actual) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s  Expected %d Was %d",
                 msg ? msg : "", expected, actual);
        unity_fail_msg(buf, line);
    }
}

void UnityAssertEqualUInt(UNITY_UINT expected, UNITY_UINT actual,
                           const char *msg, UNITY_UINT line)
{
    if (expected != actual) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s  Expected %u Was %u",
                 msg ? msg : "", expected, actual);
        unity_fail_msg(buf, line);
    }
}

void UnityAssertEqualString(const char *expected, const char *actual,
                             const char *msg, UNITY_UINT line)
{
    if (expected == NULL && actual == NULL) return;
    if (expected == NULL || actual == NULL ||
        strcmp(expected, actual) != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s  Expected \"%s\" Was \"%s\"",
                 msg ? msg : "",
                 expected ? expected : "<null>",
                 actual   ? actual   : "<null>");
        unity_fail_msg(buf, line);
    }
}

void UnityAssertNotNull(const void *pointer, const char *msg, UNITY_UINT line)
{
    if (pointer == NULL)
        unity_fail_msg(msg ? msg : "Expected non-NULL", line);
}

void UnityAssertNull(const void *pointer, const char *msg, UNITY_UINT line)
{
    if (pointer != NULL)
        unity_fail_msg(msg ? msg : "Expected NULL", line);
}
