/*
 * Tests for the c-FuSa runtime safety library (include/cfusa/runtime.h).
 * Covers Watchdog, Heartbeat, SafeState, DiagManager, FaultMonitor.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "unity.h"
#include "cfusa/runtime.h"

//cfusa:req REQ-RUNTIME001 REQ-RUNTIME002 REQ-RUNTIME003 REQ-RUNTIME004 REQ-RUNTIME005

/* ── Watchdog ─────────────────────────────────────────────────────── */

static int wd_fired_count = 0;
static void on_expiry(void *u) { (void)u; wd_fired_count++; }

void setUp(void) { wd_fired_count = 0; }
void tearDown(void) {}

//cfusa:test REQ-RUNTIME001
void test_watchdog_init_not_fired(void)
{
    cfusa_watchdog_t wd;
    cfusa_watchdog_init(&wd, 1.0, on_expiry, NULL);
    TEST_ASSERT_EQUAL_INT(0, cfusa_watchdog_fired(&wd));
}

//cfusa:test REQ-RUNTIME001
void test_watchdog_kick_resets(void)
{
    cfusa_watchdog_t wd;
    cfusa_watchdog_init(&wd, 100.0, on_expiry, NULL);
    cfusa_watchdog_kick(&wd);
    cfusa_watchdog_check(&wd); /* not overdue */
    TEST_ASSERT_EQUAL_INT(0, cfusa_watchdog_fired(&wd));
}

//cfusa:test REQ-RUNTIME001
void test_watchdog_fires_on_expiry(void)
{
    cfusa_watchdog_t wd;
    cfusa_watchdog_init(&wd, 0.0, on_expiry, NULL); /* zero timeout — immediate */
    /* Manually back-date last_kick by 2 seconds */
    wd.last_kick = time(NULL) - 2;
    cfusa_watchdog_check(&wd);
    TEST_ASSERT_EQUAL_INT(1, wd_fired_count);
    TEST_ASSERT_EQUAL_INT(1, cfusa_watchdog_fired(&wd));
}

//cfusa:test REQ-RUNTIME001
void test_watchdog_stop_prevents_fire(void)
{
    cfusa_watchdog_t wd;
    cfusa_watchdog_init(&wd, 0.0, on_expiry, NULL);
    wd.last_kick = time(NULL) - 2;
    cfusa_watchdog_stop(&wd);
    cfusa_watchdog_check(&wd);
    TEST_ASSERT_EQUAL_INT(0, wd_fired_count);
}

//cfusa:test REQ-RUNTIME001
void test_watchdog_null_safe(void)
{
    cfusa_watchdog_kick(NULL);
    cfusa_watchdog_check(NULL);
    cfusa_watchdog_stop(NULL);
    TEST_ASSERT_EQUAL_INT(0, cfusa_watchdog_fired(NULL));
}

/* ── Heartbeat ────────────────────────────────────────────────────── */

static int hb_missed_count = 0;
static int hb_last_missed = 0;
static void on_missed(int missed, void *u) { (void)u; hb_missed_count++; hb_last_missed = missed; }

//cfusa:test REQ-RUNTIME002
void test_heartbeat_init_no_missed(void)
{
    cfusa_heartbeat_t hb;
    cfusa_heartbeat_init(&hb, 1.0, on_missed, NULL);
    TEST_ASSERT_EQUAL_INT(0, cfusa_heartbeat_missed(&hb));
}

//cfusa:test REQ-RUNTIME002
void test_heartbeat_beat_resets_missed(void)
{
    cfusa_heartbeat_t hb;
    cfusa_heartbeat_init(&hb, 100.0, on_missed, NULL);
    hb.missed = 3;
    cfusa_heartbeat_beat(&hb);
    TEST_ASSERT_EQUAL_INT(0, hb.missed);
}

//cfusa:test REQ-RUNTIME002
void test_heartbeat_check_fires_callback(void)
{
    cfusa_heartbeat_t hb;
    hb_missed_count = 0;
    cfusa_heartbeat_init(&hb, 0.0, on_missed, NULL);
    hb.last_beat = time(NULL) - 2;
    cfusa_heartbeat_check(&hb);
    TEST_ASSERT_EQUAL_INT(1, hb_missed_count);
    TEST_ASSERT_EQUAL_INT(1, hb_last_missed);
}

//cfusa:test REQ-RUNTIME002
void test_heartbeat_stop_prevents_callback(void)
{
    cfusa_heartbeat_t hb;
    hb_missed_count = 0;
    cfusa_heartbeat_init(&hb, 0.0, on_missed, NULL);
    hb.last_beat = time(NULL) - 2;
    cfusa_heartbeat_stop(&hb);
    cfusa_heartbeat_check(&hb);
    TEST_ASSERT_EQUAL_INT(0, hb_missed_count);
}

//cfusa:test REQ-RUNTIME002
void test_heartbeat_null_safe(void)
{
    cfusa_heartbeat_beat(NULL);
    cfusa_heartbeat_check(NULL);
    cfusa_heartbeat_stop(NULL);
    TEST_ASSERT_EQUAL_INT(0, cfusa_heartbeat_missed(NULL));
}

/* ── SafeState ────────────────────────────────────────────────────── */

static cfusa_state_t last_from = CFUSA_STATE_OPERATIONAL;
static cfusa_state_t last_to   = CFUSA_STATE_OPERATIONAL;
static int state_cb_count = 0;
static void on_change(cfusa_state_t f, cfusa_state_t t, void *u)
{
    (void)u; last_from = f; last_to = t; state_cb_count++;
}

//cfusa:test REQ-RUNTIME003
void test_state_init_operational(void)
{
    cfusa_state_mgr_t sm;
    cfusa_state_init(&sm, NULL, NULL);
    TEST_ASSERT_EQUAL_INT(CFUSA_STATE_OPERATIONAL, cfusa_state_get(&sm));
}

//cfusa:test REQ-RUNTIME003
void test_state_transition_calls_callback(void)
{
    cfusa_state_mgr_t sm;
    state_cb_count = 0;
    cfusa_state_init(&sm, on_change, NULL);
    int rc = cfusa_state_transition(&sm, CFUSA_STATE_DEGRADED);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(1, state_cb_count);
    TEST_ASSERT_EQUAL_INT(CFUSA_STATE_OPERATIONAL, (int)last_from);
    TEST_ASSERT_EQUAL_INT(CFUSA_STATE_DEGRADED,    (int)last_to);
    TEST_ASSERT_EQUAL_INT(CFUSA_STATE_DEGRADED, cfusa_state_get(&sm));
}

//cfusa:test REQ-RUNTIME003
void test_state_emergency_stop_is_terminal(void)
{
    cfusa_state_mgr_t sm;
    cfusa_state_init(&sm, NULL, NULL);
    cfusa_state_transition(&sm, CFUSA_STATE_EMERGENCY_STOP);
    int rc = cfusa_state_transition(&sm, CFUSA_STATE_OPERATIONAL);
    TEST_ASSERT_EQUAL_INT(-1, rc);
    TEST_ASSERT_EQUAL_INT(CFUSA_STATE_EMERGENCY_STOP, cfusa_state_get(&sm));
}

//cfusa:test REQ-RUNTIME003
void test_state_noop_same_state(void)
{
    cfusa_state_mgr_t sm;
    state_cb_count = 0;
    cfusa_state_init(&sm, on_change, NULL);
    int rc = cfusa_state_transition(&sm, CFUSA_STATE_OPERATIONAL);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(0, state_cb_count); /* no callback for no-op */
}

//cfusa:test REQ-RUNTIME003
void test_state_names(void)
{
    TEST_ASSERT_NOT_NULL(cfusa_state_name(CFUSA_STATE_OPERATIONAL));
    TEST_ASSERT_NOT_NULL(cfusa_state_name(CFUSA_STATE_DEGRADED));
    TEST_ASSERT_NOT_NULL(cfusa_state_name(CFUSA_STATE_SAFE_STOP));
    TEST_ASSERT_NOT_NULL(cfusa_state_name(CFUSA_STATE_EMERGENCY_STOP));
    TEST_ASSERT_NOT_NULL(cfusa_state_name((cfusa_state_t)99));
}

/* ── DiagManager ──────────────────────────────────────────────────── */

//cfusa:test REQ-RUNTIME004
void test_diag_init_empty(void)
{
    cfusa_diag_mgr_t dm;
    cfusa_diag_init(&dm, 16);
    TEST_ASSERT_EQUAL_INT(0, cfusa_diag_count(&dm));
}

//cfusa:test REQ-RUNTIME004
void test_diag_record_and_retrieve(void)
{
    cfusa_diag_mgr_t dm;
    cfusa_diag_init(&dm, 16);
    cfusa_diag_record(&dm, "D001", CFUSA_DIAG_ERROR, "test error");
    TEST_ASSERT_EQUAL_INT(1, cfusa_diag_count(&dm));

    cfusa_diag_entry_t e;
    int rc = cfusa_diag_get(&dm, 0, &e);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_INT(CFUSA_DIAG_ERROR, e.level);
    TEST_ASSERT_EQUAL_STRING("D001", e.id);
    TEST_ASSERT_EQUAL_STRING("test error", e.message);
}

//cfusa:test REQ-RUNTIME004
void test_diag_ring_evicts_oldest(void)
{
    cfusa_diag_mgr_t dm;
    cfusa_diag_init(&dm, 3);
    cfusa_diag_record(&dm, "A", CFUSA_DIAG_INFO,    "first");
    cfusa_diag_record(&dm, "B", CFUSA_DIAG_WARNING, "second");
    cfusa_diag_record(&dm, "C", CFUSA_DIAG_ERROR,   "third");
    cfusa_diag_record(&dm, "D", CFUSA_DIAG_CRITICAL,"fourth");
    /* Count stays at max */
    TEST_ASSERT_EQUAL_INT(3, cfusa_diag_count(&dm));
    /* Oldest (first) evicted; entry 0 should be "second" */
    cfusa_diag_entry_t e;
    cfusa_diag_get(&dm, 0, &e);
    TEST_ASSERT_EQUAL_STRING("second", e.message);
}

//cfusa:test REQ-RUNTIME004
void test_diag_clear(void)
{
    cfusa_diag_mgr_t dm;
    cfusa_diag_init(&dm, 8);
    cfusa_diag_record(&dm, "X", CFUSA_DIAG_INFO, "msg");
    cfusa_diag_clear(&dm);
    TEST_ASSERT_EQUAL_INT(0, cfusa_diag_count(&dm));
}

//cfusa:test REQ-RUNTIME004
void test_diag_level_names(void)
{
    TEST_ASSERT_EQUAL_STRING("INFO",     cfusa_diag_level_name(CFUSA_DIAG_INFO));
    TEST_ASSERT_EQUAL_STRING("WARNING",  cfusa_diag_level_name(CFUSA_DIAG_WARNING));
    TEST_ASSERT_EQUAL_STRING("ERROR",    cfusa_diag_level_name(CFUSA_DIAG_ERROR));
    TEST_ASSERT_EQUAL_STRING("CRITICAL", cfusa_diag_level_name(CFUSA_DIAG_CRITICAL));
}

//cfusa:test REQ-RUNTIME004
void test_diag_get_out_of_range(void)
{
    cfusa_diag_mgr_t dm;
    cfusa_diag_init(&dm, 4);
    cfusa_diag_entry_t e;
    TEST_ASSERT_EQUAL_INT(-1, cfusa_diag_get(&dm, 0, &e));
    TEST_ASSERT_EQUAL_INT(-1, cfusa_diag_get(NULL, 0, &e));
}

/* ── FaultMonitor ────────────────────────────────────────────────── */

static int fault_fired = 0;
static int fault_count_at_fire = 0;
static char fault_id_at_fire[64];
static void on_fault(const char *id, int cnt, void *u)
{
    (void)u; fault_fired++;
    fault_count_at_fire = cnt;
    strncpy(fault_id_at_fire, id, sizeof(fault_id_at_fire) - 1);
}

//cfusa:test REQ-RUNTIME005
void test_fault_init_empty(void)
{
    cfusa_fault_monitor_t fm;
    cfusa_fault_init(&fm, NULL, NULL);
    TEST_ASSERT_EQUAL_INT(0, cfusa_fault_count(&fm, "FOO"));
}

//cfusa:test REQ-RUNTIME005
void test_fault_record_increments(void)
{
    cfusa_fault_monitor_t fm;
    cfusa_fault_init(&fm, NULL, NULL);
    cfusa_fault_record(&fm, "FAULT_A");
    cfusa_fault_record(&fm, "FAULT_A");
    TEST_ASSERT_EQUAL_INT(2, cfusa_fault_count(&fm, "FAULT_A"));
}

//cfusa:test REQ-RUNTIME005
void test_fault_threshold_fires_callback(void)
{
    cfusa_fault_monitor_t fm;
    fault_fired = 0;
    cfusa_fault_init(&fm, on_fault, NULL);
    cfusa_fault_set_threshold(&fm, "FAULT_B", 3);
    cfusa_fault_record(&fm, "FAULT_B");
    cfusa_fault_record(&fm, "FAULT_B");
    TEST_ASSERT_EQUAL_INT(0, fault_fired); /* not yet */
    cfusa_fault_record(&fm, "FAULT_B");
    TEST_ASSERT_EQUAL_INT(1, fault_fired);
    TEST_ASSERT_EQUAL_INT(3, fault_count_at_fire);
    TEST_ASSERT_EQUAL_STRING("FAULT_B", fault_id_at_fire);
}

//cfusa:test REQ-RUNTIME005
void test_fault_reset_clears_count(void)
{
    cfusa_fault_monitor_t fm;
    cfusa_fault_init(&fm, NULL, NULL);
    cfusa_fault_record(&fm, "FAULT_C");
    cfusa_fault_record(&fm, "FAULT_C");
    cfusa_fault_reset(&fm, "FAULT_C");
    TEST_ASSERT_EQUAL_INT(0, cfusa_fault_count(&fm, "FAULT_C"));
}

//cfusa:test REQ-RUNTIME005
void test_fault_unknown_returns_zero(void)
{
    cfusa_fault_monitor_t fm;
    cfusa_fault_init(&fm, NULL, NULL);
    TEST_ASSERT_EQUAL_INT(0, cfusa_fault_count(&fm, "NONEXISTENT"));
}

//cfusa:test REQ-RUNTIME005
void test_fault_null_safe(void)
{
    cfusa_fault_record(NULL, "X");
    cfusa_fault_reset(NULL, "X");
    TEST_ASSERT_EQUAL_INT(0, cfusa_fault_count(NULL, "X"));
}

int main(void)
{
    UNITY_BEGIN();
    /* Watchdog */
    RUN_TEST(test_watchdog_init_not_fired);
    RUN_TEST(test_watchdog_kick_resets);
    RUN_TEST(test_watchdog_fires_on_expiry);
    RUN_TEST(test_watchdog_stop_prevents_fire);
    RUN_TEST(test_watchdog_null_safe);
    /* Heartbeat */
    RUN_TEST(test_heartbeat_init_no_missed);
    RUN_TEST(test_heartbeat_beat_resets_missed);
    RUN_TEST(test_heartbeat_check_fires_callback);
    RUN_TEST(test_heartbeat_stop_prevents_callback);
    RUN_TEST(test_heartbeat_null_safe);
    /* SafeState */
    RUN_TEST(test_state_init_operational);
    RUN_TEST(test_state_transition_calls_callback);
    RUN_TEST(test_state_emergency_stop_is_terminal);
    RUN_TEST(test_state_noop_same_state);
    RUN_TEST(test_state_names);
    /* DiagManager */
    RUN_TEST(test_diag_init_empty);
    RUN_TEST(test_diag_record_and_retrieve);
    RUN_TEST(test_diag_ring_evicts_oldest);
    RUN_TEST(test_diag_clear);
    RUN_TEST(test_diag_level_names);
    RUN_TEST(test_diag_get_out_of_range);
    /* FaultMonitor */
    RUN_TEST(test_fault_init_empty);
    RUN_TEST(test_fault_record_increments);
    RUN_TEST(test_fault_threshold_fires_callback);
    RUN_TEST(test_fault_reset_clears_count);
    RUN_TEST(test_fault_unknown_returns_zero);
    RUN_TEST(test_fault_null_safe);
    return UNITY_END();
}
