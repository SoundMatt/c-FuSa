/*
 * cfusa_runtime.c — Safety runtime component implementations.
 * See include/cfusa/runtime.h for API documentation.
 */
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "cfusa/runtime.h"

//cfusa:req REQ-RUNTIME001 REQ-RUNTIME002 REQ-RUNTIME003 REQ-RUNTIME004 REQ-RUNTIME005

/* ── Watchdog ──────────────────────────────────────────────────────── */

void cfusa_watchdog_init(cfusa_watchdog_t *wd, double timeout_s,
                          cfusa_watchdog_cb on_expiry, void *user_data)
{
    memset(wd, 0, sizeof(*wd));
    wd->timeout_s  = (timeout_s > 0.0) ? timeout_s : 1.0;
    wd->on_expiry  = on_expiry;
    wd->user_data  = user_data;
    wd->last_kick  = time(NULL);
    wd->running    = 1;
    wd->fired      = 0;
}

void cfusa_watchdog_kick(cfusa_watchdog_t *wd)
{
    if (!wd) return;
    wd->last_kick = time(NULL);
    wd->fired     = 0;
}

void cfusa_watchdog_check(cfusa_watchdog_t *wd)
{
    if (!wd || !wd->running || wd->fired) return;
    double elapsed = difftime(time(NULL), wd->last_kick);
    if (elapsed >= wd->timeout_s) {
        wd->fired = 1;
        if (wd->on_expiry) wd->on_expiry(wd->user_data);
    }
}

void cfusa_watchdog_stop(cfusa_watchdog_t *wd)
{
    if (wd) wd->running = 0;
}

int cfusa_watchdog_fired(const cfusa_watchdog_t *wd)
{
    return wd ? wd->fired : 0;
}


/* ── Heartbeat ─────────────────────────────────────────────────────── */

void cfusa_heartbeat_init(cfusa_heartbeat_t *hb, double interval_s,
                           cfusa_heartbeat_cb on_missed, void *user_data)
{
    memset(hb, 0, sizeof(*hb));
    hb->interval_s = (interval_s > 0.0) ? interval_s : 1.0;
    hb->on_missed  = on_missed;
    hb->user_data  = user_data;
    hb->last_beat  = time(NULL);
    hb->running    = 1;
}

void cfusa_heartbeat_beat(cfusa_heartbeat_t *hb)
{
    if (!hb) return;
    hb->last_beat = time(NULL);
    hb->missed    = 0;
}

void cfusa_heartbeat_check(cfusa_heartbeat_t *hb)
{
    if (!hb || !hb->running) return;
    double elapsed = difftime(time(NULL), hb->last_beat);
    if (elapsed >= hb->interval_s) {
        hb->missed++;
        hb->last_beat = time(NULL);
        if (hb->on_missed) hb->on_missed(hb->missed, hb->user_data);
    }
}

void cfusa_heartbeat_stop(cfusa_heartbeat_t *hb)
{
    if (hb) hb->running = 0;
}

int cfusa_heartbeat_missed(const cfusa_heartbeat_t *hb)
{
    return hb ? hb->missed : 0;
}


/* ── SafeState ─────────────────────────────────────────────────────── */

void cfusa_state_init(cfusa_state_mgr_t *sm, cfusa_state_cb on_change,
                       void *user_data)
{
    memset(sm, 0, sizeof(*sm));
    sm->state     = CFUSA_STATE_OPERATIONAL;
    sm->on_change = on_change;
    sm->user_data = user_data;
}

cfusa_state_t cfusa_state_get(const cfusa_state_mgr_t *sm)
{
    return sm ? sm->state : CFUSA_STATE_OPERATIONAL;
}

int cfusa_state_transition(cfusa_state_mgr_t *sm, cfusa_state_t to)
{
    if (!sm) return -1;
    if (sm->state == CFUSA_STATE_EMERGENCY_STOP) return -1; /* terminal */
    if (sm->state == to) return 0; /* no-op */
    cfusa_state_t from = sm->state;
    sm->state = to;
    if (sm->on_change) sm->on_change(from, to, sm->user_data);
    return 0;
}

const char *cfusa_state_name(cfusa_state_t s)
{
    switch (s) {
    case CFUSA_STATE_OPERATIONAL:    return "Operational";
    case CFUSA_STATE_DEGRADED:       return "Degraded";
    case CFUSA_STATE_SAFE_STOP:      return "SafeStop";
    case CFUSA_STATE_EMERGENCY_STOP: return "EmergencyStop";
    default:                          return "Unknown";
    }
}


/* ── DiagManager ───────────────────────────────────────────────────── */

void cfusa_diag_init(cfusa_diag_mgr_t *dm, int max_entries)
{
    memset(dm, 0, sizeof(*dm));
    if (max_entries <= 0 || max_entries > CFUSA_DIAG_MAX_ENTRIES)
        max_entries = CFUSA_DIAG_MAX_ENTRIES;
    dm->max = max_entries;
}

void cfusa_diag_record(cfusa_diag_mgr_t *dm, const char *id,
                        cfusa_diag_level_t level, const char *message)
{
    if (!dm || !id || !message) return;
    int slot = dm->head % dm->max;
    cfusa_diag_entry_t *e = &dm->entries[slot];
    memset(e, 0, sizeof(*e));
    strncpy(e->id,      id,      CFUSA_DIAG_ID_LEN  - 1);
    strncpy(e->message, message, CFUSA_DIAG_MSG_LEN - 1);
    e->level     = level;
    e->timestamp = time(NULL);
    dm->head++;
    if (dm->count < dm->max) dm->count++;
}

int cfusa_diag_count(const cfusa_diag_mgr_t *dm)
{
    return dm ? dm->count : 0;
}

int cfusa_diag_get(const cfusa_diag_mgr_t *dm, int i, cfusa_diag_entry_t *out)
{
    if (!dm || !out || i < 0 || i >= dm->count) return -1;
    int oldest = (dm->count == dm->max) ? (dm->head % dm->max) : 0;
    int slot   = (oldest + i) % dm->max;
    *out = dm->entries[slot];
    return 0;
}

void cfusa_diag_clear(cfusa_diag_mgr_t *dm)
{
    if (dm) { dm->count = 0; dm->head = 0; }
}

const char *cfusa_diag_level_name(cfusa_diag_level_t lvl)
{
    switch (lvl) {
    case CFUSA_DIAG_INFO:     return "INFO";
    case CFUSA_DIAG_WARNING:  return "WARNING";
    case CFUSA_DIAG_ERROR:    return "ERROR";
    case CFUSA_DIAG_CRITICAL: return "CRITICAL";
    default:                   return "UNKNOWN";
    }
}


/* ── FaultMonitor ──────────────────────────────────────────────────── */

void cfusa_fault_init(cfusa_fault_monitor_t *fm, cfusa_fault_cb on_fault,
                       void *user_data)
{
    memset(fm, 0, sizeof(*fm));
    fm->on_fault  = on_fault;
    fm->user_data = user_data;
}

static cfusa_fault_entry_t *fault_find(cfusa_fault_monitor_t *fm,
                                        const char *id, int create)
{
    for (int i = 0; i < fm->count; i++) {
        if (strncmp(fm->faults[i].id, id, CFUSA_FAULT_ID_LEN - 1) == 0)
            return &fm->faults[i];
    }
    if (!create || fm->count >= CFUSA_FAULT_MAX) return NULL;
    cfusa_fault_entry_t *e = &fm->faults[fm->count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->id, id, CFUSA_FAULT_ID_LEN - 1);
    return e;
}

void cfusa_fault_set_threshold(cfusa_fault_monitor_t *fm, const char *fault_id,
                                int threshold)
{
    if (!fm || !fault_id) return;
    cfusa_fault_entry_t *e = fault_find(fm, fault_id, 1);
    if (e) e->threshold = threshold;
}

void cfusa_fault_record(cfusa_fault_monitor_t *fm, const char *fault_id)
{
    if (!fm || !fault_id) return;
    cfusa_fault_entry_t *e = fault_find(fm, fault_id, 1);
    if (!e) return;
    e->count++;
    if (e->threshold > 0 && e->count >= e->threshold && fm->on_fault)
        fm->on_fault(fault_id, e->count, fm->user_data);
}

void cfusa_fault_reset(cfusa_fault_monitor_t *fm, const char *fault_id)
{
    if (!fm || !fault_id) return;
    cfusa_fault_entry_t *e = fault_find(fm, fault_id, 0);
    if (e) e->count = 0;
}

int cfusa_fault_count(const cfusa_fault_monitor_t *fm, const char *fault_id)
{
    if (!fm || !fault_id) return 0;
    for (int i = 0; i < fm->count; i++) {
        if (strncmp(fm->faults[i].id, fault_id, CFUSA_FAULT_ID_LEN - 1) == 0)
            return fm->faults[i].count;
    }
    return 0;
}
