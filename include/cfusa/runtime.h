/*
 * cfusa/runtime.h — Safety runtime components for embedded C.
 *
 * Provides five polling-based safety monitors:
 *   Watchdog     — kick-based timeout detection
 *   Heartbeat    — periodic beat health checking
 *   SafeState    — formal safe-state machine (ISO 26262-4 §6.4.6)
 *   DiagManager  — bounded ring buffer of diagnostic events
 *   FaultMonitor — per-fault occurrence counter with threshold callbacks
 *
 * All structures are zero-initialised by cfusa_*_init().
 * Call cfusa_*_check() from a scheduler tick / main loop.
 * None of these components create threads; the caller owns the loop.
 *
 * Standards: ISO 26262 ASIL-D, IEC 61508 SIL-4, DO-178C DAL-A
 */
#ifndef CFUSA_RUNTIME_H
#define CFUSA_RUNTIME_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Watchdog ──────────────────────────────────────────────────────── */
/*
 * REQ-RUNTIME001: Watchdog provides kick-based timeout monitoring.
 * The caller must call cfusa_watchdog_kick() at least once every
 * `timeout_s` seconds. cfusa_watchdog_check() fires `on_expiry` when
 * the deadline has passed without a kick.
 */
//cfusa:req REQ-RUNTIME001

typedef void (*cfusa_watchdog_cb)(void *user_data);

typedef struct {
    double           timeout_s;
    cfusa_watchdog_cb on_expiry;
    void            *user_data;
    time_t           last_kick;
    int              running;
    int              fired;
} cfusa_watchdog_t;

/* Initialise and arm the watchdog. timeout_s > 0 required. */
void cfusa_watchdog_init(cfusa_watchdog_t *wd, double timeout_s,
                          cfusa_watchdog_cb on_expiry, void *user_data);
/* Reset the timeout timer. Call from the monitored task. */
void cfusa_watchdog_kick(cfusa_watchdog_t *wd);
/* Check for expiry; fires callback if overdue. Call from scheduler tick. */
void cfusa_watchdog_check(cfusa_watchdog_t *wd);
/* Stop watchdog monitoring. */
void cfusa_watchdog_stop(cfusa_watchdog_t *wd);
/* Returns 1 if the watchdog has fired (not yet reset by init/kick). */
int  cfusa_watchdog_fired(const cfusa_watchdog_t *wd);


/* ── Heartbeat ─────────────────────────────────────────────────────── */
/*
 * REQ-RUNTIME002: Heartbeat provides periodic beat health checking.
 * The source calls cfusa_heartbeat_beat() each interval.
 * cfusa_heartbeat_check() increments the missed counter and fires
 * `on_missed(missed, user_data)` when a beat interval is overdue.
 */
//cfusa:req REQ-RUNTIME002

typedef void (*cfusa_heartbeat_cb)(int missed, void *user_data);

typedef struct {
    double             interval_s;
    cfusa_heartbeat_cb on_missed;
    void              *user_data;
    time_t             last_beat;
    int                missed;
    int                running;
} cfusa_heartbeat_t;

void cfusa_heartbeat_init(cfusa_heartbeat_t *hb, double interval_s,
                           cfusa_heartbeat_cb on_missed, void *user_data);
void cfusa_heartbeat_beat(cfusa_heartbeat_t *hb);
void cfusa_heartbeat_check(cfusa_heartbeat_t *hb);
void cfusa_heartbeat_stop(cfusa_heartbeat_t *hb);
int  cfusa_heartbeat_missed(const cfusa_heartbeat_t *hb);


/* ── SafeState ─────────────────────────────────────────────────────── */
/*
 * REQ-RUNTIME003: Formal safe-state machine (ISO 26262-4 §6.4.6).
 * States form a monotone degradation path.
 * StateEmergencyStop is terminal — no transitions out.
 */
//cfusa:req REQ-RUNTIME003

typedef enum {
    CFUSA_STATE_OPERATIONAL   = 0,
    CFUSA_STATE_DEGRADED      = 1,
    CFUSA_STATE_SAFE_STOP     = 2,
    CFUSA_STATE_EMERGENCY_STOP = 3
} cfusa_state_t;

typedef void (*cfusa_state_cb)(cfusa_state_t from, cfusa_state_t to,
                                void *user_data);

typedef struct {
    cfusa_state_t  state;
    cfusa_state_cb on_change;
    void          *user_data;
} cfusa_state_mgr_t;

void          cfusa_state_init(cfusa_state_mgr_t *sm, cfusa_state_cb on_change,
                                void *user_data);
cfusa_state_t cfusa_state_get(const cfusa_state_mgr_t *sm);
/* Returns 0 on success, -1 if transition not allowed (terminal state). */
int           cfusa_state_transition(cfusa_state_mgr_t *sm, cfusa_state_t to);
const char   *cfusa_state_name(cfusa_state_t s);


/* ── DiagManager ───────────────────────────────────────────────────── */
/*
 * REQ-RUNTIME004: Bounded ring buffer of diagnostic events.
 * Oldest entry evicted when max_entries is reached.
 */
//cfusa:req REQ-RUNTIME004

#define CFUSA_DIAG_MAX_ENTRIES 256
#define CFUSA_DIAG_ID_LEN       32
#define CFUSA_DIAG_MSG_LEN     128

typedef enum {
    CFUSA_DIAG_INFO     = 0,
    CFUSA_DIAG_WARNING  = 1,
    CFUSA_DIAG_ERROR    = 2,
    CFUSA_DIAG_CRITICAL = 3
} cfusa_diag_level_t;

typedef struct {
    char               id[CFUSA_DIAG_ID_LEN];
    cfusa_diag_level_t level;
    char               message[CFUSA_DIAG_MSG_LEN];
    time_t             timestamp;
} cfusa_diag_entry_t;

typedef struct {
    cfusa_diag_entry_t entries[CFUSA_DIAG_MAX_ENTRIES];
    int                count;
    int                head;   /* ring write head */
    int                max;
} cfusa_diag_mgr_t;

void cfusa_diag_init(cfusa_diag_mgr_t *dm, int max_entries);
void cfusa_diag_record(cfusa_diag_mgr_t *dm, const char *id,
                        cfusa_diag_level_t level, const char *message);
int  cfusa_diag_count(const cfusa_diag_mgr_t *dm);
/* Copy entry i (0-based) into out. Returns 0 on success, -1 if out of range. */
int  cfusa_diag_get(const cfusa_diag_mgr_t *dm, int i,
                     cfusa_diag_entry_t *out);
void cfusa_diag_clear(cfusa_diag_mgr_t *dm);
const char *cfusa_diag_level_name(cfusa_diag_level_t lvl);


/* ── FaultMonitor ──────────────────────────────────────────────────── */
/*
 * REQ-RUNTIME005: Per-fault occurrence counter with threshold callbacks.
 * Supports up to CFUSA_FAULT_MAX distinct fault IDs.
 */
//cfusa:req REQ-RUNTIME005

#define CFUSA_FAULT_MAX      64
#define CFUSA_FAULT_ID_LEN   32

typedef void (*cfusa_fault_cb)(const char *fault_id, int count,
                                void *user_data);

typedef struct {
    char id[CFUSA_FAULT_ID_LEN];
    int  count;
    int  threshold;
} cfusa_fault_entry_t;

typedef struct {
    cfusa_fault_entry_t faults[CFUSA_FAULT_MAX];
    int                 count;
    cfusa_fault_cb      on_fault;
    void               *user_data;
} cfusa_fault_monitor_t;

void cfusa_fault_init(cfusa_fault_monitor_t *fm, cfusa_fault_cb on_fault,
                       void *user_data);
/* Set threshold for fault_id (0 = disabled). */
void cfusa_fault_set_threshold(cfusa_fault_monitor_t *fm, const char *fault_id,
                                int threshold);
/* Increment counter; fire callback if threshold reached. */
void cfusa_fault_record(cfusa_fault_monitor_t *fm, const char *fault_id);
/* Reset counter to 0. */
void cfusa_fault_reset(cfusa_fault_monitor_t *fm, const char *fault_id);
/* Return current count (0 if unknown). */
int  cfusa_fault_count(const cfusa_fault_monitor_t *fm, const char *fault_id);

#ifdef __cplusplus
}
#endif

#endif /* CFUSA_RUNTIME_H */
