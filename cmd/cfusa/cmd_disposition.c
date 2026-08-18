#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include "cfusa/config.h"
#include "cfusa/utils.h"

//cfusa:req REQ-DISP-SUBCMD001 REQ-DISP-SUBCMD002 REQ-DISP-ADD001 REQ-DISP-ACTION001

/*
 * Finding disposition tracking.
 * Stores accepted/fixed findings in .fusa-dispositions.json.
 *
 * Subcommands: add, list, show
 * Flags align with go-FuSa: --reviewer, --action accept|fix, --ref
 */

#define DISP_FILE        ".fusa-dispositions.json"
#define DISP_FILE_LEGACY ".cfusa-dispositions.json"

static void write_dispositions_header(FILE *f)
{
    fprintf(f, "{\n  \"dispositions\": [\n");
}

static void write_dispositions_footer(FILE *f)
{
    fprintf(f, "  ]\n}\n");
}

static int count_dispositions(const char *path)
{
    int n = 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[2048];
    while (fgets(line, sizeof(line), f))
        if (strstr(line, "\"id\"")) n++;
    fclose(f);
    return n;
}

/* Finds the ']' that closes the array beginning at `arr` (which points to
 * the character immediately after the opening '['), tracking [ ] nesting
 * depth and skipping over any '[' or ']' that appears inside a JSON string
 * value (e.g. a rationale like "see ticket [ABC-123]"). Returns NULL if no
 * balanced closing bracket is found. Used instead of a plain strrchr(),
 * which would find the wrong ']' if one appears inside a string value. */
static const char *find_array_end(const char *arr)
{
    int depth = 1;
    int in_str = 0;
    for (const char *p = arr; *p; p++) {
        if (in_str) {
            if (*p == '\\' && p[1]) { p++; continue; }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') { in_str = 1; continue; }
        if (*p == '[') depth++;
        else if (*p == ']') { depth--; if (depth == 0) return p; }
    }
    return NULL;
}

/* Acquires an exclusive advisory lock on `dir`/.fusa-dispositions.json.lock
 * (created if absent), blocking until held. Guards the read-modify-write
 * critical section in do_add() end to end — without it, two concurrent
 * `cfusa disposition add` invocations can each read the same pre-add
 * content, then each write back their own single new entry, silently
 * losing whichever one wrote second (issue #158). Returns the lock fd (to
 * be released via disp_unlock()), or -1 on failure (a WARNING is printed;
 * callers proceed unlocked rather than blocking disposition-add forever
 * on a broken filesystem). */
static int disp_lock(const char *dir)
{
    char lockpath[512];
    cfusa_path_join(lockpath, sizeof(lockpath), dir, DISP_FILE ".lock");
    int fd = open(lockpath, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) {
        fprintf(stderr,
            "cfusa disposition add: WARNING: could not open %s (%s) — "
            "proceeding without a lock; a concurrent 'disposition add' "
            "could race with this one\n", lockpath, strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        fprintf(stderr,
            "cfusa disposition add: WARNING: could not lock %s (%s) — "
            "proceeding without a lock; a concurrent 'disposition add' "
            "could race with this one\n", lockpath, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void disp_unlock(int fd)
{
    if (fd >= 0) { flock(fd, LOCK_UN); close(fd); }
}

//cfusa:req REQ-DISP-FP001
static void do_add(const char *dir, const char *rule, const char *rationale,
                   const char *action, const char *reviewer, const char *ref,
                   const char *fingerprint)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);
    char tmppath[550];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", path, (int)getpid());

    int lockfd = disp_lock(dir);

    size_t len = 0;
    char *existing = cfusa_read_file(path, &len);

    int id_num = count_dispositions(path) + 1;
    char ts[32]; cfusa_timestamp_now(ts);

    char esc_rat[512], esc_rev[128], esc_rule[64], esc_ref[128], esc_fp[80];
    cfusa_str_escape_json(rationale,   esc_rat,  sizeof(esc_rat));
    cfusa_str_escape_json(reviewer,    esc_rev,  sizeof(esc_rev));
    cfusa_str_escape_json(rule,        esc_rule, sizeof(esc_rule));
    cfusa_str_escape_json(ref,         esc_ref,  sizeof(esc_ref));
    cfusa_str_escape_json(fingerprint, esc_fp,   sizeof(esc_fp));

    /* cfusa_fopen_write(): explicit 0600, not fopen()'s umask-dependent
     * mode (which could leave .fusa-dispositions.json world-writable).
     * Written to a temp file and rename()'d into place below so a reader
     * (or a crash mid-write) never observes a partially-written file. */
    FILE *f = cfusa_fopen_write(tmppath);
    if (!f) { perror(tmppath); free(existing); disp_unlock(lockfd); return; }

    write_dispositions_header(f);

    if (existing) {
        char *start = strstr(existing, "\"dispositions\"");
        char *arr   = start ? strchr(start, '[') : NULL;
        if (!arr) {
            /* Fallback: no "dispositions" wrapper key — the file is (or
             * was migrated from) the legacy bare-array shape
             * `[ {...}, {...} ]`, which this repo's own real
             * .cfusa-dispositions.json actually uses. Without this
             * fallback every prior entry would be silently discarded on
             * the next `disposition add` (issue #144). */
            arr = strchr(existing, '[');
        }
        if (arr) {
            arr++;
            const char *end = find_array_end(arr);
            if (end) {
                while (end > arr && (end[-1] == ' ' || end[-1] == '\n' ||
                                      end[-1] == '\r' || end[-1] == '\t'))
                    end--;
                if (end > arr) {
                    fwrite(arr, 1, (size_t)(end - arr), f);
                    fprintf(f, ",\n");
                }
            } else {
                fprintf(stderr,
                    "cfusa disposition add: WARNING: could not find the end "
                    "of the existing dispositions array in %s — prior "
                    "entries were NOT preserved; check %s before trusting "
                    "this run's suppression\n", path, path);
            }
        } else if (*existing) {
            fprintf(stderr,
                "cfusa disposition add: WARNING: %s exists but doesn't look "
                "like a dispositions array — prior entries were NOT "
                "preserved; check %s before trusting this run's "
                "suppression\n", path, path);
        }
        free(existing);
    }

    fprintf(f,
        "    {\"id\":\"DISP-%04d\",\"rule\":\"%s\","
        "\"fingerprint\":\"%s\","
        "\"action\":\"%s\",\"rationale\":\"%s\","
        "\"reviewer\":\"%s\",\"ref\":\"%s\",\"createdAt\":\"%s\"}\n",
        id_num, esc_rule, esc_fp, action, esc_rat, esc_rev, esc_ref, ts);

    write_dispositions_footer(f);
    fclose(f);

    if (rename(tmppath, path) != 0) {
        perror(path);
        remove(tmppath);
        disp_unlock(lockfd);
        return;
    }
    disp_unlock(lockfd);

    printf("Added DISP-%04d: rule=%s action=%s\n", id_num, rule, action);
    if (!fingerprint[0])
        fprintf(stderr,
            "cfusa disposition add: WARNING: no --fingerprint given — this "
            "entry is recorded as an audit note only and will NOT suppress "
            "any finding in 'cfusa check'/'cfusa lint' (rule-only scoping "
            "would be too coarse: it would exempt every future finding "
            "under rule '%s', anywhere in the codebase). Pass "
            "--fingerprint <sha256:...> (shown in 'cfusa check'/'cfusa "
            "lint' text output) to make this disposition enforceable.\n",
            rule);
}

static void do_list(const char *dir)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, DISP_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) {
        printf("No dispositions found.\n");
        return;
    }

    printf("%-12s %-18s %-8s %-20s %s\n",
           "ID", "Rule", "Action", "Reviewer", "Created");
    printf("%-12s %-18s %-8s %-20s %s\n",
           "------------", "------------------", "--------",
           "--------------------", "-------");

    char *p = content;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16]="", rule[32]="", action[16]="", reviewer[64]="", created[32]="";
        char *fp;
        if ((fp = strstr(p, "\"id\":")))         sscanf(fp, "\"id\":\"%15[^\"]", id);
        if ((fp = strstr(p, "\"rule\":")))        sscanf(fp, "\"rule\":\"%31[^\"]", rule);
        if ((fp = strstr(p, "\"action\":")))      sscanf(fp, "\"action\":\"%15[^\"]", action);
        if ((fp = strstr(p, "\"reviewer\":")))    sscanf(fp, "\"reviewer\":\"%63[^\"]", reviewer);
        /* accept both createdAt (new) and created (old) */
        if ((fp = strstr(p, "\"createdAt\":")))   sscanf(fp, "\"createdAt\":\"%31[^\"]", created);
        else if ((fp = strstr(p, "\"created\":"))) sscanf(fp, "\"created\":\"%31[^\"]", created);
        printf("%-12s %-18s %-8s %-20s %s\n", id, rule, action, reviewer, created);
        p++;
    }
    free(content);
}

static void do_show(const char *dir, const char *disp_id)
{
    char path[512];
    cfusa_path_join(path, sizeof(path), dir, DISP_FILE);

    size_t len = 0;
    char *content = cfusa_read_file(path, &len);
    if (!content) {
        char legacy[512];
        cfusa_path_join(legacy, sizeof(legacy), dir, DISP_FILE_LEGACY);
        content = cfusa_read_file(legacy, &len);
    }
    if (!content) { fprintf(stderr, "cfusa disposition: no %s found\n", DISP_FILE); return; }

    char *p = content;
    int found = 0;
    while ((p = strstr(p, "\"id\"")) != NULL) {
        char id[16] = "";
        char *fp = p;
        sscanf(fp, "\"id\":\"%15[^\"]", id);
        if (!strcmp(id, disp_id)) {
            char rule[32]="", action[16]="", rat[512]="", reviewer[64]="", ref[128]="", created[32]="", fingerprint[80]="";
            if ((fp = strstr(p, "\"rule\":")))        sscanf(fp, "\"rule\":\"%31[^\"]", rule);
            if ((fp = strstr(p, "\"fingerprint\":"))) sscanf(fp, "\"fingerprint\":\"%79[^\"]", fingerprint);
            if ((fp = strstr(p, "\"action\":")))    sscanf(fp, "\"action\":\"%15[^\"]", action);
            if ((fp = strstr(p, "\"rationale\":"))) sscanf(fp, "\"rationale\":\"%511[^\"]", rat);
            if ((fp = strstr(p, "\"reviewer\":")))  sscanf(fp, "\"reviewer\":\"%63[^\"]", reviewer);
            if ((fp = strstr(p, "\"ref\":")))       sscanf(fp, "\"ref\":\"%127[^\"]", ref);
            if ((fp = strstr(p, "\"createdAt\":"))) sscanf(fp, "\"createdAt\":\"%31[^\"]", created);
            else if ((fp = strstr(p, "\"created\":"))) sscanf(fp, "\"created\":\"%31[^\"]", created);

            printf("Disposition %s\n", id);
            printf("  Rule:        %s\n", rule);
            printf("  Fingerprint: %s\n", fingerprint[0] ? fingerprint : "(none — audit note only, does not suppress)");
            printf("  Action:      %s\n", action);
            printf("  Reviewer:    %s\n", reviewer);
            if (ref[0]) printf("  Ref:         %s\n", ref);
            printf("  Created:     %s\n", created);
            printf("  Rationale:   %s\n", rat);
            found = 1;
            break;
        }
        p++;
    }
    free(content);

    if (!found)
        fprintf(stderr, "cfusa disposition: '%s' not found\n", disp_id);
}

int cmd_disposition(int argc, char **argv)
{
    const char *subcmd    = NULL;
    const char *dir       = ".";
    const char *rule      = NULL;
    const char *rationale = NULL;
    const char *action    = "accept";
    const char *reviewer  = NULL;
    const char *ref       = "";
    const char *show_id   = NULL;
    const char *fingerprint = "";

    static const struct option long_opts[] = {
        {"dir",        required_argument, NULL, 'd'},
        {"rule",       required_argument, NULL, 'r'},
        {"rationale",  required_argument, NULL, 'R'},
        {"action",     required_argument, NULL, 'a'},
        {"reviewer",   required_argument, NULL, 'v'},
        {"ref",        required_argument, NULL, 'e'},
        {"fingerprint", required_argument, NULL, 'F'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,0,NULL,0}
    };

    if (argc >= 2 && argv[1][0] != '-') {
        subcmd = argv[1];
        argv++; argc--;
    }
    if (subcmd && !strcmp(subcmd, "show") && argc >= 2 && argv[1][0] != '-') {
        show_id = argv[1];
        argv++; argc--;
    }

    int c;
    optind = 1;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    { extern int optreset; optreset = 1; }
#elif defined(__linux__)
    optind = 0; /* glibc: reset nextchar so stale argv pointer is not followed */
#endif
    while ((c = getopt_long(argc, argv, "d:r:R:a:v:e:F:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': dir      = optarg; break;
        case 'r': rule     = optarg; break;
        case 'R': rationale = optarg; break;
        case 'a': action   = optarg; break;
        case 'v': reviewer = optarg; break;
        case 'e': ref      = optarg; break;
        case 'F': fingerprint = optarg; break;
        case 'h':
            printf("Usage: cfusa disposition <subcommand> [options]\n\n"
                   "Subcommands:\n"
                   "  add   --rule <ID> --rationale <text> --reviewer <name>\n"
                   "        [--action accept|fix|mitigate] [--ref <ticket>]\n"
                   "        [--fingerprint <sha256:...>]\n"
                   "  list  Show all dispositions\n"
                   "  show  <DISP-ID>  Show single disposition detail\n\n"
                   "Stored in .fusa-dispositions.json\n\n"
                   "--fingerprint <sha256:...> (shown in 'cfusa check'/'cfusa lint' text\n"
                   "output next to each finding) is what 'cfusa check'/'cfusa lint' match\n"
                   "on to suppress a finding's contribution to the exit-code gate for\n"
                   "accept/mitigate actions. Without it, this entry is an audit note only\n"
                   "-- --rule alone is deliberately never used to suppress, since that\n"
                   "would exempt every future finding under that rule ID, anywhere.\n");
            return 0;
        default: return 2;
        }
    }

    /* Subcommand is required */
    if (!subcmd) {
        fprintf(stderr, "cfusa disposition: subcommand required (add|list|show)\n");
        return 2;
    }

    cfusa_config_t cfg;
    cfusa_config_load(dir, &cfg);

    if (!strcmp(subcmd, "add")) {
        if (!rule) {
            fprintf(stderr, "cfusa disposition add: --rule is required\n");
            return 2;
        }
        if (!rationale) {
            fprintf(stderr, "cfusa disposition add: --rationale is required\n");
            return 2;
        }
        if (!reviewer) {
            fprintf(stderr, "cfusa disposition add: --reviewer is required\n");
            return 2;
        }
        if (strcmp(action, "accept") != 0 && strcmp(action, "fix") != 0 &&
            strcmp(action, "mitigate") != 0) {
            fprintf(stderr, "cfusa disposition add: invalid --action '%s' (accept|fix|mitigate)\n", action);
            return 2;
        }
        do_add(dir, rule, rationale, action, reviewer, ref, fingerprint);
    } else if (!strcmp(subcmd, "list")) {
        do_list(dir);
    } else if (!strcmp(subcmd, "show")) {
        if (!show_id) {
            fprintf(stderr, "cfusa disposition show: requires a DISP-ID argument\n");
            return 2;
        }
        do_show(dir, show_id);
    } else {
        fprintf(stderr, "cfusa disposition: unknown subcommand '%s' (add|list|show)\n", subcmd);
        return 2;
    }

    return 0;
}
