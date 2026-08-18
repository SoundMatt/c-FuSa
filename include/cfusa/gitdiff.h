#ifndef CFUSA_GITDIFF_H
#define CFUSA_GITDIFF_H

#include "cfusa/report.h"

/*
 * issue #209: `cfusa check --changed-since <ref>` scopes analysis to
 * lines actually touched since `ref` -- so adopting c-FuSa on an
 * existing codebase can gate CI on only the NEW findings a change
 * introduces, without needing #208's baseline mechanism (the two are
 * independent; a project can use either, or both).
 */

typedef struct {
    char file[CFUSA_FINDING_FILE_MAX]; /* same project-relative convention
                                           as cfusa_finding_t.file */
    int  start;
    int  end; /* inclusive */
} cfusa_changed_range_t;

typedef struct {
    cfusa_changed_range_t *items;
    int count;
    int cap;
} cfusa_changed_lines_t;

/* Runs `git -C dir diff --unified=0 <ref> -- .` with no shell (pipe() +
 * fork() + execvp("git", ...), the same safe subprocess pattern
 * cmd_impact.c already established for git invocation — argv entries
 * are passed separately, never concatenated into a shell command
 * string, so this can never be interpreted as shell syntax, CWE-78) and
 * parses the unified-diff hunk headers into a list of per-file NEW-side
 * changed line ranges.
 *
 * `ref` is validated (rejects a leading '-', which git would otherwise
 * parse as an option — the same argument-injection class cmd_impact.c's
 * validate_git_ref() already guards against — and any character outside
 * a conservative git-ref-name allowlist) before it ever reaches git.
 *
 * git diff's own paths are always relative to the repository root, not
 * to `dir` — `git -C dir rev-parse --show-prefix` supplies the
 * repo-root-to-`dir` prefix, which is stripped off every path so a
 * `--dir` pointing at a subdirectory of a larger repo still lines up
 * with cfusa_finding_t.file's `dir`-relative convention.
 *
 * Returns 1 on success (*out populated, possibly with 0 ranges — an
 * empty diff is not an error), 0 on failure (bad ref, not a git repo,
 * git not found, ...) — *out is always safe to pass to
 * cfusa_git_changed_lines_free() either way. */
int cfusa_git_changed_lines_load(const char *dir, const char *ref,
                                  cfusa_changed_lines_t *out);

/* Releases the array cfusa_git_changed_lines_load() allocated. Safe on a
 * zeroed/already-freed list. */
void cfusa_git_changed_lines_free(cfusa_changed_lines_t *list);

/* Removes every finding in `rpt` whose (file, line) does not fall
 * within any range in `changed`, then recomputes error_count/
 * warning_count/info_count/dispositioned_count from what remains.
 * Unlike disposition/baseline suppression (cfusa_report_apply_
 * dispositions(), which keeps a finding visible but excludes it from
 * the gate), this genuinely filters the report down to only what's
 * relevant to the diff — composes with, but is independent of, that
 * mechanism; apply this first if using both, so a disposition/baseline
 * lookup never has to look at a finding this already dropped.
 *
 * A finding with no line information (line <= 0) is always kept — line
 * 0 is used project-wide for directory/file-level findings that don't
 * correspond to any specific changed line. Safe to call with an empty
 * `changed` list (removes every findable-line finding — an empty diff
 * means nothing changed). */
void cfusa_report_filter_to_changed_lines(cfusa_report_t *rpt,
                                           const cfusa_changed_lines_t *changed);

#endif /* CFUSA_GITDIFF_H */
