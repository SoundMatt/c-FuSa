#ifndef CFUSA_COMMANDS_H
#define CFUSA_COMMANDS_H

typedef int (*cfusa_cmd_fn)(int argc, char **argv);

typedef struct {
    const char    *name;
    const char    *description;
    cfusa_cmd_fn   run;
} cfusa_command_t;

/* Forward declarations for all command entry points */
int cmd_init(int argc, char **argv);
int cmd_check(int argc, char **argv);
int cmd_lint(int argc, char **argv);
int cmd_analyze(int argc, char **argv);
int cmd_cyber(int argc, char **argv);
int cmd_tara(int argc, char **argv);
int cmd_fmea(int argc, char **argv);
int cmd_report(int argc, char **argv);
int cmd_template(int argc, char **argv);
int cmd_trace(int argc, char **argv);
int cmd_verify(int argc, char **argv);
int cmd_release(int argc, char **argv);
int cmd_qualify(int argc, char **argv);
int cmd_safety_case(int argc, char **argv);
int cmd_boundary(int argc, char **argv);
int cmd_vuln(int argc, char **argv);
int cmd_audit_pack(int argc, char **argv);
int cmd_diff(int argc, char **argv);
int cmd_badge(int argc, char **argv);
int cmd_req(int argc, char **argv);
int cmd_fix(int argc, char **argv);
int cmd_hooks(int argc, char **argv);
int cmd_sign(int argc, char **argv);
int cmd_do178(int argc, char **argv);
int cmd_sas(int argc, char **argv);
int cmd_sci(int argc, char **argv);
int cmd_coverage(int argc, char **argv);
int cmd_pr(int argc, char **argv);
int cmd_hara(int argc, char **argv);
int cmd_iso26262(int argc, char **argv);
int cmd_iec61508(int argc, char **argv);
int cmd_misra(int argc, char **argv);
int cmd_disposition(int argc, char **argv);
int cmd_impact(int argc, char **argv);
int cmd_metrics(int argc, char **argv);
int cmd_version(int argc, char **argv);
int cmd_help(int argc, char **argv);

extern const cfusa_command_t CFUSA_COMMANDS[];
extern const int             CFUSA_COMMAND_COUNT;

#endif /* CFUSA_COMMANDS_H */
