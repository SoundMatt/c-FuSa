# Contributing to c-FuSa

## Getting Started

```bash
git clone https://github.com/SoundMatt/c-FuSa.git
cd c-FuSa
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build -V
```

## Code Style

- C99 — no C11 or compiler extensions unless gated behind a macro
- Follow MISRA-C:2012 where practical (c-FuSa must pass its own lint)
- No dynamic memory in the rule engine paths
- One function per command file; keep functions under 50 lines
- No global mutable state outside `engine.c`

## Adding a Rule

1. Add the rule function and registration call to the appropriate `cmd_lint.c`, `cmd_analyze.c`, or `cmd_cyber.c`
2. Follow the existing `static int rule_XXXX(...)` pattern
3. Add the rule to the static rule table and to `XXXX_register_rules()`
4. Document the rule ID, standard reference, and description
5. Add a test in `tests/test_rules.c`

## Adding a Command

1. Create `cmd/cfusa/cmd_<name>.c` with `int cmd_<name>(int argc, char **argv)`
2. Add the declaration to `include/cfusa/commands.h`
3. Add the entry to `CFUSA_COMMANDS[]` in `cmd/cfusa/main.c`
4. Add the source file to `CMakeLists.txt`
5. Add docs to `docs/commands/<name>.md`

## Tests

All new code must have tests using the Unity framework in `tests/`.

```bash
cmake --build build && ctest --test-dir build -V
```

## Commit Style

```
<type>(<scope>): <short summary>

Types: feat, fix, docs, test, refactor, build, ci
```

## Pull Requests

- Run `cfusa check --dir .` before opening a PR
- All CI checks must pass
- SARIF findings in the Security tab must be reviewed

## License

All contributions are made under the [Mozilla Public License 2.0](LICENSE).
