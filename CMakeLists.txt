cmake_minimum_required(VERSION 3.16)
project(cfusa
    VERSION 0.5.13
    DESCRIPTION "C functional safety toolkit"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---- Compiler warnings ----
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion -Wformat=2 -Wnull-dereference
        -Wstrict-prototypes
        -fstack-protector-strong
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2 -DNDEBUG)
    else()
        add_compile_options(-g -O0)
    endif()
endif()

# MISRA-C friendly: treat char as signed/unsigned consistently
add_compile_options(-funsigned-char)

# ---- Include paths ----
include_directories(include)

# ---- Core library ----
add_library(cfusa_core STATIC
    src/engine.c
    src/report.c
    src/config.c
    src/utils.c
    src/cfusa_runtime.c
)
target_include_directories(cfusa_core PUBLIC include)
set_target_properties(cfusa_core PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

# ---- Command implementations (testable library, excludes main.c) ----
add_library(cfusa_cmds STATIC
    cmd/cfusa/cmd_init.c
    cmd/cfusa/cmd_check.c
    cmd/cfusa/cmd_lint.c
    cmd/cfusa/cmd_analyze.c
    cmd/cfusa/cmd_cyber.c
    cmd/cfusa/cmd_tara.c
    cmd/cfusa/cmd_fmea.c
    cmd/cfusa/cmd_report.c
    cmd/cfusa/cmd_template.c
    cmd/cfusa/cmd_trace.c
    cmd/cfusa/cmd_verify.c
    cmd/cfusa/cmd_release.c
    cmd/cfusa/cmd_qualify.c
    cmd/cfusa/cmd_safety_case.c
    cmd/cfusa/cmd_boundary.c
    cmd/cfusa/cmd_vuln.c
    cmd/cfusa/cmd_audit_pack.c
    cmd/cfusa/cmd_diff.c
    cmd/cfusa/cmd_badge.c
    cmd/cfusa/cmd_req.c
    cmd/cfusa/cmd_fix.c
    cmd/cfusa/cmd_hooks.c
    cmd/cfusa/cmd_sign.c
    cmd/cfusa/cmd_do178.c
    cmd/cfusa/cmd_sas.c
    cmd/cfusa/cmd_sci.c
    cmd/cfusa/cmd_coverage.c
    cmd/cfusa/cmd_pr.c
    cmd/cfusa/cmd_hara.c
    cmd/cfusa/cmd_iso26262.c
    cmd/cfusa/cmd_iec61508.c
    cmd/cfusa/cmd_iec62443.c
    cmd/cfusa/cmd_misra.c
    cmd/cfusa/cmd_disposition.c
    cmd/cfusa/cmd_impact.c
    cmd/cfusa/cmd_metrics.c
    cmd/cfusa/cmd_coupling.c
    cmd/cfusa/cmd_iso21434.c
    cmd/cfusa/cmd_unece.c
    cmd/cfusa/cmd_slsa.c
    cmd/cfusa/cmd_comp.c
    cmd/cfusa/cmd_capabilities.c
    cmd/cfusa/cmd_version.c
    cmd/cfusa/cmd_safety_rules.c
)
target_link_libraries(cfusa_cmds PUBLIC cfusa_core)
target_include_directories(cfusa_cmds PUBLIC include)

# ---- cfusa binary ----
add_executable(cfusa
    cmd/cfusa/main.c
)
target_link_libraries(cfusa PRIVATE cfusa_cmds)
target_include_directories(cfusa PRIVATE include)

# ---- Tests ----
enable_testing()

# Unity test framework
add_library(unity STATIC
    vendor/unity/unity.c
)
target_include_directories(unity PUBLIC vendor/unity)

# Helper macro to register a test executable
macro(cfusa_test name)
    add_executable(${name} tests/${name}.c)
    target_link_libraries(${name} PRIVATE cfusa_cmds cfusa_core unity)
    target_include_directories(${name} PRIVATE include vendor/unity)
    add_test(NAME ${name} COMMAND ${name})
endmacro()

cfusa_test(test_engine)
cfusa_test(test_utils)
cfusa_test(test_config)
cfusa_test(test_report)
cfusa_test(test_lint_rules)
cfusa_test(test_cyber_rules)
cfusa_test(test_analyze_rules)
cfusa_test(test_hara)
cfusa_test(test_match_outside_string)
cfusa_test(test_asil_table)
cfusa_test(test_report_formats)
cfusa_test(test_impact)
cfusa_test(test_safety_commands)
cfusa_test(test_trace_req)
cfusa_test(test_cli_commands)
cfusa_test(test_lint_extended)
cfusa_test(test_cyber_extended)
cfusa_test(test_lint_rules2)
cfusa_test(test_cyber_rules2)
cfusa_test(test_analyze_rules2)
cfusa_test(test_commands2)
cfusa_test(test_config_advanced)
cfusa_test(test_utils_advanced)
cfusa_test(test_report_advanced)
cfusa_test(test_hara_advanced)
cfusa_test(test_engine_advanced)
cfusa_test(test_cyber_cy011_020)
cfusa_test(test_comp)
cfusa_test(test_fusa_rules)
cfusa_test(test_qualify)
cfusa_test(test_req_trace_cov)
cfusa_test(test_new_commands)
cfusa_test(test_safety_rules)
cfusa_test(test_runtime)

# ---- Installation ----
include(GNUInstallDirs)
install(TARGETS cfusa
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/cfusa
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# ---- Package config ----
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/cfusaConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

# ---- Summary ----
message(STATUS "cfusa ${PROJECT_VERSION}")
message(STATUS "  Build type:  ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler:  ${CMAKE_C_COMPILER}")
message(STATUS "  Install to:  ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "  Build:   cmake -B build && cmake --build build")
message(STATUS "  Test:    cmake --build build --target test")
message(STATUS "  Install: cmake --install build")
