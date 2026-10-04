# Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
# SPDX-License-Identifier: BSD-4-Clause
#
# Fuzzing targets, included from the root CMakeLists (guarded by SPIPROXY_FUZZ)
# after the executables so the harness inherits the project-wide compile
# flags. The SPIPROXY_FUZZ[_COVERAGE] options and their global build-flag
# interactions (SPIPROXY_STATIC exclusion, no _FORTIFY_SOURCE under fuzz) stay
# in the root file, which must evaluate them early. Paths are relative to the
# project root -- include() keeps CMAKE_CURRENT_SOURCE_DIR pointed there.

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "Fuzzing (-fsanitize=fuzzer) is only available with Clang. "
        "Reconfigure your project with CMAKE_C_COMPILER=clang")
endif()

# Harnesses (SPIPROXY_FUZZ drops main + stubs hardware). fuzz_msg and fuzz_frame
# #include the daemon sources -- the request handlers via the scheduler, and the
# transport parse (client_frame); fuzz_resp #includes spiproxy_cli.c -- the CLI
# response parse (parse_resp). Need clang for -fsanitize=fuzzer.
foreach(harness fuzz_msg fuzz_frame fuzz_resp)
    add_executable(${harness} fuzz/${harness}.c log.c parse.c)
    add_dependencies(${harness} gen_lan80xx_regs)   # generated header (build dir)
    target_include_directories(${harness} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_definitions(${harness} PRIVATE SPIPROXY_FUZZ)
    target_compile_options(${harness} PRIVATE
        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
        -fno-omit-frame-pointer -Wno-unused-function)
    target_link_options(${harness} PRIVATE
        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
    set_target_properties(${harness} PROPERTIES FOLDER fuzz)
endforeach()

# Optional: clang source-based coverage. `fuzz_coverage` replays the corpus
# through the harness and prints an llvm-cov report for the parser.
if(SPIPROXY_FUZZ_COVERAGE)
    find_program(LLVM_PROFDATA NAMES llvm-profdata llvm-profdata-21
                 llvm-profdata-20 llvm-profdata-19 llvm-profdata-18)
    find_program(LLVM_COV NAMES llvm-cov llvm-cov-21 llvm-cov-20
                 llvm-cov-19 llvm-cov-18)
    if(NOT LLVM_PROFDATA OR NOT LLVM_COV)
        message(FATAL_ERROR
            "SPIPROXY_FUZZ_COVERAGE needs llvm-profdata and llvm-cov")
    endif()
    target_compile_options(fuzz_msg PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(fuzz_msg PRIVATE -fprofile-instr-generate)
    set(SPIPROXY_FUZZ_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus"
        CACHE PATH "Corpus directory to replay for the coverage report")
    # Replay the corpus once into fuzz_msg.profdata, shared by the reports.
    add_custom_target(fuzz_profdata
        # seed corpus is generated, not committed
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/gen_seeds.py
                ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus
        COMMAND ${CMAKE_COMMAND} -E env
                ASAN_OPTIONS=symbolize=0 UBSAN_OPTIONS=symbolize=0
                LLVM_PROFILE_FILE=fuzz_msg.profraw
                $<TARGET_FILE:fuzz_msg> -runs=0 -print_funcs=0
                "${SPIPROXY_FUZZ_CORPUS}"
        COMMAND ${LLVM_PROFDATA} merge -sparse fuzz_msg.profraw
                -o fuzz_msg.profdata
        DEPENDS fuzz_msg
        BYPRODUCTS fuzz_msg.profraw fuzz_msg.profdata
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        USES_TERMINAL VERBATIM
        COMMENT "Replaying ${SPIPROXY_FUZZ_CORPUS} -> fuzz_msg.profdata")

    # Terminal summary.
    add_custom_target(fuzz_coverage
        COMMAND ${LLVM_COV} report $<TARGET_FILE:fuzz_msg>
                -instr-profile=fuzz_msg.profdata
                "${CMAKE_CURRENT_SOURCE_DIR}/lan80xx_spid.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/ts_fifo.c"
        DEPENDS fuzz_profdata
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        USES_TERMINAL VERBATIM
        COMMENT "llvm-cov summary for the daemon sources")

    # Annotated line-by-line HTML.
    add_custom_target(fuzz_coverage_html
        COMMAND ${LLVM_COV} show $<TARGET_FILE:fuzz_msg>
                -instr-profile=fuzz_msg.profdata -format=html
                -output-dir=${CMAKE_CURRENT_BINARY_DIR}/coverage-html
                "${CMAKE_CURRENT_SOURCE_DIR}/lan80xx_spid.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/ts_fifo.c"
        COMMAND ${CMAKE_COMMAND} -E echo
                "HTML report: ${CMAKE_CURRENT_BINARY_DIR}/coverage-html/index.html"
        DEPENDS fuzz_profdata
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        USES_TERMINAL VERBATIM
        COMMENT "llvm-cov HTML report for the daemon sources")
    set_target_properties(fuzz_profdata fuzz_coverage fuzz_coverage_html
                          PROPERTIES FOLDER fuzz)
endif()
