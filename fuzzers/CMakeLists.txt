set(FUZZERS aflgo hawkeye dafl beacon selectfuzz halo idfuzz)

foreach(FUZZER ${FUZZERS})
  # Reset feature flags
  unset(EXTEND_CALLGRAPH)
  unset(USE_HAWKEYE_DISTANCE)
  unset(TRACE_FUNCTION_DISTANCE)
  unset(DAFL_MODE)
  unset(BEACON_ENTRY_PRUNING)
  unset(BEACON_CLI_MODE)
  unset(SELECTFUZZ_MODE)
  unset(SELECTFUZZ_CLI_MODE)
  unset(HALO_CLI_MODE)
  unset(HALO_MODE)
  unset(IDFUZZ_MODE)
  unset(IDFUZZ_CLI_MODE)

  add_subdirectory(${FUZZER})

  # Variables set by add_subdirectory are scoped to that directory. Configure
  # the wrapper in this parent scope so the BEACON link pass is actually on.
  if(FUZZER STREQUAL "beacon")
    set(BEACON_ENTRY_PRUNING TRUE)
  endif()
  if(FUZZER STREQUAL "selectfuzz")
    set(SELECTFUZZ_MODE TRUE)
  endif()
  if(FUZZER STREQUAL "halo")
    set(HALO_MODE TRUE)
  endif()
  if(FUZZER STREQUAL "idfuzz")
    set(IDFUZZ_MODE TRUE)
  endif()

  # Corrosion does not currently support installing libraries through CMake, so
  # it is necessary to install this one manually. See:
  # https://github.com/AndrewGaspar/corrosion/issues/64
  install(FILES $<TARGET_FILE:${FUZZER}-static> TYPE LIB)

  set(PLUGIN_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/lib${LLVM_LIBDIR_SUFFIX}")
  set(LIBAFLGO_COMPILER_PLUGIN_PATH
      "${PLUGIN_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${AFLGO_COMPILER_PLUGIN_NAME}>"
  )
  set(LIBAFLGO_LINKER_PLUGIN_PATH
      "${PLUGIN_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${AFLGO_LINKER_PLUGIN_NAME}>"
  )

  set(LIBS_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")

  set(LIBAFL_CMPLOG_RTN_PLUGIN_PATH
      "${LIBS_INSTALL_PREFIX}/${CMPLOG_RTN_PLUGIN_FILE_NAME}")
  set(LIBAFL_AUTOTOKENS_PLUGIN_PATH
      "${LIBS_INSTALL_PREFIX}/${AUTOTOKENS_PLUGIN_FILE_NAME}")

  set(FUZZER_PATH "${LIBS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:${FUZZER}-static>")

  configure_file("${PROJECT_SOURCE_DIR}/wrapper/libaflgo_cc.in"
                 "libaflgo_${FUZZER}_cc.gen" @ONLY)
  file(
    GENERATE
    OUTPUT "libaflgo_${FUZZER}_cc"
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc.gen")
  install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc" TYPE BIN)
  install(
    PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc"
    TYPE BIN
    RENAME "libaflgo_${FUZZER}_cxx")

  if(BUILD_TESTING)
    # If testing is enabled, build a version of the wrapper that refers to the
    # artifacts in the build directory. This version of the wrapper can be used
    # directly in tests, without requiring to install the project.

    set(LIBAFLGO_COMPILER_PLUGIN_PATH
        $<TARGET_FILE:${AFLGO_COMPILER_PLUGIN_NAME}>)
    set(LIBAFLGO_LINKER_PLUGIN_PATH $<TARGET_FILE:${AFLGO_LINKER_PLUGIN_NAME}>)

    set(LIBAFL_CMPLOG_RTN_PLUGIN_PATH
        "${CMAKE_BINARY_DIR}/${CMPLOG_RTN_PLUGIN_FILE_NAME}")
    set(LIBAFL_AUTOTOKENS_PLUGIN_PATH
        "${CMAKE_BINARY_DIR}/${AUTOTOKENS_PLUGIN_FILE_NAME}")

    # The `-static` suffix is needed because this is how Corruption defines the
    # target.
    set(FUZZER_PATH "$<TARGET_FILE:${FUZZER}-static>")

    configure_file("${PROJECT_SOURCE_DIR}/wrapper/libaflgo_cc.in"
                   "libaflgo_${FUZZER}_cc_test.gen" @ONLY)
    file(
      GENERATE
      OUTPUT "libaflgo_${FUZZER}_cc_test"
      INPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc_test.gen")

    add_custom_target(
      "build_libaflgo_${FUZZER}_cxx_test" ALL
      DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cxx_test")
    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cxx_test"
      COMMAND
        ${CMAKE_COMMAND} -E copy
        "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc_test"
        "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cxx_test"
      MAIN_DEPENDENCY "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc_test"
      DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc_test.gen")

    list(APPEND TEST_CC_WRAPPER_PATHS
         "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cc_test")
    list(APPEND TEST_CXX_WRAPPER_PATHS
         "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_${FUZZER}_cxx_test")
  endif()
endforeach()

# Command-line Magma entries need their own instrumentation callbacks, without
# the in-process LibFuzzer main that the Rust static library provides.
set(HALO_MODE FALSE)
set(BEACON_CLI_MODE TRUE)
set(BEACON_ENTRY_PRUNING TRUE)
set(FUZZER_PATH
    "${LIBS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:BeaconCliRuntime>")
configure_file("${PROJECT_SOURCE_DIR}/wrapper/libaflgo_cc.in"
               "libaflgo_beacon_cli_cc.gen" @ONLY)
file(GENERATE OUTPUT "libaflgo_beacon_cli_cc"
     INPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_beacon_cli_cc.gen")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_beacon_cli_cc" TYPE BIN)
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_beacon_cli_cc" TYPE BIN
        RENAME "libaflgo_beacon_cli_cxx")

set(BEACON_CLI_MODE FALSE)
set(BEACON_ENTRY_PRUNING FALSE)
set(SELECTFUZZ_CLI_MODE TRUE)
set(SELECTFUZZ_MODE TRUE)
set(FUZZER_PATH
    "${LIBS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:SelectFuzzCliRuntime>")
configure_file("${PROJECT_SOURCE_DIR}/wrapper/libaflgo_cc.in"
               "libaflgo_selectfuzz_cli_cc.gen" @ONLY)
file(GENERATE OUTPUT "libaflgo_selectfuzz_cli_cc"
     INPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_selectfuzz_cli_cc.gen")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_selectfuzz_cli_cc" TYPE BIN)
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_selectfuzz_cli_cc" TYPE BIN
        RENAME "libaflgo_selectfuzz_cli_cxx")

set(SELECTFUZZ_CLI_MODE FALSE)
set(SELECTFUZZ_MODE FALSE)
set(HALO_CLI_MODE TRUE)
set(HALO_MODE TRUE)
set(FUZZER_PATH
    "${LIBS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:HaloCliRuntime>")
configure_file("${PROJECT_SOURCE_DIR}/wrapper/libaflgo_cc.in"
               "libaflgo_halo_cli_cc.gen" @ONLY)
file(GENERATE OUTPUT "libaflgo_halo_cli_cc"
     INPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_halo_cli_cc.gen")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_halo_cli_cc" TYPE BIN)
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_halo_cli_cc" TYPE BIN
        RENAME "libaflgo_halo_cli_cxx")

set(HALO_CLI_MODE FALSE)
set(HALO_MODE FALSE)
set(IDFUZZ_CLI_MODE TRUE)
set(IDFUZZ_MODE TRUE)
set(FUZZER_PATH
    "${LIBS_INSTALL_PREFIX}/$<TARGET_FILE_NAME:IDFuzzCliRuntime>")
configure_file("${PROJECT_SOURCE_DIR}/wrapper/libaflgo_cc.in"
               "libaflgo_idfuzz_cli_cc.gen" @ONLY)
file(GENERATE OUTPUT "libaflgo_idfuzz_cli_cc"
     INPUT "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_idfuzz_cli_cc.gen")
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_idfuzz_cli_cc" TYPE BIN)
install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/libaflgo_idfuzz_cli_cc" TYPE BIN
        RENAME "libaflgo_idfuzz_cli_cxx")

set(FUZZERS
    ${FUZZERS}
    PARENT_SCOPE)
set(TEST_CC_WRAPPER_PATHS
    ${TEST_CC_WRAPPER_PATHS}
    PARENT_SCOPE)
set(TEST_CXX_WRAPPER_PATHS
    ${TEST_CXX_WRAPPER_PATHS}
    PARENT_SCOPE)
