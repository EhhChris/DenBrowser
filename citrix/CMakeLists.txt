cmake_minimum_required(VERSION 3.21)
project(DenCapCitrix LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "DENCAP endpoint protection is Windows-only")
endif()

option(DENCAP_BUILD_CITRIX_ADAPTER
       "Compile the adapter against an installed Citrix Virtual Channel SDK"
       OFF)
option(DENCAP_BUILD_TESTS "Build the dependency-free lease-engine tests" ON)
option(DENCAP_CITRIX_HAS_WINDOW_CALLBACK
       "The selected Citrix SDK exposes WdRegisterWindowChangeCallback"
       ON)

add_library(dencap_core STATIC
  client/dencap_lease_engine.cpp
  client/dencap_window_protector.cpp
)
target_compile_features(dencap_core PUBLIC cxx_std_17)
target_compile_definitions(dencap_core PUBLIC
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
target_include_directories(dencap_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/client"
  "${CMAKE_CURRENT_SOURCE_DIR}/protocol"
)
target_link_libraries(dencap_core PUBLIC user32)

add_executable(dencap_hwnd_probe tools/dencap_hwnd_probe.cpp)
target_compile_features(dencap_hwnd_probe PRIVATE cxx_std_17)
target_compile_definitions(dencap_hwnd_probe PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN
)
target_link_libraries(dencap_hwnd_probe PRIVATE user32)

if(DENCAP_BUILD_TESTS)
  enable_testing()
  add_executable(dencap_lease_engine_tests
    tests/dencap_lease_engine_tests.cpp
  )
  target_compile_features(dencap_lease_engine_tests PRIVATE cxx_std_17)
  target_link_libraries(dencap_lease_engine_tests PRIVATE dencap_core)
  add_test(NAME dencap_lease_engine_tests COMMAND dencap_lease_engine_tests)
endif()

if(DENCAP_BUILD_CITRIX_ADAPTER)
  # Normally the only variable an integrator sets. Everything below is derived
  # from it; see cmake/DenCapCitrixSdk.cmake for the per-generation overrides.
  set(CITRIX_VCSDK_ROOT "" CACHE PATH
      "Root of the unpacked Citrix Virtual Channel SDK matching the target \
Citrix Workspace generation and architecture")
  set(CITRIX_VCSDK_VERSION "" CACHE STRING
      "Optional label for the SDK/Workspace generation, recorded in the \
configure summary so a build tree states which SDK produced it")

  set(CITRIX_VC_INCLUDE_DIR "" CACHE PATH
      "Override: directory containing the matching Citrix SDK vdapi.h and \
wdapi.h")
  set(CITRIX_VDAPI_LIBRARY "" CACHE FILEPATH
      "Override: full path to the matching architecture's Citrix Vdapi.lib")
  set(CITRIX_WDICA_LIBRARY "" CACHE FILEPATH
      "Override: full path to the matching Citrix wdica30.lib")

  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/DenCapCitrixSdk.cmake")
  dencap_resolve_citrix_sdk(${CMAKE_SIZEOF_VOID_P})

  if(CITRIX_VCSDK_VERSION)
    set(_dencap_sdk_label "${CITRIX_VCSDK_VERSION}")
  else()
    set(_dencap_sdk_label "unspecified (set CITRIX_VCSDK_VERSION to record it)")
  endif()
  if(CITRIX_WDICA_LIBRARY)
    set(_dencap_wdica_label "${CITRIX_WDICA_LIBRARY}")
  else()
    set(_dencap_wdica_label "not found (optional)")
  endif()
  if(DENCAP_CITRIX_SDK_ROOT)
    set(_dencap_root_label "${DENCAP_CITRIX_SDK_ROOT}")
  else()
    set(_dencap_root_label "not set (using explicit path overrides)")
  endif()
  message(STATUS "DENCAP Citrix adapter:")
  message(STATUS "  SDK version:     ${_dencap_sdk_label}")
  message(STATUS "  SDK root:        ${_dencap_root_label}")
  message(STATUS "  Target arch:     ${DENCAP_CITRIX_TARGET_ARCH}")
  message(STATUS "  Headers:         ${CITRIX_VC_INCLUDE_DIR}")
  message(STATUS "  Vdapi.lib:       ${CITRIX_VDAPI_LIBRARY}")
  message(STATUS "  wdica30.lib:     ${_dencap_wdica_label}")
  message(STATUS "  Window callback: ${DENCAP_CITRIX_HAS_WINDOW_CALLBACK}")

  add_library(dencap_citrix_adapter STATIC
    client/dencap_citrix_adapter.cpp
  )
  target_compile_features(dencap_citrix_adapter PUBLIC cxx_std_17)
  target_compile_definitions(dencap_citrix_adapter PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    DENCAP_CITRIX_HAS_WINDOW_CALLBACK=$<BOOL:${DENCAP_CITRIX_HAS_WINDOW_CALLBACK}>
  )
  target_include_directories(dencap_citrix_adapter PUBLIC
    "${CITRIX_VC_INCLUDE_DIR}"
  )
  target_link_libraries(dencap_citrix_adapter PUBLIC
    dencap_core
    "${CITRIX_VDAPI_LIBRARY}"
  )
  # Existence was validated during resolution; only some SDK generations ship
  # wdica30.lib as a separate import library.
  if(CITRIX_WDICA_LIBRARY)
    target_link_libraries(dencap_citrix_adapter PUBLIC
      "${CITRIX_WDICA_LIBRARY}"
    )
  endif()
endif()
