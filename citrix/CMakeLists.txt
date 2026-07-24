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
  set(CITRIX_VC_INCLUDE_DIR "" CACHE PATH
      "Directory containing the matching Citrix SDK vdapi.h and wdapi.h")
  set(CITRIX_VDAPI_LIBRARY "" CACHE FILEPATH
      "Full path to the matching architecture's Citrix Vdapi.lib")
  set(CITRIX_WDICA_LIBRARY "" CACHE FILEPATH
      "Optional full path to the matching Citrix wdica30.lib")

  if(NOT EXISTS "${CITRIX_VC_INCLUDE_DIR}/vdapi.h" OR
     NOT EXISTS "${CITRIX_VC_INCLUDE_DIR}/wdapi.h")
    message(FATAL_ERROR
      "Set CITRIX_VC_INCLUDE_DIR to the include directory from the Citrix "
      "Virtual Channel SDK that matches the target Workspace release.")
  endif()
  if(NOT EXISTS "${CITRIX_VDAPI_LIBRARY}")
    message(FATAL_ERROR
      "Set CITRIX_VDAPI_LIBRARY to the exact Vdapi.lib for the target "
      "Workspace architecture.")
  endif()

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
  if(CITRIX_WDICA_LIBRARY)
    if(NOT EXISTS "${CITRIX_WDICA_LIBRARY}")
      message(FATAL_ERROR "CITRIX_WDICA_LIBRARY does not exist")
    endif()
    target_link_libraries(dencap_citrix_adapter PUBLIC
      "${CITRIX_WDICA_LIBRARY}"
    )
  endif()
endif()
