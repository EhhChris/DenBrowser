cmake_minimum_required(VERSION 3.21)
project(DenCapCitrix LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "DENCAP endpoint protection is Windows-only")
endif()

option(DENCAP_BUILD_CITRIX_ADAPTER
       "Compile the adapter against an installed Citrix Virtual Channel SDK"
       OFF)
option(DENCAP_BUILD_CITRIX_DRIVER "Build the loadable Workspace DENCAP DLL" OFF)
if(DENCAP_BUILD_CITRIX_DRIVER)
  set(DENCAP_BUILD_CITRIX_ADAPTER ON)
endif()
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
  set(CITRIX_VCSDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/VCSDK" CACHE PATH
      "Root of the extracted Citrix Virtual Channel SDK (contains src and bin)")

  if(NOT MSVC)
    message(FATAL_ERROR
      "The supplied Citrix SDK libraries require MSVC or clang-cl.")
  endif()

  # Select by the compiler target, not the build host's architecture. This
  # works with both Visual Studio (-A) and Ninja (Developer Shell) generators.
  if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "X86")
    set(dencap_sdk_arch Win32)
  elseif(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "x64")
    set(dencap_sdk_arch x64)
  elseif(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "ARM64")
    set(dencap_sdk_arch ARM64)
  else()
    message(FATAL_ERROR
      "Unsupported Citrix SDK compiler architecture: "
      "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}")
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

  set(dencap_sdk_lib_dir "${CITRIX_VCSDK_ROOT}/bin/Release/${dencap_sdk_arch}")
  foreach(dencap_sdk_file IN ITEMS
      src/inc/citrix.h src/inc/clib.h src/inc/vd.h src/inc/vdapi.h src/inc/wdapi.h
      src/inc/win32/plat.h src/shared/inc/ica.h src/shared/inc/vrtlclss.h
      bin/Release/${dencap_sdk_arch}/vdapi.lib
      bin/Release/${dencap_sdk_arch}/clibdll.lib)
    if(NOT EXISTS "${CITRIX_VCSDK_ROOT}/${dencap_sdk_file}")
      message(FATAL_ERROR
        "Citrix SDK file not found: ${CITRIX_VCSDK_ROOT}/${dencap_sdk_file}. "
        "Set CITRIX_VCSDK_ROOT to the extracted VCSDK directory containing "
        "src and bin (the default is citrix/VCSDK).")
    endif()
  endforeach()

  # Match the 2507.1 sample's include roots, structure packing and Win32 ABI.
  # Keep these requirements on SDK consumers; dencap_core stays SDK-neutral.
  add_library(dencap_citrix_sdk INTERFACE)
  target_include_directories(dencap_citrix_sdk INTERFACE
    "${CITRIX_VCSDK_ROOT}/src/inc"
    "${CITRIX_VCSDK_ROOT}/src/inc/win32"
    "${CITRIX_VCSDK_ROOT}/src/shared/inc"
  )
  target_compile_options(dencap_citrix_sdk INTERFACE /Zp8)
  if(dencap_sdk_arch STREQUAL "Win32")
    target_compile_options(dencap_citrix_sdk INTERFACE /Gz)
  endif()
  target_link_libraries(dencap_citrix_sdk INTERFACE
    "${dencap_sdk_lib_dir}/vdapi.lib"
    "${dencap_sdk_lib_dir}/clibdll.lib"
    kernel32 advapi32
  )
  message(STATUS "Citrix VCSDK: ${CITRIX_VCSDK_ROOT} (${dencap_sdk_arch})")

  add_library(dencap_citrix_adapter STATIC
    client/dencap_citrix_adapter.cpp
  )
  target_compile_features(dencap_citrix_adapter PUBLIC cxx_std_17)
  target_compile_definitions(dencap_citrix_adapter PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    DENCAP_CITRIX_HAS_WINDOW_CALLBACK=$<BOOL:${DENCAP_CITRIX_HAS_WINDOW_CALLBACK}>
  )
  target_link_libraries(dencap_citrix_adapter PUBLIC
    dencap_core
    dencap_citrix_sdk
  )

  if(DENCAP_BUILD_CITRIX_DRIVER)
    add_library(dencap_vd SHARED
      client/dencap_driver.cpp
      client/dencap_driver.def
    )
    target_link_libraries(dencap_vd PRIVATE dencap_citrix_adapter)
    set_target_properties(dencap_vd PROPERTIES PREFIX "")
  endif()

  if(DENCAP_BUILD_TESTS)
    # A static library build alone cannot detect a wrong VdCallWd ABI or
    # missing SDK link dependencies. This check never calls a live Citrix API.
    add_executable(dencap_sdk_link_check tests/dencap_sdk_link_check.cpp)
    target_link_libraries(dencap_sdk_link_check PRIVATE dencap_citrix_adapter)
    add_test(NAME dencap_sdk_link_check COMMAND dencap_sdk_link_check)

    if(DENCAP_BUILD_CITRIX_DRIVER)
      add_executable(dencap_driver_tests
        tests/dencap_driver_tests.cpp
        client/dencap_driver.cpp
      )
      target_link_libraries(dencap_driver_tests PRIVATE dencap_citrix_adapter)
      file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-profile")
      add_test(NAME dencap_driver_tests COMMAND dencap_driver_tests)
      set_tests_properties(dencap_driver_tests PROPERTIES
        ENVIRONMENT "LOCALAPPDATA=${CMAKE_CURRENT_BINARY_DIR}/test-profile"
        TIMEOUT 30
      )
    endif()
  endif()
endif()
