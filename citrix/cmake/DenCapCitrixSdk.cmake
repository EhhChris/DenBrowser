# Resolves a Citrix Virtual Channel SDK layout from a single root directory.
#
# Citrix moves headers and import libraries between SDK generations, so the
# lookup tries the known layout variants instead of hard-coding one. Callers
# normally set only CITRIX_VCSDK_ROOT.
#
# Explicit overrides always win. Set CITRIX_VC_INCLUDE_DIR,
# CITRIX_VDAPI_LIBRARY, or CITRIX_WDICA_LIBRARY directly for a layout this
# module does not recognise; a set override is used verbatim and still
# validated, so a typo fails at configure time rather than at link time.

include_guard(GLOBAL)

# Joins a candidate list into an indented block for error messages.
function(_dencap_sdk_format_candidates out_var)
  set(text "")
  foreach(candidate IN LISTS ARGN)
    string(APPEND text "\n    ${candidate}")
  endforeach()
  set(${out_var} "${text}" PARENT_SCOPE)
endfunction()

# Resolves the SDK layout for a target whose pointer size is |pointer_size|
# bytes. On success, sets in the caller's scope:
#
#   DENCAP_CITRIX_TARGET_ARCH  x86 or x64, for diagnostics
#   DENCAP_CITRIX_SDK_ROOT     CITRIX_VCSDK_ROOT normalised, or empty
#   CITRIX_VC_INCLUDE_DIR      directory holding vdapi.h and wdapi.h
#   CITRIX_VDAPI_LIBRARY       full path to Vdapi.lib
#   CITRIX_WDICA_LIBRARY       full path to wdica30.lib, or empty when absent
function(dencap_resolve_citrix_sdk pointer_size)
  if(pointer_size EQUAL 8)
    set(arch_name "x64")
    set(arch_dirs "x64" "amd64" "x86_64")
  else()
    set(arch_name "x86")
    set(arch_dirs "x86" "Win32" "i386")
  endif()
  set(DENCAP_CITRIX_TARGET_ARCH "${arch_name}" PARENT_SCOPE)

  set(root "${CITRIX_VCSDK_ROOT}")
  if(root)
    file(TO_CMAKE_PATH "${root}" root)
    string(REGEX REPLACE "/+$" "" root "${root}")
    if(NOT IS_DIRECTORY "${root}")
      message(FATAL_ERROR
        "CITRIX_VCSDK_ROOT is not a directory:\n"
        "    ${root}\n"
        "Point it at the unpacked Citrix Virtual Channel SDK that matches the "
        "deployed Citrix Workspace generation.")
    endif()
  endif()
  set(DENCAP_CITRIX_SDK_ROOT "${root}" PARENT_SCOPE)

  set(include_candidates
    "${root}/inc"
    "${root}/include"
    "${root}/Inc"
    "${root}/Include"
    "${root}")

  set(lib_candidates "")
  foreach(arch IN LISTS arch_dirs)
    list(APPEND lib_candidates
      "${root}/lib/${arch}"
      "${root}/Lib/${arch}"
      "${root}/${arch}/lib"
      "${root}/${arch}")
  endforeach()
  list(APPEND lib_candidates "${root}/lib" "${root}/Lib" "${root}")

  # ---------------------------------------------------------------- headers
  set(include_dir "${CITRIX_VC_INCLUDE_DIR}")
  if(include_dir)
    set(include_origin "CITRIX_VC_INCLUDE_DIR")
  else()
    set(include_origin "CITRIX_VCSDK_ROOT")
    if(NOT root)
      message(FATAL_ERROR
        "No Citrix Virtual Channel SDK configured.\n"
        "Set -DCITRIX_VCSDK_ROOT=<unpacked SDK root> for the SDK matching the "
        "deployed Citrix Workspace generation and architecture, or set "
        "-DCITRIX_VC_INCLUDE_DIR and -DCITRIX_VDAPI_LIBRARY individually.")
    endif()
    foreach(candidate IN LISTS include_candidates)
      if(EXISTS "${candidate}/vdapi.h" AND EXISTS "${candidate}/wdapi.h")
        set(include_dir "${candidate}")
        break()
      endif()
    endforeach()
    if(NOT include_dir)
      _dencap_sdk_format_candidates(searched ${include_candidates})
      message(FATAL_ERROR
        "Could not find vdapi.h and wdapi.h under CITRIX_VCSDK_ROOT.\n"
        "  root:     ${root}\n"
        "  searched:${searched}\n"
        "Override with -DCITRIX_VC_INCLUDE_DIR=<dir> if this SDK uses a "
        "different layout.")
    endif()
  endif()

  foreach(header IN ITEMS "vdapi.h" "wdapi.h")
    if(NOT EXISTS "${include_dir}/${header}")
      message(FATAL_ERROR
        "${header} is missing from the Citrix include directory.\n"
        "  directory: ${include_dir}\n"
        "  chosen by: ${include_origin}\n"
        "Both vdapi.h and wdapi.h must come from the same SDK generation as "
        "the target Citrix Workspace release.")
    endif()
  endforeach()
  set(CITRIX_VC_INCLUDE_DIR "${include_dir}" PARENT_SCOPE)

  # ------------------------------------------------------------- Vdapi.lib
  set(vdapi "${CITRIX_VDAPI_LIBRARY}")
  if(vdapi)
    if(NOT EXISTS "${vdapi}")
      message(FATAL_ERROR
        "CITRIX_VDAPI_LIBRARY does not exist:\n    ${vdapi}")
    endif()
  else()
    foreach(candidate IN LISTS lib_candidates)
      if(EXISTS "${candidate}/Vdapi.lib")
        set(vdapi "${candidate}/Vdapi.lib")
        break()
      endif()
    endforeach()
    if(NOT vdapi)
      _dencap_sdk_format_candidates(searched ${lib_candidates})
      message(FATAL_ERROR
        "Could not find Vdapi.lib for ${arch_name} under CITRIX_VCSDK_ROOT.\n"
        "  root:     ${root}\n"
        "  searched:${searched}\n"
        "Check that this SDK ships an ${arch_name} import library, then "
        "override with -DCITRIX_VDAPI_LIBRARY=<path> if needed.")
    endif()
  endif()
  set(CITRIX_VDAPI_LIBRARY "${vdapi}" PARENT_SCOPE)

  # ----------------------------------------------------------- wdica30.lib
  # Optional: only some SDK generations ship it as a separate import library.
  set(wdica "${CITRIX_WDICA_LIBRARY}")
  if(wdica)
    if(NOT EXISTS "${wdica}")
      message(FATAL_ERROR
        "CITRIX_WDICA_LIBRARY does not exist:\n    ${wdica}")
    endif()
  else()
    foreach(candidate IN LISTS lib_candidates)
      if(EXISTS "${candidate}/wdica30.lib")
        set(wdica "${candidate}/wdica30.lib")
        break()
      endif()
    endforeach()
  endif()
  set(CITRIX_WDICA_LIBRARY "${wdica}" PARENT_SCOPE)
endfunction()
