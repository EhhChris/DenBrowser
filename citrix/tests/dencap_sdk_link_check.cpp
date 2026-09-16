#include "dencap_citrix_adapter.h"

#include <type_traits>

// This is a build/link check, not a Workspace virtual-driver shell. It never
// initializes an adapter or invokes an SDK function with the null PVD below.
// Referencing the real SDK symbol catches an x86 calling-convention mismatch
// that creating a static adapter library alone cannot detect.
#if defined(_M_IX86)
static_assert(
    std::is_same_v<decltype(&VdCallWd),
                   int(__stdcall *)(PVD, USHORT, PVOID, PUINT16)>,
    "VCSDK 2507.1 requires the stdcall VdCallWd ABI on x86");
#endif

namespace {
auto volatile linked_vd_call_wd = &VdCallWd;
}

int __cdecl main() {
  if (linked_vd_call_wd == nullptr) {
    return 1;
  }

  dencap::CitrixAdapter adapter(nullptr);
  return adapter.Shutdown() ? 0 : 1;
}
