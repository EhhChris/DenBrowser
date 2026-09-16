#pragma once

// This header is compiled only inside a Citrix Virtual Channel SDK build.
// PVD and the Wd* structures come from the SDK version installed by the
// integrator; they are deliberately not vendored or re-declared here.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wtypes.h> // DOUBLE in WDOVERLAYINFO, omitted by lean windows.h.

// Match the SDK sample's platform setup before loading its driver interfaces.
// vd.h supplies PVD and VdCallWd; vdapi.h alone does not declare them.
// platcomm.h defines min/max even with NOMINMAX; keep them out of our C++ API.
#pragma push_macro("min")
#pragma push_macro("max")
extern "C" {
#include <citrix.h>
#include <clib.h>
#include <wdapi.h>
#include <vdapi.h>
#include <vd.h>
}
#pragma pop_macro("max")
#pragma pop_macro("min")

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "dencap_lease_engine.h"

namespace dencap {

// The response buffer is valid only for the duration of the call. A sink that
// queues asynchronous output must copy all |length| bytes before returning.
using ResponseSink = bool (*)(void *context, const std::uint8_t *bytes,
                              std::size_t length);

enum class Phase0Disposition {
  kReady,
  kRetryLater,
  kUnsupported,
};

class CitrixWindowSource final : public IWindowSource {
public:
  explicit CitrixWindowSource(PVD pvd) noexcept : pvd_(pvd) {}
  WindowQueryResult QueryIcaWindow() noexcept override;

private:
  PVD pvd_ = nullptr;
};

// SDK-neutral lease/protection code plus the two stable Citrix integration
// points: VdCallWd window discovery and window-change notification.
//
// dencap_driver.cpp provides DriverOpen/DriverPoll/DriverClose/ICADataArrival
// and writes status frames back to the channel using the SDK transport.
class CitrixAdapter {
public:
  explicit CitrixAdapter(PVD pvd) noexcept;
  ~CitrixAdapter();

  CitrixAdapter(const CitrixAdapter &) = delete;
  CitrixAdapter &operator=(const CitrixAdapter &) = delete;

  Phase0Disposition Initialize(OwnershipProbeResult *phase0_result) noexcept;
  bool OnChannelBytes(const std::uint8_t *bytes, std::size_t length,
                      ResponseSink response_sink,
                      void *response_context) noexcept;
  bool Poll(ResponseSink response_sink = nullptr,
            void *response_context = nullptr) noexcept;
  [[nodiscard]] bool Shutdown() noexcept;

  [[nodiscard]] bool window_callback_registered() const noexcept {
    return callback_registered_;
  }
  [[nodiscard]] int last_callback_error() const noexcept {
    return last_callback_error_;
  }

private:
  static void __cdecl WindowChangedThunk(UINT32 mode);
  bool RegisterWindowCallback() noexcept;
  bool UnregisterWindowCallback() noexcept;

  PVD pvd_ = nullptr;
  CitrixWindowSource window_source_;
  WindowProtector protector_;
  LeaseEngine lease_engine_;
  std::array<std::uint8_t, sizeof(Message)> receive_buffer_{};
  std::size_t receive_used_ = 0;
  std::uint64_t observed_window_generation_ = 0;
  std::uint32_t callback_handle_ = 0;
  bool callback_registered_ = false;
  bool initialized_ = false;
  bool phase0_unsupported_ = false;
  bool shutdown_ = false;
  int last_callback_error_ = 0;
  OwnershipProbeResult phase0_success_{};
  OwnershipProbeResult phase0_failure_{};

  static std::atomic_uint64_t window_generation_;
};

} // namespace dencap
