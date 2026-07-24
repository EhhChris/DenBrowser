#include "dencap_citrix_adapter.h"

#include <algorithm>
#include <cstring>
#include <type_traits>

namespace dencap {
namespace {

// Citrix's published examples contain both three- and four-argument VdCallWd
// calls. Select the ABI exposed by the installed SDK header instead of
// re-declaring the function or trusting one documentation version.
template <typename Function>
int CallWd(Function function, PVD pvd, USHORT procedure, PVOID parameter,
           PUINT16 parameter_size) noexcept {
  if constexpr (std::is_invocable_v<Function, PVD, USHORT, PVOID, PUINT16>) {
    return static_cast<int>(
        function(pvd, procedure, parameter, parameter_size));
  } else {
    static_assert(std::is_invocable_v<Function, PVD, USHORT, PVOID>,
                  "Unsupported VdCallWd signature in this Citrix SDK");
    return static_cast<int>(function(pvd, procedure, parameter));
  }
}

} // namespace

std::atomic_uint64_t CitrixAdapter::window_generation_{1};

WindowQueryResult CitrixWindowSource::QueryIcaWindow() noexcept {
  WDICAWINDOWINFO window_info{};
  WDQUERYINFORMATION query{};
  query.WdInformationClass = WdGetICAWindowInfo;
  query.pWdInformation = &window_info;
  query.WdInformationLength = static_cast<USHORT>(sizeof(window_info));
  UINT16 query_size = static_cast<UINT16>(sizeof(query));

  const int result =
      CallWd(&VdCallWd, pvd_, WDxQUERYINFORMATION, &query, &query_size);
  if (result != 0) {
    return WindowQueryResult{Status::kIcaWindowQueryFailed,
                             static_cast<DWORD>(result), nullptr};
  }
  return WindowQueryResult{Status::kOk, ERROR_SUCCESS, window_info.hwnd};
}

CitrixAdapter::CitrixAdapter(PVD pvd) noexcept
    : pvd_(pvd), window_source_(pvd), protector_(window_source_),
      lease_engine_(protector_) {}

CitrixAdapter::~CitrixAdapter() { (void)Shutdown(); }

Phase0Disposition
CitrixAdapter::Initialize(OwnershipProbeResult *phase0_result) noexcept {
  if (shutdown_) {
    OwnershipProbeResult result{};
    result.status = Status::kNotInitialized;
    result.win32_error = ERROR_INVALID_STATE;
    result.current_pid = ::GetCurrentProcessId();
    if (phase0_result != nullptr) {
      *phase0_result = result;
    }
    return Phase0Disposition::kUnsupported;
  }
  if (initialized_) {
    if (phase0_result != nullptr) {
      *phase0_result = phase0_success_;
    }
    return Phase0Disposition::kReady;
  }
  if (phase0_unsupported_) {
    if (phase0_result != nullptr) {
      *phase0_result = phase0_failure_;
    }
    return Phase0Disposition::kUnsupported;
  }

  const OwnershipProbeResult probe = protector_.Probe();
  if (phase0_result != nullptr) {
    *phase0_result = probe;
  }
  if (!probe.ok()) {
    const bool window_not_ready =
        probe.status == Status::kIcaWindowQueryFailed ||
        (probe.status == Status::kWindowOwnershipFailed &&
         probe.win32_error == ERROR_INVALID_WINDOW_HANDLE);
    if (window_not_ready) {
      return Phase0Disposition::kRetryLater;
    }
    phase0_failure_ = probe;
    phase0_unsupported_ = true;
    return Phase0Disposition::kUnsupported;
  }

  // Registration is an optimization. DriverPoll still re-queries once per
  // second, so a Workspace version that lacks this callback remains safe.
  RegisterWindowCallback();
  observed_window_generation_ =
      window_generation_.load(std::memory_order_acquire);
  phase0_success_ = probe;
  initialized_ = true;
  return Phase0Disposition::kReady;
}

bool CitrixAdapter::OnChannelBytes(const std::uint8_t *bytes,
                                   std::size_t length,
                                   ResponseSink response_sink,
                                   void *response_context) noexcept {
  if (shutdown_ || !initialized_ || bytes == nullptr ||
      response_sink == nullptr) {
    return false;
  }

  while (length != 0) {
    const std::size_t to_copy =
        std::min(length, receive_buffer_.size() - receive_used_);
    std::memcpy(receive_buffer_.data() + receive_used_, bytes, to_copy);
    receive_used_ += to_copy;
    bytes += to_copy;
    length -= to_copy;

    if (receive_used_ == receive_buffer_.size()) {
      const Message response = lease_engine_.HandleFrame(
          receive_buffer_.data(), receive_buffer_.size(), ::GetTickCount64());
      receive_used_ = 0;
      if (!response_sink(response_context,
                         reinterpret_cast<const std::uint8_t *>(&response),
                         sizeof(response))) {
        return false;
      }
    }
  }
  return true;
}

void CitrixAdapter::Poll() noexcept {
  if (shutdown_) {
    return;
  }
  if (!initialized_) {
    Initialize(nullptr);
    return;
  }

  const std::uint64_t generation =
      window_generation_.load(std::memory_order_acquire);
  if (generation != observed_window_generation_) {
    observed_window_generation_ = generation;
    lease_engine_.NotifyWindowChanged();
  }
  lease_engine_.Poll(::GetTickCount64());
}

bool CitrixAdapter::Shutdown() noexcept {
  if (!shutdown_) {
    shutdown_ = true;
    lease_engine_.Shutdown();
    receive_used_ = 0;
    initialized_ = false;
  }
  return UnregisterWindowCallback();
}

void __cdecl CitrixAdapter::WindowChangedThunk(UINT32) {
  // Citrix requires callbacks to return promptly. Poll performs the query and
  // WDA work after observing this generation change.
  window_generation_.fetch_add(1, std::memory_order_release);
}

bool CitrixAdapter::RegisterWindowCallback() noexcept {
#if !defined(DENCAP_CITRIX_HAS_WINDOW_CALLBACK) ||                             \
    DENCAP_CITRIX_HAS_WINDOW_CALLBACK
  WDREGISTERWINDOWCALLBACKPARAMS callback{};
  callback.pfnCallback = &CitrixAdapter::WindowChangedThunk;

  WDQUERYINFORMATION query{};
  query.WdInformationClass = WdRegisterWindowChangeCallback;
  query.pWdInformation = &callback;
  query.WdInformationLength = static_cast<USHORT>(sizeof(callback));
  UINT16 query_size = static_cast<UINT16>(sizeof(query));
  const int result =
      CallWd(&VdCallWd, pvd_, WDxQUERYINFORMATION, &query, &query_size);
  if (result != 0 || callback.Handle == 0) {
    last_callback_error_ =
        result != 0 ? result : static_cast<int>(ERROR_INVALID_HANDLE);
    return false;
  }

  callback_handle_ = callback.Handle;
  callback_registered_ = true;
  last_callback_error_ = 0;
  return true;
#else
  return false;
#endif
}

bool CitrixAdapter::UnregisterWindowCallback() noexcept {
  if (!callback_registered_) {
    return true;
  }

#if !defined(DENCAP_CITRIX_HAS_WINDOW_CALLBACK) ||                             \
    DENCAP_CITRIX_HAS_WINDOW_CALLBACK
  WDQUERYINFORMATION query{};
  query.WdInformationClass = WdUnregisterWindowChangeCallback;
  query.pWdInformation = &callback_handle_;
  query.WdInformationLength = static_cast<USHORT>(sizeof(callback_handle_));
  UINT16 query_size = static_cast<UINT16>(sizeof(query));
  const int result =
      CallWd(&VdCallWd, pvd_, WDxQUERYINFORMATION, &query, &query_size);
  if (result != 0) {
    last_callback_error_ = result;
    return false;
  }
#endif

  callback_handle_ = 0;
  callback_registered_ = false;
  last_callback_error_ = 0;
  return true;
}

} // namespace dencap
