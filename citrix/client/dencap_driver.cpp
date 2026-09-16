// DENCAP's Workspace virtual-driver entry points. The SDK's vdapi.lib supplies
// Load and the common module front end; it calls these C entry points.
// ABI and initialization sequence follow Citrix VCSDK 2507.1's vdping example.
#include "dencap_citrix_adapter.h"

extern "C" {
#include <clterr.h>
#include <ica-c2h.h>
}

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <new>

namespace {

constexpr std::size_t kReceiveCapacity = 64 * 1024;
constexpr std::size_t kResponseCapacity = 128;
constexpr std::size_t kFramesPerPoll = 16;
constexpr std::uint64_t kPhase0RetryMs = 1'000;
constexpr LONGLONG kMaximumLogBytes = 2 * 1024 * 1024;

// The ICA arrival callback only performs a bounded memory copy. All SDK window
// queries, capture-affinity changes, response generation and I/O occur on Poll.
struct DriverState {
  explicit DriverState(PVD vd) noexcept : adapter(vd) {}
  ~DriverState() {
    if (log != INVALID_HANDLE_VALUE) {
      ::CloseHandle(log);
    }
    if (module_reference != nullptr && !retain_module_reference) {
      // The SDK's original module reference remains live through DriverClose.
      ::FreeLibrary(module_reference);
    }
  }

  dencap::CitrixAdapter adapter;
  PVOID wd = nullptr;
  PQUEUEVIRTUALWRITEPROC queue_write = nullptr;
  PSENDDATAPROC send_data = nullptr;
  USHORT channel = 0;
  bool hpc = false;
  std::atomic_bool disabled{false};
  std::atomic_bool transport_failed{false};
  bool failure_logged = false;
  bool phase0_logged = false;
  std::uint64_t next_phase0_ms = 0;
  dencap::Phase0Disposition phase0 = dencap::Phase0Disposition::kRetryLater;
  dencap::OwnershipProbeResult probe{};
  SRWLOCK receive_lock = SRWLOCK_INIT;
  std::array<std::uint8_t, kReceiveCapacity> receive{};
  std::size_t receive_head = 0;
  std::size_t receive_used = 0;
  std::array<dencap::Message, kResponseCapacity> responses{};
  std::size_t response_head = 0;
  std::size_t response_count = 0;
  HANDLE log = INVALID_HANDLE_VALUE;
  LONGLONG log_bytes = 0;
  HMODULE module_reference = nullptr;
  bool retain_module_reference = false;
};

DriverState *State(PVD vd) noexcept {
  return vd == nullptr ? nullptr : static_cast<DriverState *>(vd->pPrivate);
}

void OpenLog(DriverState &state) noexcept {
  wchar_t path[MAX_PATH]{};
  const DWORD count = ::GetEnvironmentVariableW(L"LOCALAPPDATA", path,
                                               static_cast<DWORD>(std::size(path)));
  if (count == 0 || count >= std::size(path) - 64) {
    return;
  }
  if (wcscat_s(path, L"\\DenBrowser") != 0) {
    return;
  }
  ::CreateDirectoryW(path, nullptr);
  if (wcscat_s(path, L"\\Citrix") != 0) {
    return;
  }
  ::CreateDirectoryW(path, nullptr);
  wchar_t suffix[48]{};
  swprintf_s(suffix, L"\\dencap-%lu.log", ::GetCurrentProcessId());
  if (wcscat_s(path, suffix) != 0) {
    return;
  }
  state.log = ::CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (state.log != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(state.log, &size)) {
      state.log_bytes = size.QuadPart;
    }
  }
}

void Log(DriverState *state, const char *format, ...) noexcept {
  char line[768]{};
  SYSTEMTIME now{};
  ::GetSystemTime(&now);
  int used = _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "DENCAP %04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu channel=%u ",
                        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
                        now.wSecond, now.wMilliseconds, ::GetCurrentProcessId(),
                        state != nullptr ? state->channel : 0);
  if (used < 0) {
    return;
  }
  va_list arguments;
  va_start(arguments, format);
  _vsnprintf_s(line + used, sizeof(line) - used - 3, _TRUNCATE, format, arguments);
  va_end(arguments);
  strcat_s(line, "\r\n");
  ::OutputDebugStringA(line);
  if (state != nullptr && state->log != INVALID_HANDLE_VALUE &&
      state->log_bytes < kMaximumLogBytes) {
    DWORD written = 0;
    ::WriteFile(state->log, line, static_cast<DWORD>(std::strlen(line)), &written,
                nullptr);
    state->log_bytes += written;
  }
}

bool QueueResponse(void *context, const std::uint8_t *bytes,
                   std::size_t length) noexcept {
  auto &state = *static_cast<DriverState *>(context);
  if (bytes == nullptr || length != sizeof(dencap::Message) ||
      state.response_count == state.responses.size() ||
      state.transport_failed.load(std::memory_order_acquire)) {
    return false;
  }
  const std::size_t tail =
      (state.response_head + state.response_count) % state.responses.size();
  std::memcpy(&state.responses[tail], bytes, length);
  ++state.response_count;
  const dencap::Message &response = state.responses[tail];
  Log(&state, "STATUS sequence=%llu status=%lu win32=%lu affinity=0x%lx",
      static_cast<unsigned long long>(response.sequence),
      static_cast<unsigned long>(response.status),
      static_cast<unsigned long>(response.win32_error),
      static_cast<unsigned long>(response.observed_affinity));
  return true;
}

void WFCAPI ICADataArrival(PVOID context, USHORT channel, LPBYTE bytes,
                           USHORT length) {
  auto *state = State(static_cast<PVD>(context));
  if (state == nullptr || state->disabled.load(std::memory_order_acquire) ||
      state->transport_failed.load(std::memory_order_acquire) || length == 0) {
    return;
  }
  if (bytes == nullptr || channel != state->channel ||
      !::TryAcquireSRWLockExclusive(&state->receive_lock)) {
    state->transport_failed.store(true, std::memory_order_release);
    return;
  }
  if (length > state->receive.size() - state->receive_used) {
    // Dropping bytes and continuing would silently shift the frame boundary.
    // Fail only this channel closed. Existing leases still expire via Poll.
    state->transport_failed.store(true, std::memory_order_release);
  } else {
    const std::size_t tail =
        (state->receive_head + state->receive_used) % state->receive.size();
    const std::size_t first = std::min<std::size_t>(length, state->receive.size() - tail);
    std::memcpy(state->receive.data() + tail, bytes, first);
    std::memcpy(state->receive.data(), bytes + first, length - first);
    state->receive_used += length;
  }
  ::ReleaseSRWLockExclusive(&state->receive_lock);
}

bool TakeRequest(DriverState &state, dencap::Message &request) noexcept {
  // Never hold this lock across a window query, send, or adapter operation.
  if (!::TryAcquireSRWLockExclusive(&state.receive_lock)) {
    return false;
  }
  const bool available = state.receive_used >= sizeof(request);
  if (available) {
    const std::size_t first =
        std::min(sizeof(request), state.receive.size() - state.receive_head);
    std::memcpy(&request, state.receive.data() + state.receive_head, first);
    std::memcpy(reinterpret_cast<std::uint8_t *>(&request) + first,
                state.receive.data(), sizeof(request) - first);
    state.receive_head = (state.receive_head + sizeof(request)) % state.receive.size();
    state.receive_used -= sizeof(request);
  }
  ::ReleaseSRWLockExclusive(&state.receive_lock);
  return available;
}

int SendResponses(PVD vd, DriverState &state) noexcept {
  for (std::size_t sent = 0; sent < kFramesPerPoll && state.response_count != 0;
       ++sent) {
    auto &response = state.responses[state.response_head];
    if (response.status == static_cast<std::uint32_t>(dencap::Status::kOk) &&
        response.lease_ms != 0 &&
        ::GetTickCount64() - response.monotonic_ms >= response.lease_ms) {
      // A full WD queue can retain a successful acknowledgement past its grant.
      // Never tell the browser an expired lease still protects the window.
      response.status = static_cast<std::uint32_t>(dencap::Status::kLeaseNotFound);
      response.win32_error = ERROR_TIMEOUT;
      response.lease_ms = 0;
      response.observed_affinity = WDA_NONE;
      Log(&state, "STATUS sequence=%llu expired while queued; reporting timeout",
          static_cast<unsigned long long>(response.sequence));
    }
    auto *bytes = reinterpret_cast<LPBYTE>(&response);
    int result;
    if (state.hpc) {
      // The 2507.1 SDK intentionally specifies a DWORD WD handle, also on x64.
      // Polling is enabled, so no SENDDATA_NOTIFY / async buffer ownership is needed.
      result = state.send_data(static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(state.wd)),
                               state.channel, bytes, sizeof(dencap::Message),
                               nullptr, 0);
    } else {
      MEMORY_SECTION section{};
      section.length = sizeof(dencap::Message);
      section.pSection = bytes;
      result = state.queue_write(state.wd, state.channel, &section, 1,
                                 FLUSH_IMMEDIATELY);
    }
    if (result == CLIENT_ERROR_NO_OUTBUF || result == CLIENT_ERROR_BUFFER_STILL_BUSY ||
        result == CLIENT_STATUS_NO_DATA) {
      return CLIENT_STATUS_ERROR_RETRY;
    }
    if (result != CLIENT_STATUS_SUCCESS) {
      vd->LastError = result;
      state.transport_failed.store(true, std::memory_order_release);
      Log(&state, "output failed rc=%d; DENCAP disabled until reconnect", result);
      return CLIENT_STATUS_SUCCESS;
    }
    // Both interfaces copy all bytes on success; retain the frame on retry.
    state.response_head = (state.response_head + 1) % state.responses.size();
    --state.response_count;
  }
  return CLIENT_STATUS_SUCCESS;
}

void StopAdapter(DriverState &state) noexcept {
  if (!state.adapter.Shutdown()) {
    // The window callback only touches module-static data. If Workspace keeps
    // its function pointer after rejecting unregistration, keep code/data mapped
    // until process exit instead of allowing an eventual call into an unloaded DLL.
    // The extra reference was obtained before any callback was registered, so
    // this fallback cannot fail because of a late allocation/API error.
    state.retain_module_reference = true;
    Log(&state, "window callback unregister failed rc=%d; module reference retained until process exit",
        state.adapter.last_callback_error());
  }
}

int InvalidParameter(PVD vd) noexcept {
  if (vd != nullptr) {
    vd->LastError = CLIENT_ERROR_INVALID_PARAMETER;
  }
  return CLIENT_ERROR_INVALID_PARAMETER;
}

} // namespace

extern "C" int DriverOpen(PVD vd, PVDOPEN open, PUINT16 size) {
  if (vd == nullptr || open == nullptr || size == nullptr || vd->pPrivate != nullptr) {
    return InvalidParameter(vd);
  }
  *size = sizeof(VDOPEN);
  vd->LastError = CLIENT_STATUS_SUCCESS;
  auto *state = new (std::nothrow) DriverState(vd);
  if (state == nullptr) {
    vd->LastError = CLIENT_ERROR_NO_MEMORY;
    return vd->LastError;
  }
  OpenLog(*state);
  if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            reinterpret_cast<LPCWSTR>(&ICADataArrival),
                            &state->module_reference)) {
    Log(state, "cannot retain callback module reference win32=%lu", ::GetLastError());
    vd->LastError = CLIENT_ERROR_NO_MEMORY;
    delete state;
    return vd->LastError;
  }
  OPENVIRTUALCHANNEL channel{};
  channel.pVCName = const_cast<char *>(dencap::kWfApiChannelName);
  WDQUERYINFORMATION query{};
  query.WdInformationClass = WdOpenVirtualChannel;
  query.pWdInformation = &channel;
  query.WdInformationLength = sizeof(channel);
  UINT16 parameter_size = sizeof(query);
  int result = VdCallWd(vd, WDxQUERYINFORMATION, &query, &parameter_size);
  if (result != CLIENT_STATUS_SUCCESS) {
    vd->LastError = result;
    Log(state, "channel open failed rc=%d", result);
    delete state;
    return result;
  }
  state->channel = channel.Channel;
  vd->pPrivate = state;

  VDWRITEHOOK hook{};
  hook.Type = state->channel;
  hook.pVdData = vd;
  hook.pProc = &ICADataArrival;
  WDSETINFORMATION set{};
  set.WdInformationClass = WdVirtualWriteHook;
  set.pWdInformation = &hook;
  set.WdInformationLength = sizeof(hook);
  parameter_size = sizeof(set);
  result = VdCallWd(vd, WDxSETINFORMATION, &set, &parameter_size);
  if (result != CLIENT_STATUS_SUCCESS) {
    vd->LastError = result;
    vd->pPrivate = nullptr;
    Log(state, "write hook failed rc=%d", result);
    delete state;
    return result;
  }
  state->wd = hook.pWdData;
  state->queue_write = hook.pQueueVirtualWriteProc;

  VDWRITEHOOKEX extended{};
  extended.usVersion = HPC_VD_API_VERSION_LEGACY;
  query.WdInformationClass = WdVirtualWriteHookEx;
  query.pWdInformation = &extended;
  query.WdInformationLength = sizeof(extended);
  parameter_size = sizeof(query);
  result = VdCallWd(vd, WDxQUERYINFORMATION, &query, &parameter_size);
  state->hpc = result == CLIENT_STATUS_SUCCESS &&
               extended.usVersion != HPC_VD_API_VERSION_LEGACY &&
               extended.pSendDataProc != nullptr;
  state->send_data = extended.pSendDataProc;

  if (state->hpc) {
    WDSET_HPC_PROPERITES properties{};
    properties.usVersion = HPC_VD_API_VERSION_V1;
    properties.pWdData = state->wd;
    // Leases expire even while no messages arrive. Never use NO_POLLING here.
    properties.ulVdOptions = 0;
    set.WdInformationClass = WdHpcProperties;
    set.pWdInformation = &properties;
    set.WdInformationLength = sizeof(properties);
    parameter_size = sizeof(set);
    result = VdCallWd(vd, WDxSETINFORMATION, &set, &parameter_size);
    if (result != CLIENT_STATUS_SUCCESS) {
      state->transport_failed.store(true, std::memory_order_release);
      vd->LastError = result;
      Log(state, "HPC polling configuration failed rc=%d; channel disabled", result);
    }
  }
  if ((!state->hpc && state->queue_write == nullptr) ||
      hook.MaximumWriteSize <= sizeof(dencap::Message)) {
    state->transport_failed.store(true, std::memory_order_release);
    vd->LastError = CLIENT_ERROR_BUFFER_TOO_SMALL;
    Log(state, "invalid output hook or write limit=%u; channel disabled",
        hook.MaximumWriteSize);
  }
  // After registering a write hook retain its state until DriverClose, even if
  // an optional API failed. A silent DENCAP channel makes the browser fail closed
  // without tearing down the user's complete ICA session.
  Log(state, "opened transport=%s periodic_polling=1 max_write=%u",
      state->hpc ? "HPC" : "legacy", hook.MaximumWriteSize);
  return CLIENT_STATUS_SUCCESS;
}

extern "C" int DriverClose(PVD vd, PDLLCLOSE, PUINT16) {
  auto *state = State(vd);
  if (state != nullptr) {
    state->disabled.store(true, std::memory_order_release);
    StopAdapter(*state);
    Log(state, "closed; leases released");
    vd->pPrivate = nullptr;
    // Citrix owns channel/write-hook teardown and guarantees their lifetime
    // through DriverClose; private driver storage belongs to this module.
    delete state;
  }
  return CLIENT_STATUS_SUCCESS;
}

extern "C" int DriverInfo(PVD vd, PDLLINFO info, PUINT16 size) {
  if (info == nullptr || size == nullptr) {
    return InvalidParameter(vd);
  }
  *size = sizeof(DLLINFO);
  if (info->ByteCount < sizeof(VD_C2H) || info->pBuffer == nullptr) {
    info->ByteCount = sizeof(VD_C2H);
    return CLIENT_ERROR_BUFFER_TOO_SMALL;
  }
  VD_C2H header{};
  header.Header.ByteCount = sizeof(header);
  header.Header.ModuleClass = Module_VirtualDriver;
  header.Header.VersionL = dencap::kProtocolVersion;
  header.Header.VersionH = dencap::kProtocolVersion;
  std::memcpy(header.Header.HostModuleName, "ICA", 4);
  header.Flow.BandwidthQuota = 0;
  header.Flow.Flow = VirtualFlow_None;
  // The SDK common front end supplies the negotiated ChannelMask semantics.
  // This Windows build uses the SDK's little-endian native wire structures.
  std::memcpy(info->pBuffer, &header, sizeof(header));
  info->ByteCount = sizeof(header);
  return CLIENT_STATUS_SUCCESS;
}

extern "C" int DriverPoll(PVD vd, PVOID, PUINT16) {
  auto *state = State(vd);
  if (state == nullptr || state->disabled.load(std::memory_order_acquire)) {
    return CLIENT_STATUS_SUCCESS;
  }
  if (state->transport_failed.load(std::memory_order_acquire)) {
    if (!state->failure_logged) {
      state->failure_logged = true;
      vd->LastError = vd->LastError != 0 ? vd->LastError : CLIENT_ERROR_BUFFER_TOO_SMALL;
      Log(state, "transport disabled; reconnect required; active leases will expire");
    }
    (void)state->adapter.Poll();
    return CLIENT_STATUS_SUCCESS;
  }

  const int output_result = SendResponses(vd, *state);
  if (state->transport_failed.load(std::memory_order_acquire)) {
    return CLIENT_STATUS_SUCCESS;
  }
  const auto now = ::GetTickCount64();
  if (state->phase0 == dencap::Phase0Disposition::kRetryLater &&
      now >= state->next_phase0_ms) {
    const auto old_status = state->probe.status;
    state->phase0 = state->adapter.Initialize(&state->probe);
    state->next_phase0_ms = now + kPhase0RetryMs;
    if (!state->phase0_logged || state->probe.status != old_status ||
        state->phase0 != dencap::Phase0Disposition::kRetryLater) {
      state->phase0_logged = true;
      Log(state, "phase0=%d status=%lu win32=%lu hwnd=%p root=%p owner=%lu current=%lu callback=%d",
          static_cast<int>(state->phase0), static_cast<unsigned long>(state->probe.status),
          state->probe.win32_error, state->probe.hwnd, state->probe.root_hwnd,
          state->probe.owner_pid, state->probe.current_pid,
          state->adapter.window_callback_registered());
    }
  }
  if (state->phase0 == dencap::Phase0Disposition::kReady) {
    (void)state->adapter.Poll(&QueueResponse, state);
  }
  if (state->phase0 == dencap::Phase0Disposition::kRetryLater) {
    // Window construction can lag DriverOpen. Keep the bounded request queue
    // until the ownership probe completes; the browser has its own timeout.
    return CLIENT_STATUS_SUCCESS;
  }

  for (std::size_t handled = 0; handled < kFramesPerPoll &&
                               state->response_count < state->responses.size();
       ++handled) {
    dencap::Message request{};
    if (!TakeRequest(*state, request)) {
      break;
    }
    if (state->transport_failed.load(std::memory_order_acquire)) {
      break;
    }
    if (state->phase0 == dencap::Phase0Disposition::kReady) {
      if (!state->adapter.OnChannelBytes(reinterpret_cast<const std::uint8_t *>(&request),
                                         sizeof(request), &QueueResponse, state)) {
        state->transport_failed.store(true, std::memory_order_release);
        break;
      }
    } else {
      const auto response = dencap::MakeStatusMessage(
          &request, state->probe.status, state->probe.win32_error,
          state->probe.observed_affinity, now);
      (void)QueueResponse(state, reinterpret_cast<const std::uint8_t *>(&response),
                          sizeof(response));
    }
    if (request.type == static_cast<std::uint16_t>(dencap::MessageType::kAcquire) ||
        request.type == static_cast<std::uint16_t>(dencap::MessageType::kRelease)) {
      Log(state, "request type=%u sequence=%llu", request.type,
          static_cast<unsigned long long>(request.sequence));
    }
  }
  const int final_output = SendResponses(vd, *state);
  // SUCCESS keeps timer polling active even when both queues are empty.
  return output_result == CLIENT_STATUS_ERROR_RETRY ? output_result : final_output;
}

extern "C" int DriverQueryInformation(PVD vd, PVDQUERYINFORMATION query,
                                      PUINT16 size) {
  if (query == nullptr || size == nullptr) {
    return InvalidParameter(vd);
  }
  *size = sizeof(VDQUERYINFORMATION);
  query->VdReturnLength = 0;
  return CLIENT_STATUS_SUCCESS;
}

extern "C" int DriverSetInformation(PVD vd, PVDSETINFORMATION set, PUINT16) {
  auto *state = State(vd);
  if (set == nullptr) {
    return InvalidParameter(vd);
  }
  if (state != nullptr && set->VdInformationClass == VdDisableModule) {
    state->disabled.store(true, std::memory_order_release);
    StopAdapter(*state);
    Log(state, "disabled; leases released");
  } else if (state != nullptr && set->VdInformationClass == VdFlush &&
             set->pVdInformation != nullptr && set->VdInformationLength >= sizeof(VDFLUSH)) {
    const auto &flush = *static_cast<const VDFLUSH *>(set->pVdInformation);
    if (flush.Channel == state->channel) {
      // A purge can discard part of a frame. Continuing an unknown byte boundary
      // is unsafe; require a fresh ICA channel and allow existing leases to expire.
      state->transport_failed.store(true, std::memory_order_release);
      Log(state, "channel purge mask=%u; reconnect required", flush.Mask);
    }
  }
  return CLIENT_STATUS_SUCCESS;
}

extern "C" int DriverGetLastError(PVD vd, PVDLASTERROR error) {
  if (vd == nullptr || error == nullptr) {
    return InvalidParameter(vd);
  }
  error->Error = vd->LastError;
  error->Message[0] = '\0';
  return CLIENT_STATUS_SUCCESS;
}
