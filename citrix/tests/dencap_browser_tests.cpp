// SPDX-License-Identifier: MPL-2.0
// Compile with verify_browser_patch.py. This includes the actual extracted
// browser implementation and substitutes only the Citrix discovery/transport
// APIs. Windows events, threads, waits and the lease watchdog are real.
#include <windows.h>
#include <wtsapi32.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <memory>

#include "DenCitrixCaptureProtocol.h"

namespace {
bool gWtsSuccess = true;
USHORT gWtsProtocol = WTS_PROTOCOL_TYPE_CONSOLE;
DWORD gWtsBytes = sizeof(USHORT);
bool gRuntimePresent = false;
const char* gMissingExport = nullptr;
int gWfProtocol = WTS_PROTOCOL_TYPE_CONSOLE;
LSTATUS gVdaKeyStatus = ERROR_FILE_NOT_FOUND;
REGSAM gVdaRegistryView = KEY_WOW64_64KEY;
bool gPositiveReply = true;
bool gDelayRenewal = false;
bool gNegativeRenewal = false;
std::atomic<unsigned> gAcquireCount{0};
std::atomic<unsigned> gRenewCount{0};
std::atomic<unsigned> gReleaseCount{0};
std::atomic<unsigned> gCloseCount{0};
std::atomic<unsigned> gCancelCount{0};
dencap::Message gLastRequest{};  // Read/written only by the worker.
HANDLE gRenewReadEntered = nullptr;

void Check(bool condition, const char* message) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", message);
    std::exit(1);
  }
}

void Reset() {
  gWtsSuccess = true;
  gWtsProtocol = WTS_PROTOCOL_TYPE_CONSOLE;
  gWtsBytes = sizeof(USHORT);
  gRuntimePresent = false;
  gMissingExport = nullptr;
  gWfProtocol = WTS_PROTOCOL_TYPE_CONSOLE;
  gVdaKeyStatus = ERROR_FILE_NOT_FOUND;
  gVdaRegistryView = KEY_WOW64_64KEY;
  gPositiveReply = true;
  gDelayRenewal = false;
  gNegativeRenewal = false;
  gAcquireCount = gRenewCount = gReleaseCount = gCloseCount = gCancelCount = 0;
  gLastRequest = {};
}
}  // namespace

BOOL WINAPI TestWTSQuerySessionInformationW(HANDLE, DWORD, WTS_INFO_CLASS,
                                           LPWSTR* buffer, DWORD* bytes) {
  *buffer = gWtsSuccess ? reinterpret_cast<LPWSTR>(&gWtsProtocol) : nullptr;
  *bytes = gWtsBytes;
  return gWtsSuccess;
}
void WINAPI TestWTSFreeMemory(PVOID) {}
LSTATUS WINAPI TestRegOpenKeyExW(HKEY, LPCWSTR path, DWORD, REGSAM access,
                               PHKEY key) {
  if (std::wcscmp(path, L"SOFTWARE\\Citrix\\VirtualDesktopAgent") == 0 &&
      (access & gVdaRegistryView)) {
    if (gVdaKeyStatus == ERROR_SUCCESS) {
      *key = reinterpret_cast<HKEY>(1);
    }
    return gVdaKeyStatus;
  }
  return ERROR_FILE_NOT_FOUND;
}
LSTATUS WINAPI TestRegGetValueW(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID,
                              LPDWORD) {
  return ERROR_FILE_NOT_FOUND;
}
LSTATUS WINAPI TestRegCloseKey(HKEY) { return ERROR_SUCCESS; }
DWORD WINAPI TestGetFileAttributesW(LPCWSTR) { return INVALID_FILE_ATTRIBUTES; }
HMODULE WINAPI TestLoadLibraryExW(LPCWSTR, HANDLE, DWORD) {
  return gRuntimePresent ? reinterpret_cast<HMODULE>(1) : nullptr;
}
BOOL WINAPI TestFreeLibrary(HMODULE) { return TRUE; }
INT WINAPI TestGetActiveProtocol(DWORD session) {
  Check(session == 0xFFFFFFFFu, "WFAPI must query the current session");
  return gWfProtocol;
}
HANDLE WINAPI TestChannelOpen(HANDLE, DWORD session, LPSTR name) {
  Check(session == 0xFFFFFFFFu, "channel must open in the current session");
  Check(std::strcmp(name, "DENCAP ") == 0, "channel name must be padded");
  return reinterpret_cast<HANDLE>(1);
}
BOOL WINAPI TestChannelClose(HANDLE) {
  ++gCloseCount;
  return TRUE;
}
BOOL WINAPI TestChannelWrite(HANDLE, PCHAR data, ULONG size, PULONG written) {
  Check(size == sizeof(gLastRequest), "request must be exactly one frame");
  std::memcpy(&gLastRequest, data, size);
  Check(gLastRequest.magic == dencap::kMagic, "request magic");
  Check(!dencap::LeaseIdIsZero(gLastRequest.lease_id), "nonzero lease ID");
  switch (static_cast<dencap::MessageType>(gLastRequest.type)) {
    case dencap::MessageType::kAcquire:
      ++gAcquireCount;
      break;
    case dencap::MessageType::kRenew:
      ++gRenewCount;
      break;
    case dencap::MessageType::kRelease:
      ++gReleaseCount;
      Check(gLastRequest.lease_ms == 0, "RELEASE must not request a lease");
      break;
    default:
      Check(false, "unexpected request type");
  }
  *written = size;
  return TRUE;
}
BOOL WINAPI TestChannelRead(HANDLE, ULONG, PCHAR data, ULONG size,
                           PULONG read) {
  if (gDelayRenewal && gLastRequest.type ==
                           static_cast<uint16_t>(dencap::MessageType::kRenew)) {
    ::SetEvent(gRenewReadEntered);
    ::Sleep(100);
  }
  const bool positive = gPositiveReply &&
      !(gNegativeRenewal && gLastRequest.type ==
          static_cast<uint16_t>(dencap::MessageType::kRenew));
  const auto response = dencap::MakeStatusMessage(
      &gLastRequest,
      positive ? dencap::Status::kOk : dencap::Status::kSetAffinityFailed,
      positive ? ERROR_SUCCESS : ERROR_ACCESS_DENIED,
      positive ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE, ::GetTickCount64(),
      dencap::kDefaultLeaseMs);
  Check(size >= sizeof(response), "read buffer can hold a STATUS frame");
  std::memcpy(data, &response, sizeof(response));
  *read = sizeof(response);
  return TRUE;
}
FARPROC WINAPI TestGetProcAddress(HMODULE, LPCSTR name) {
  if (gMissingExport && std::strcmp(name, gMissingExport) == 0) {
    return nullptr;
  }
  if (std::strcmp(name, "WFVirtualChannelOpen") == 0) {
    return reinterpret_cast<FARPROC>(TestChannelOpen);
  }
  if (std::strcmp(name, "WFVirtualChannelClose") == 0) {
    return reinterpret_cast<FARPROC>(TestChannelClose);
  }
  if (std::strcmp(name, "WFVirtualChannelRead") == 0) {
    return reinterpret_cast<FARPROC>(TestChannelRead);
  }
  if (std::strcmp(name, "WFVirtualChannelWrite") == 0) {
    return reinterpret_cast<FARPROC>(TestChannelWrite);
  }
  if (std::strcmp(name, "WFGetActiveProtocol") == 0) {
    return reinterpret_cast<FARPROC>(TestGetActiveProtocol);
  }
  return nullptr;
}
BOOL WINAPI TestCancelSynchronousIo(HANDLE thread) {
  ++gCancelCount;
  return ::CancelSynchronousIo(thread);
}

// Keep the test independent of linking libxul while production compilation
// below still uses the real generated Mozilla headers without these overrides.
#define mozilla_RandomNum_h_
namespace mozilla {
uint64_t RandomUint64OrDie() {
  static std::atomic<uint64_t> value{1};
  return value++;
}
}  // namespace mozilla

#define WTSQuerySessionInformationW TestWTSQuerySessionInformationW
#define WTSFreeMemory TestWTSFreeMemory
#define RegOpenKeyExW TestRegOpenKeyExW
#define RegGetValueW TestRegGetValueW
#define RegCloseKey TestRegCloseKey
#define GetFileAttributesW TestGetFileAttributesW
#define LoadLibraryExW TestLoadLibraryExW
#define FreeLibrary TestFreeLibrary
#define GetProcAddress TestGetProcAddress
#define CancelSynchronousIo TestCancelSynchronousIo
#include "DenCitrixCaptureProtection.cpp"

int main() {
  using Protection = mozilla::denbrowser::DenCitrixCaptureProtection;
  using Session = Protection::SessionType;

  Reset();
  Check(Protection::GetCurrentSessionType() == Session::kNotIca,
        "ordinary local computer without VDA");
  gWtsProtocol = WTS_PROTOCOL_TYPE_ICA;
  Check(Protection::GetCurrentSessionType() == Session::kIca,
        "WTS ICA does not require WFAPI discovery");
  gVdaKeyStatus = ERROR_SUCCESS;
  gWtsProtocol = WTS_PROTOCOL_TYPE_RDP;
  Check(Protection::GetCurrentSessionType() == Session::kNotIca,
        "direct RDP on a VDA remains ordinary RDP");
  gWtsProtocol = WTS_PROTOCOL_TYPE_CONSOLE;
  Check(Protection::GetCurrentSessionType() == Session::kUnknown,
        "console-shaped VDA with missing WFAPI must not bypass protection");
  gVdaRegistryView = KEY_WOW64_32KEY;
  Check(Protection::GetCurrentSessionType() == Session::kUnknown,
        "VDA marker is checked in both registry views");
  gVdaKeyStatus = ERROR_ACCESS_DENIED;
  Check(Protection::GetCurrentSessionType() == Session::kUnknown,
        "inaccessible VDA marker does not imply ordinary local computer");
  gRuntimePresent = true;
  gWfProtocol = WTS_PROTOCOL_TYPE_CONSOLE;
  Check(Protection::GetCurrentSessionType() == Session::kNotIca,
        "confirmed console on VDA remains local");
  gWfProtocol = WTS_PROTOCOL_TYPE_ICA;
  Check(Protection::GetCurrentSessionType() == Session::kIca,
        "WFAPI identifies console-shaped ICA session");
  gWtsSuccess = false;
  Check(Protection::GetCurrentSessionType() == Session::kIca,
        "WFAPI classifies ICA after WTS query failure");
  gWtsSuccess = true;
  gWtsBytes = 0;
  Check(Protection::GetCurrentSessionType() == Session::kIca,
        "WFAPI classifies ICA after truncated WTS response");
  gWfProtocol = -1;
  Check(Protection::GetCurrentSessionType() == Session::kUnknown,
        "WFAPI unknown result must not bypass protection");
  gVdaKeyStatus = ERROR_FILE_NOT_FOUND;
  gMissingExport = "WFGetActiveProtocol";
  Check(Protection::GetCurrentSessionType() == Session::kUnknown,
        "WFAPI missing protocol export must not bypass protection");
  gMissingExport = "WFVirtualChannelWrite";
  Check(Protection::GetCurrentSessionType() == Session::kUnknown,
        "broken channel runtime is remembered even without VDA marker");
  std::puts("PASS: session detection (13 cases)");

  Reset();
  { Protection guard; Check(!guard.Start(), "missing runtime denies startup"); }
  Check(gAcquireCount == 0, "missing runtime sends no ACQUIRE");
  gRuntimePresent = true;
  gPositiveReply = false;
  { Protection guard; Check(!guard.Start(), "negative ACK denies startup"); }
  Check(gAcquireCount == 1 && gCloseCount == 1 && gReleaseCount == 0,
        "failed startup closes channel without an acquired lease");
  std::puts("PASS: missing runtime and negative startup ACK");

  Reset();
  gRuntimePresent = true;
  {
    auto guard = std::make_unique<Protection>();
    Check(guard->Start(), "positive ACK allows startup");
    guard.reset();  // Same explicit pre-XPCOM shutdown as nsAppRunner.
    Check(gReleaseCount == 1 && gCloseCount == 1,
          "orderly reset sends RELEASE before returning");
  }
  Check(gCancelCount == 0, "normal shutdown does not cancel the channel");
  std::puts("PASS: normal close sends RELEASE");

  for (const bool negative : {false, true}) {
    Reset();
    gRuntimePresent = true;
    gDelayRenewal = true;
    gNegativeRenewal = negative;
    gRenewReadEntered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(gRenewReadEntered != nullptr, "create renewal synchronization event");
    auto guard = std::make_unique<Protection>();
    Check(guard->Start(), "start lease for in-flight renewal test");
    Check(::WaitForSingleObject(gRenewReadEntered, 8000) == WAIT_OBJECT_0,
          "renewal reaches the pending read");
    guard.reset();
    Check(gRenewCount == 1 && gReleaseCount == 1 && gCloseCount == 1,
          "shutdown during renewal sends RELEASE on the live channel");
    Check(gCancelCount == 0, "bounded pending read completes without cancellation");
    ::CloseHandle(gRenewReadEntered);
    std::puts(negative ? "PASS: close during negative in-flight renewal sends RELEASE"
                       : "PASS: close during positive in-flight renewal sends RELEASE");
  }
  return 0;
}
