// Drive the actual Driver* entry points through a fake WinStation driver. No
// Workspace installation or ICA connection is required. Window-affinity checks
// use this process's hidden windows and a hidden helper owned by the test.
#include "../client/dencap_citrix_adapter.h"
extern "C" {
#include <clterr.h>
#include <ica-c2h.h>
int DriverOpen(PVD, PVDOPEN, PUINT16);
int DriverClose(PVD, PDLLCLOSE, PUINT16);
int DriverInfo(PVD, PDLLINFO, PUINT16);
int DriverPoll(PVD, PVOID, PUINT16);
int DriverSetInformation(PVD, PVDSETINFORMATION, PUINT16);
int DriverGetLastError(PVD, PVDLASTERROR);
}

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

void Require(bool condition, const char *reason) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s (win32=%lu)\n", reason, ::GetLastError());
    std::exit(1);
  }
}

// A separate copy of this executable owns the foreign root. Its helper loop
// processes window messages so a test-owned rendering child can be parented to
// that root, matching the case where Workspace and Desktop Viewer differ.
int RunForeignWindowHelper(HANDLE stop) {
  HWND window = ::CreateWindowExW(0, L"STATIC", L"DENCAP foreign test root",
      WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, nullptr, nullptr,
      ::GetModuleHandleW(nullptr), nullptr);
  if (window == nullptr) {
    return 2;
  }
  const UINT_PTR value = reinterpret_cast<UINT_PTR>(window);
  DWORD written = 0;
  if (!::WriteFile(::GetStdHandle(STD_OUTPUT_HANDLE), &value, sizeof(value),
                   &written, nullptr) || written != sizeof(value)) {
    ::DestroyWindow(window);
    return 3;
  }
  const auto deadline = ::GetTickCount64() + 20'000;
  while (::GetTickCount64() < deadline) {
    const DWORD result = ::MsgWaitForMultipleObjects(1, &stop, FALSE, 1000, QS_ALLINPUT);
    if (result == WAIT_OBJECT_0) {
      break;
    }
    if (result != WAIT_OBJECT_0 + 1 && result != WAIT_TIMEOUT) {
      ::DestroyWindow(window);
      return 4;
    }
    MSG message{};
    while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
      ::TranslateMessage(&message);
      ::DispatchMessageW(&message);
    }
  }
  DWORD affinity = 0;
  const BOOL observed = ::GetWindowDisplayAffinity(window, &affinity);
  ::DestroyWindow(window);
  ::CloseHandle(stop);
  return observed && affinity == WDA_NONE ? 0 : 5;
}

class ForeignWindow {
public:
  ForeignWindow() {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    stop_ = ::CreateEventW(&security, TRUE, FALSE, nullptr);
    Require(stop_ != nullptr, "create foreign-window stop event");
    HANDLE reader = nullptr;
    HANDLE writer = nullptr;
    Require(::CreatePipe(&reader, &writer, &security, 0) != FALSE,
            "create foreign-window result pipe");
    Require(::SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0) != FALSE,
            "keep pipe reader private to test parent");
    wchar_t executable[MAX_PATH]{};
    const DWORD length = ::GetModuleFileNameW(nullptr, executable, MAX_PATH);
    Require(length != 0 && length < MAX_PATH, "find test helper executable");
    wchar_t command[MAX_PATH + 80]{};
    swprintf_s(command, L"\"%s\" --foreign-window %llu", executable,
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(stop_)));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = writer;
    startup.hStdError = writer;
    Require(::CreateProcessW(executable, command, nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                             &process_) != FALSE,
            "start hidden foreign-window helper");
    ::CloseHandle(writer);
    UINT_PTR value = 0;
    DWORD received = 0;
    const BOOL read = ::ReadFile(reader, &value, sizeof(value), &received, nullptr);
    ::CloseHandle(reader);
    window_ = reinterpret_cast<HWND>(value);
    Require(read && received == sizeof(value) && ::IsWindow(window_),
            "receive foreign top-level HWND");
    DWORD owner = 0;
    ::GetWindowThreadProcessId(window_, &owner);
    Require(owner == process_.dwProcessId && owner != ::GetCurrentProcessId(),
            "test root belongs to another process");
  }
  ~ForeignWindow() {
    ::SetEvent(stop_);
    Require(::WaitForSingleObject(process_.hProcess, 5000) == WAIT_OBJECT_0,
            "foreign-window helper exits");
    DWORD exit_code = 0;
    Require(::GetExitCodeProcess(process_.hProcess, &exit_code) && exit_code == 0,
            "foreign root affinity remained unchanged");
    ::CloseHandle(process_.hThread);
    ::CloseHandle(process_.hProcess);
    ::CloseHandle(stop_);
  }
  HWND get() const noexcept { return window_; }

private:
  HANDLE stop_ = nullptr;
  PROCESS_INFORMATION process_{};
  HWND window_ = nullptr;
};

struct Session;
std::array<Session *, 8> sessions{};
struct Session {
  explicit Session(bool use_hpc, HWND hwnd) : hpc(use_hpc), window(hwnd) {
    for (std::size_t index = 1; index < sessions.size(); ++index) {
      if (sessions[index] == nullptr) {
        id = static_cast<DWORD>(index);
        sessions[index] = this;
        break;
      }
    }
    Require(id != 0, "free fake session slot");
    vd.pWdLink = reinterpret_cast<PDLLLINK>(this);
  }
  ~Session() {
    Close();
    sessions[id] = nullptr;
  }
  void Open() {
    VDOPEN open{};
    UINT16 size = sizeof(open);
    Require(DriverOpen(&vd, &open, &size) == CLIENT_STATUS_SUCCESS, "DriverOpen");
    Require(size == sizeof(open), "DriverOpen output size");
    Require(hook != nullptr, "arrival hook registered");
    Require(!hpc || polling_options == 0, "HPC periodic polling enabled");
  }
  void Close() {
    if (vd.pPrivate != nullptr) {
      Require(DriverClose(&vd, nullptr, nullptr) == CLIENT_STATUS_SUCCESS,
              "DriverClose");
      Require(vd.pPrivate == nullptr, "DriverClose cleared private state");
    }
  }
  int Poll() {
    DLLPOLL poll{};
    UINT16 size = sizeof(poll);
    return DriverPoll(&vd, &poll, &size);
  }
  void Deliver(const void *bytes, std::size_t length) {
    Require(length <= 65535, "test delivery fits SDK USHORT");
    hook(hook_context, channel,
         const_cast<LPBYTE>(static_cast<const BYTE *>(bytes)),
         static_cast<USHORT>(length));
  }
  int Send(const BYTE *bytes, std::size_t length) {
    Require(length == sizeof(dencap::Message), "each output is exactly 64 bytes");
    ++send_attempts;
    if (send_result != CLIENT_STATUS_SUCCESS) {
      return send_result;
    }
    dencap::Message response{};
    std::memcpy(&response, bytes, sizeof(response));
    Require(response.type == static_cast<USHORT>(dencap::MessageType::kStatus),
            "each output is STATUS");
    sent.push_back(response);
    return CLIENT_STATUS_SUCCESS;
  }

  VD vd{};
  DWORD id = 0;
  USHORT channel = 25;
  bool hpc;
  HWND window = nullptr;
  PVDWRITEPROCEDURE hook = nullptr;
  PVOID hook_context = nullptr;
  PFNWD_WINDOWCHANGED window_callback = nullptr;
  ULONG polling_options = 0xFFFFFFFF;
  int query_count = 0;
  int send_attempts = 0;
  int send_result = CLIENT_STATUS_SUCCESS;
  int unregister_count = 0;
  bool fail_unregister = false;
  std::vector<dencap::Message> sent;
};

int WFCAPI FakeQueue(PVOID wd, USHORT channel, LPMEMORY_SECTION sections,
                     USHORT count, UINT32) {
  const auto id = reinterpret_cast<ULONG_PTR>(wd);
  Require(id < sessions.size() && sessions[id] != nullptr, "legacy WD handle");
  Session &session = *sessions[id];
  Require(!session.hpc && channel == session.channel && count == 1,
          "legacy output route");
  return session.Send(sections[0].pSection, sections[0].length);
}

int WFCAPI FakeSend(DWORD wd, USHORT channel, LPBYTE bytes, USHORT length,
                    LPVOID, UINT32 flags) {
  Require(wd < sessions.size() && sessions[wd] != nullptr, "HPC WD handle");
  Session &session = *sessions[wd];
  Require(session.hpc && channel == session.channel && flags == 0,
          "HPC polled output route");
  return session.Send(bytes, length);
}

dencap::Message Request(dencap::MessageType type, std::uint64_t sequence,
                        std::uint32_t lease_ms = 1000) {
  dencap::Message message{};
  message.magic = dencap::kMagic;
  message.version = dencap::kProtocolVersion;
  message.size = sizeof(message);
  message.type = static_cast<USHORT>(type);
  message.lease_id[0] = 1;
  message.sequence = sequence;
  message.lease_ms = type == dencap::MessageType::kRelease ? 0 : lease_ms;
  return message;
}

DWORD Affinity(HWND window) {
  DWORD affinity = 0;
  Require(::GetWindowDisplayAffinity(window, &affinity) != FALSE, "read affinity");
  return affinity;
}

void TestInfo() {
  DLLINFO info{};
  UINT16 size = 0;
  Require(DriverInfo(nullptr, &info, &size) == CLIENT_ERROR_BUFFER_TOO_SMALL,
          "DriverInfo size negotiation");
  Require(info.ByteCount == sizeof(VD_C2H) && size == sizeof(DLLINFO),
          "DriverInfo exact SDK structure sizes");
  VD_C2H header{};
  info.pBuffer = reinterpret_cast<LPBYTE>(&header);
  Require(DriverInfo(nullptr, &info, &size) == CLIENT_STATUS_SUCCESS,
          "DriverInfo writes handshake");
  Require(header.Header.ByteCount == sizeof(header) &&
              header.Header.ModuleClass == Module_VirtualDriver &&
              header.Header.VersionL == dencap::kProtocolVersion &&
              header.Header.VersionH == dencap::kProtocolVersion &&
              header.Flow.Flow == VirtualFlow_None &&
              std::strcmp(reinterpret_cast<const char *>(header.Header.HostModuleName), "ICA") == 0,
          "DriverInfo handshake content");
}

void TestTransport(bool hpc, HWND foreign_root) {
  Session session(hpc, foreign_root);
  session.Open();
  auto first = Request(dencap::MessageType::kAcquire, 1);
  session.Deliver(&first, 7);
  Require(session.query_count == 0 && session.sent.empty(),
          "arrival performs no window query or write");
  Require(session.Poll() == CLIENT_STATUS_SUCCESS && session.sent.empty(),
          "partial frame retained");
  session.Deliver(reinterpret_cast<const BYTE *>(&first) + 7, sizeof(first) - 7);
  Require(session.Poll() == CLIENT_STATUS_SUCCESS && session.sent.size() == 1,
          "fragmented request gets one response");
  Require(session.sent[0].sequence == 1 &&
              session.sent[0].status == static_cast<ULONG>(dencap::Status::kWindowOwnershipFailed),
          "permanent ownership failure is explicit, correlated STATUS");

  std::array<dencap::Message, 2> pair{
      Request(dencap::MessageType::kAcquire, 2),
      Request(dencap::MessageType::kAcquire, 3)};
  session.send_result = CLIENT_ERROR_NO_OUTBUF;
  session.Deliver(pair.data(), sizeof(pair));
  Require(session.Poll() == CLIENT_STATUS_ERROR_RETRY && session.sent.size() == 1,
          "backpressure retains both complete responses");
  session.send_result = CLIENT_STATUS_SUCCESS;
  Require(session.Poll() == CLIENT_STATUS_SUCCESS && session.sent.size() == 3,
          "backpressure retry drains responses");
  Require(session.sent[1].sequence == 2 && session.sent[2].sequence == 3,
          "coalesced requests preserve response ordering");
  Require(session.Poll() == CLIENT_STATUS_SUCCESS,
          "idle poll requests continued periodic polling");
}

void TestIsolation(HWND foreign_root) {
  Session first(false, foreign_root);
  Session second(true, foreign_root);
  first.Open();
  second.Open();
  auto request = Request(dencap::MessageType::kAcquire, 41);
  first.Deliver(&request, 32);
  request.sequence = 42;
  second.Deliver(&request, sizeof(request));
  second.Poll();
  first.Poll();
  Require(first.sent.empty() && second.sent.size() == 1 && second.sent[0].sequence == 42,
          "PVD sessions do not share framing or transport");
}

void TestDelayedWindowAndLease(HWND top) {
  Session session(true, nullptr);
  session.Open();
  auto request = Request(dencap::MessageType::kAcquire, 1);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(session.sent.empty(), "missing initial HWND retains request for retry");
  session.window = top;
  ::Sleep(1050);
  session.Poll();
  Require(session.sent.size() == 1 &&
              session.sent[0].status == static_cast<ULONG>(dencap::Status::kOk),
          "retryable HWND initialization eventually acquires protection");
  Require(Affinity(top) == WDA_EXCLUDEFROMCAPTURE,
          "ACQUIRE protects actual owned top-level window");
  ::Sleep(1050);
  Require(session.Poll() == CLIENT_STATUS_SUCCESS && Affinity(top) == WDA_NONE,
          "idle polling expires lease and restores actual window");

  request = Request(dencap::MessageType::kAcquire, 2);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(Affinity(top) == WDA_EXCLUDEFROMCAPTURE, "reacquire after idle expiry");
  request = Request(dencap::MessageType::kRelease, 3);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(Affinity(top) == WDA_NONE, "RELEASE restores immediately on poll");

  session.send_result = CLIENT_ERROR_NO_OUTBUF;
  request = Request(dencap::MessageType::kAcquire, 4);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  const auto sent_before_expiry = session.sent.size();
  Require(Affinity(top) == WDA_EXCLUDEFROMCAPTURE,
          "lease installed while acknowledgement awaits output capacity");
  ::Sleep(1050);
  session.send_result = CLIENT_STATUS_SUCCESS;
  session.Poll();
  Require(session.sent.size() == sent_before_expiry + 1 &&
              session.sent.back().status == static_cast<ULONG>(dencap::Status::kLeaseNotFound) &&
              session.sent.back().win32_error == ERROR_TIMEOUT && Affinity(top) == WDA_NONE,
          "expired queued acknowledgement cannot report successful protection");
  session.Close();
  Require(session.unregister_count == 1, "window callback unregistered on close");
}

void TestChildResolvesToRoot(HWND child, HWND root, HWND unrelated_owner = nullptr) {
  Require(::GetAncestor(child, GA_ROOT) == root, "test child has expected parent root");
  Session session(true, child);
  session.Open();
  dencap::CitrixWindowSource source(&session.vd);
  Require(source.QueryIcaWindow().hwnd == root, "SDK child resolves to parent root");
  auto request = Request(dencap::MessageType::kAcquire, 1);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(session.sent.size() == 1 &&
              session.sent[0].status == static_cast<ULONG>(dencap::Status::kOk) &&
              session.sent[0].observed_affinity == WDA_EXCLUDEFROMCAPTURE &&
              Affinity(root) == WDA_EXCLUDEFROMCAPTURE,
          "SDK rendering child permits protection of its owned top-level root");
  if (unrelated_owner != nullptr) {
    Require(Affinity(unrelated_owner) == WDA_NONE,
            "owner window outside the parent chain remains unchanged");
  }
  request = Request(dencap::MessageType::kRelease, 2);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(Affinity(root) == WDA_NONE, "release restores normalized root affinity");
}

void TestForeignRootIsRejected(HWND foreign_root) {
  HWND child = ::CreateWindowExW(0, L"STATIC", L"DENCAP cross-process test child",
      WS_CHILD, 0, 0, 50, 50, foreign_root, nullptr,
      ::GetModuleHandleW(nullptr), nullptr);
  Require(child != nullptr && ::GetAncestor(child, GA_ROOT) == foreign_root,
          "create own rendering child beneath foreign root");
  DWORD owner = 0;
  ::GetWindowThreadProcessId(child, &owner);
  Require(owner == ::GetCurrentProcessId(), "rendering child belongs to test process");
  Session session(true, child);
  session.Open();
  auto request = Request(dencap::MessageType::kAcquire, 1);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(session.sent.size() == 1 &&
              session.sent[0].status == static_cast<ULONG>(dencap::Status::kWindowOwnershipFailed) &&
              session.sent[0].win32_error == ERROR_ACCESS_DENIED &&
              session.window_callback == nullptr,
          "own child cannot authorize modifying a foreign top-level root");
  session.Close();
  ::DestroyWindow(child);
}

void TestOverflowAndPurge(HWND child) {
  Session session(false, child);
  session.Open();
  std::array<BYTE, 65535> excess{};
  session.Deliver(excess.data(), excess.size());
  session.Deliver(excess.data(), 2);
  session.Poll();
  auto request = Request(dencap::MessageType::kAcquire, 99);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(session.sent.empty(), "overflow cannot resume from unknown frame boundary");
  VDLASTERROR error{};
  DriverGetLastError(&session.vd, &error);
  Require(error.Error != 0, "overflow recorded as channel error");

  Session purged(false, child);
  purged.Open();
  VDFLUSH flush{};
  flush.Channel = static_cast<UCHAR>(purged.channel);
  flush.Mask = VDFLUSH_MASK_PURGEOUTPUT;
  VDSETINFORMATION set{};
  set.VdInformationClass = VdFlush;
  set.pVdInformation = &flush;
  set.VdInformationLength = sizeof(flush);
  Require(DriverSetInformation(&purged.vd, &set, nullptr) == CLIENT_STATUS_SUCCESS,
          "purge handled");
  purged.Deliver(&request, sizeof(request));
  purged.Poll();
  Require(purged.sent.empty(), "purge requires reconnect instead of unsafe reframing");
}

void TestDisableAndFailedUnregister(HWND top) {
  Session session(true, top);
  session.Open();
  auto request = Request(dencap::MessageType::kAcquire, 1);
  session.Deliver(&request, sizeof(request));
  session.Poll();
  Require(Affinity(top) == WDA_EXCLUDEFROMCAPTURE, "acquire before disable");
  session.fail_unregister = true;
  VDSETINFORMATION set{};
  set.VdInformationClass = VdDisableModule;
  Require(DriverSetInformation(&session.vd, &set, nullptr) == CLIENT_STATUS_SUCCESS,
          "disable succeeds");
  Require(Affinity(top) == WDA_NONE, "disable releases leases");
  auto callback = session.window_callback;
  Require(callback != nullptr, "fake Workspace retained failing callback");
  session.Close();
  callback(0);
  Require(session.unregister_count >= 1, "failed unregister attempted before close");
}

} // namespace

// This definition resolves the real adapter/driver's SDK calls in this executable.
// The DLL target still links the unmodified Citrix vdapi.lib implementation.
extern "C" int VdCallWd(PVD vd, USHORT procedure, PVOID parameter, PUINT16) {
  Session &session = *reinterpret_cast<Session *>(vd->pWdLink);
  if (procedure == WDxQUERYINFORMATION) {
    auto &query = *static_cast<WDQUERYINFORMATION *>(parameter);
    switch (query.WdInformationClass) {
    case WdOpenVirtualChannel: {
      auto &channel = *static_cast<OPENVIRTUALCHANNEL *>(query.pWdInformation);
      Require(std::memcmp(channel.pVCName, dencap::kWfApiChannelName, 8) == 0,
              "SDK and WFAPI use identical padded channel name");
      channel.Channel = session.channel;
      return CLIENT_STATUS_SUCCESS;
    }
    case WdVirtualWriteHookEx: {
      auto &extended = *static_cast<VDWRITEHOOKEX *>(query.pWdInformation);
      extended.usVersion = session.hpc ? HPC_VD_API_VERSION_V1 : HPC_VD_API_VERSION_LEGACY;
      extended.pSendDataProc = session.hpc ? &FakeSend : nullptr;
      return CLIENT_STATUS_SUCCESS;
    }
    case WdGetICAWindowInfo:
      ++session.query_count;
      static_cast<WDICAWINDOWINFO *>(query.pWdInformation)->hwnd = session.window;
      return CLIENT_STATUS_SUCCESS;
    case WdRegisterWindowChangeCallback: {
      auto &callback = *static_cast<WDREGISTERWINDOWCALLBACKPARAMS *>(query.pWdInformation);
      callback.Handle = 123;
      session.window_callback = callback.pfnCallback;
      return CLIENT_STATUS_SUCCESS;
    }
    case WdUnregisterWindowChangeCallback:
      ++session.unregister_count;
      if (session.fail_unregister) {
        return CLIENT_ERROR_INVALID_PARAMETER;
      }
      session.window_callback = nullptr;
      return CLIENT_STATUS_SUCCESS;
    default:
      return CLIENT_ERROR_INVALID_PARAMETER;
    }
  }
  if (procedure == WDxSETINFORMATION) {
    auto &set = *static_cast<WDSETINFORMATION *>(parameter);
    if (set.WdInformationClass == WdVirtualWriteHook) {
      auto &hook = *static_cast<VDWRITEHOOK *>(set.pWdInformation);
      session.hook = hook.pProc;
      session.hook_context = hook.pVdData;
      hook.pWdData = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(session.id));
      hook.pQueueVirtualWriteProc = &FakeQueue;
      hook.MaximumWriteSize = 4096;
      return CLIENT_STATUS_SUCCESS;
    }
    if (set.WdInformationClass == WdHpcProperties) {
      session.polling_options =
          static_cast<WDSET_HPC_PROPERITES *>(set.pWdInformation)->ulVdOptions;
      return CLIENT_STATUS_SUCCESS;
    }
  }
  return CLIENT_ERROR_INVALID_PARAMETER;
}

int __cdecl main(int argc, char **argv) {
  if (argc == 3 && std::strcmp(argv[1], "--foreign-window") == 0) {
    return RunForeignWindowHelper(reinterpret_cast<HANDLE>(
        static_cast<UINT_PTR>(std::strtoull(argv[2], nullptr, 10))));
  }
  ForeignWindow foreign;
  HWND top = ::CreateWindowExW(0, L"STATIC", L"DENCAP test owned window",
                                WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, nullptr,
                                nullptr, ::GetModuleHandleW(nullptr), nullptr);
  Require(top != nullptr, "create owned top-level window");
  HWND child = ::CreateWindowExW(0, L"STATIC", L"DENCAP test child", WS_CHILD,
                                  0, 0, 50, 50, top, nullptr,
                                  ::GetModuleHandleW(nullptr), nullptr);
  Require(child != nullptr, "create SDK rendering child");
  TestInfo();
  TestTransport(false, foreign.get());
  TestTransport(true, foreign.get());
  TestIsolation(foreign.get());
  TestChildResolvesToRoot(child, top);
  TestForeignRootIsRejected(foreign.get());
  HWND popup = ::CreateWindowExW(0, L"STATIC", L"DENCAP test owned popup",
      WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 100, 100, top, nullptr,
      ::GetModuleHandleW(nullptr), nullptr);
  HWND popup_child = ::CreateWindowExW(0, L"STATIC", L"DENCAP popup rendering child",
      WS_CHILD, 0, 0, 50, 50, popup, nullptr,
      ::GetModuleHandleW(nullptr), nullptr);
  Require(popup != nullptr && popup_child != nullptr &&
              ::GetAncestor(popup_child, GA_ROOTOWNER) == top,
          "owned-popup fixture distinguishes root from root owner");
  TestChildResolvesToRoot(popup_child, popup, top);
  ::DestroyWindow(popup);
  TestDelayedWindowAndLease(top);
  TestOverflowAndPurge(child);
  TestDisableAndFailedUnregister(top);
  ::DestroyWindow(top);
  std::puts("DENCAP driver lifecycle, framing, backpressure, isolation, HWND retry, lease expiry, release, overflow and disable checks passed.");
  return 0;
}
