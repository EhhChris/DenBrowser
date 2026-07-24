#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <string_view>

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace {

void PrintUsage() {
  std::wcerr
      << L"Usage:\n"
      << L"  dencap_hwnd_probe.exe --hwnd <decimal-or-0x-hex> [--apply]\n"
      << L"  dencap_hwnd_probe.exe --self-test\n"
      << L"  Without --apply the probe is read-only.\n"
      << L"  --apply is refused unless the HWND is top-level and owned by this "
         L"process.\n";
}

bool ParseHwnd(const wchar_t *text, HWND *hwnd) {
  if (text == nullptr || *text == L'\0') {
    return false;
  }
  wchar_t *end = nullptr;
  errno = 0;
  const unsigned long long value = std::wcstoull(text, &end, 0);
  if (errno != 0 || end == text || *end != L'\0') {
    return false;
  }
  *hwnd = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(value));
  return true;
}

LRESULT CALLBACK ProbeWindowProc(HWND hwnd, UINT message, WPARAM wparam,
                                 LPARAM lparam) {
  return ::DefWindowProcW(hwnd, message, wparam, lparam);
}

int ProbeAndMaybeApply(HWND hwnd, bool apply) {
  const HWND root = ::GetAncestor(hwnd, GA_ROOT);
  DWORD owner_pid = 0;
  ::GetWindowThreadProcessId(hwnd, &owner_pid);
  const DWORD current_pid = ::GetCurrentProcessId();
  const bool is_window = ::IsWindow(hwnd) != FALSE;
  const bool is_top_level = is_window && root == hwnd;
  const bool owned_by_process = owner_pid != 0 && owner_pid == current_pid;

  std::wcout << L"HWND:             0x" << std::hex
             << reinterpret_cast<std::uintptr_t>(hwnd) << L"\n"
             << L"Root HWND:        0x"
             << reinterpret_cast<std::uintptr_t>(root) << L"\n"
             << std::dec << L"Owner PID:        " << owner_pid << L"\n"
             << L"Probe process PID:" << current_pid << L"\n"
             << L"IsWindow:         " << (is_window ? L"yes" : L"no") << L"\n"
             << L"Top-level:        " << (is_top_level ? L"yes" : L"no")
             << L"\n"
             << L"Same process:     " << (owned_by_process ? L"yes" : L"no")
             << L"\n";

  DWORD previous = WDA_NONE;
  if (is_window && ::GetWindowDisplayAffinity(hwnd, &previous)) {
    std::wcout << L"Current affinity: 0x" << std::hex << previous << std::dec
               << L"\n";
  } else {
    std::wcerr << L"GetWindowDisplayAffinity failed: " << ::GetLastError()
               << L"\n";
    if (apply) {
      return 4;
    }
  }

  if (!is_window || !is_top_level || !owned_by_process) {
    std::wcerr << L"GO/NO-GO: NO-GO. SetWindowDisplayAffinity must run in "
                  L"the process that owns the top-level window.\n";
    return 3;
  }

  std::wcout << L"GO/NO-GO: GO\n";
  if (!apply) {
    return 0;
  }

  if (!::SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
    std::wcerr << L"SetWindowDisplayAffinity failed: " << ::GetLastError()
               << L"\n";
    return 5;
  }
  DWORD observed = WDA_NONE;
  if (!::GetWindowDisplayAffinity(hwnd, &observed) ||
      observed != WDA_EXCLUDEFROMCAPTURE) {
    std::wcerr << L"Affinity read-back was not WDA_EXCLUDEFROMCAPTURE (0x11): "
               << L"0x" << std::hex << observed << std::dec << L"\n";
    ::SetWindowDisplayAffinity(hwnd, previous);
    return 6;
  }

  std::wcout << L"WDA_EXCLUDEFROMCAPTURE applied and verified; restoring 0x"
             << std::hex << previous << std::dec << L".\n";
  if (!::SetWindowDisplayAffinity(hwnd, previous)) {
    std::wcerr << L"Restore failed: " << ::GetLastError() << L"\n";
    return 7;
  }
  return 0;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  HWND hwnd = nullptr;
  bool apply = false;
  bool self_test = false;

  for (int index = 1; index < argc; ++index) {
    const std::wstring_view argument(argv[index]);
    if (argument == L"--hwnd" && index + 1 < argc) {
      if (!ParseHwnd(argv[++index], &hwnd)) {
        PrintUsage();
        return 2;
      }
    } else if (argument == L"--apply") {
      apply = true;
    } else if (argument == L"--self-test") {
      self_test = true;
    } else {
      PrintUsage();
      return 2;
    }
  }

  if (self_test) {
    if (hwnd != nullptr || apply || argc != 2) {
      PrintUsage();
      return 2;
    }

    const HINSTANCE instance = ::GetModuleHandleW(nullptr);
    const wchar_t class_name[] = L"DenCapWdaSelfTestWindow";
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = &ProbeWindowProc;
    window_class.hInstance = instance;
    window_class.lpszClassName = class_name;
    const ATOM atom = ::RegisterClassExW(&window_class);
    if (atom == 0) {
      std::wcerr << L"RegisterClassExW failed: " << ::GetLastError() << L"\n";
      return 8;
    }

    HWND test_hwnd =
        ::CreateWindowExW(WS_EX_TOOLWINDOW, class_name, L"DENCAP WDA self-test",
                          WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                          320, 200, nullptr, nullptr, instance, nullptr);
    if (test_hwnd == nullptr) {
      const DWORD error = ::GetLastError();
      ::UnregisterClassW(class_name, instance);
      std::wcerr << L"CreateWindowExW failed: " << error << L"\n";
      return 9;
    }

    const int result = ProbeAndMaybeApply(test_hwnd, true);
    ::DestroyWindow(test_hwnd);
    ::UnregisterClassW(class_name, instance);
    return result;
  }

  if (hwnd == nullptr) {
    PrintUsage();
    return 2;
  }
  return ProbeAndMaybeApply(hwnd, apply);
}
