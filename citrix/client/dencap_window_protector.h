#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>

#include "../protocol/dencap_protocol.h"

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace dencap {

struct WindowQueryResult {
  Status status = Status::kIcaWindowQueryFailed;
  DWORD win32_error = ERROR_SUCCESS;
  HWND hwnd = nullptr;
};

class IWindowSource {
public:
  virtual ~IWindowSource() = default;
  virtual WindowQueryResult QueryIcaWindow() noexcept = 0;
};

struct ProtectionResult {
  Status status = Status::kOk;
  DWORD win32_error = ERROR_SUCCESS;
  DWORD observed_affinity = WDA_NONE;

  [[nodiscard]] bool ok() const noexcept { return status == Status::kOk; }
};

class IProtectionController {
public:
  virtual ~IProtectionController() = default;
  virtual ProtectionResult Protect() noexcept = 0;
  virtual ProtectionResult Restore() noexcept = 0;
};

struct OwnershipProbeResult {
  Status status = Status::kOk;
  DWORD win32_error = ERROR_SUCCESS;
  HWND hwnd = nullptr;
  HWND root_hwnd = nullptr;
  DWORD owner_pid = 0;
  DWORD current_pid = 0;
  DWORD observed_affinity = WDA_NONE;

  [[nodiscard]] bool ok() const noexcept { return status == Status::kOk; }
};

// SetWindowDisplayAffinity is intentionally called only after proving that the
// queried ICA HWND is a top-level window owned by this process.
class WindowProtector final : public IProtectionController {
public:
  static constexpr std::size_t kMaxClaimedWindows = 16;

  explicit WindowProtector(IWindowSource &source) noexcept;
  ~WindowProtector();

  WindowProtector(const WindowProtector &) = delete;
  WindowProtector &operator=(const WindowProtector &) = delete;

  OwnershipProbeResult Probe() noexcept;
  ProtectionResult Protect() noexcept override;
  ProtectionResult Restore() noexcept override;

private:
  struct ClaimedWindow {
    HWND hwnd = nullptr;
    DWORD previous_affinity = WDA_NONE;
    DWORD last_written_affinity = WDA_NONE;
    bool wrote_affinity = false;
    bool active = false;
  };

  OwnershipProbeResult ProbeWindow(HWND hwnd) noexcept;
  std::size_t FindClaim(HWND hwnd) const noexcept;
  std::size_t FindEmptyClaim() const noexcept;
  void EraseClaim(std::size_t index) noexcept;
  ProtectionResult RestoreClaimLocked(std::size_t index) noexcept;
  ProtectionResult RestoreLocked() noexcept;

  IWindowSource &source_;
  std::mutex mutex_;
  std::array<ClaimedWindow, kMaxClaimedWindows> claims_{};
  HWND current_hwnd_ = nullptr;
};

} // namespace dencap
