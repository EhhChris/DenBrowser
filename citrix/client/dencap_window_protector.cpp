#include "dencap_window_protector.h"

namespace dencap {
namespace {

ProtectionResult FromProbe(const OwnershipProbeResult &probe) noexcept {
  return ProtectionResult{probe.status, probe.win32_error,
                          probe.observed_affinity};
}

} // namespace

WindowProtector::WindowProtector(IWindowSource &source) noexcept
    : source_(source) {}

WindowProtector::~WindowProtector() { Restore(); }

OwnershipProbeResult WindowProtector::ProbeWindow(HWND hwnd) noexcept {
  OwnershipProbeResult result{};
  result.hwnd = hwnd;
  result.current_pid = ::GetCurrentProcessId();

  if (hwnd == nullptr || !::IsWindow(hwnd)) {
    result.status = Status::kWindowOwnershipFailed;
    result.win32_error = ERROR_INVALID_WINDOW_HANDLE;
    return result;
  }

  result.root_hwnd = ::GetAncestor(hwnd, GA_ROOT);
  ::GetWindowThreadProcessId(hwnd, &result.owner_pid);
  if (result.root_hwnd != hwnd || result.owner_pid == 0 ||
      result.owner_pid != result.current_pid) {
    result.status = Status::kWindowOwnershipFailed;
    result.win32_error = ERROR_ACCESS_DENIED;
    return result;
  }

  if (!::GetWindowDisplayAffinity(hwnd, &result.observed_affinity)) {
    result.status = Status::kGetAffinityFailed;
    result.win32_error = ::GetLastError();
    return result;
  }

  result.status = Status::kOk;
  result.win32_error = ERROR_SUCCESS;
  return result;
}

OwnershipProbeResult WindowProtector::Probe() noexcept {
  const WindowQueryResult query = source_.QueryIcaWindow();
  if (query.status != Status::kOk) {
    OwnershipProbeResult result{};
    result.status = query.status;
    result.win32_error = query.win32_error;
    result.hwnd = query.hwnd;
    result.current_pid = ::GetCurrentProcessId();
    return result;
  }
  return ProbeWindow(query.hwnd);
}

ProtectionResult WindowProtector::Protect() noexcept {
  std::scoped_lock lock(mutex_);

  const WindowQueryResult query = source_.QueryIcaWindow();
  if (query.status != Status::kOk) {
    return ProtectionResult{query.status, query.win32_error, WDA_NONE};
  }

  OwnershipProbeResult probe = ProbeWindow(query.hwnd);
  if (!probe.ok()) {
    return FromProbe(probe);
  }

  std::size_t claim_index = FindClaim(query.hwnd);
  if (claim_index == kMaxClaimedWindows) {
    claim_index = FindEmptyClaim();
    if (claim_index == kMaxClaimedWindows) {
      // Sixteen old HWNDs with persistent restore failures is already an
      // abnormal client state. Retry their restores once before refusing to
      // claim a seventeenth window without a value that can later be restored.
      for (std::size_t index = 0; index < kMaxClaimedWindows; ++index) {
        if (claims_[index].active) {
          RestoreClaimLocked(index);
        }
      }
      claim_index = FindEmptyClaim();
    }
    if (claim_index == kMaxClaimedWindows) {
      return ProtectionResult{Status::kWindowClaimTableFull,
                              ERROR_TOO_MANY_NAMES, probe.observed_affinity};
    }
    claims_[claim_index] = ClaimedWindow{query.hwnd, probe.observed_affinity,
                                         WDA_NONE, false, true};
  }
  current_hwnd_ = query.hwnd;
  ClaimedWindow &claim = claims_[claim_index];

  if (probe.observed_affinity != WDA_EXCLUDEFROMCAPTURE) {
    if (!::SetWindowDisplayAffinity(query.hwnd, WDA_EXCLUDEFROMCAPTURE)) {
      return ProtectionResult{Status::kSetAffinityFailed, ::GetLastError(),
                              probe.observed_affinity};
    }
    claim.wrote_affinity = true;
    claim.last_written_affinity = WDA_EXCLUDEFROMCAPTURE;
  }

  DWORD observed = WDA_NONE;
  if (!::GetWindowDisplayAffinity(query.hwnd, &observed)) {
    return ProtectionResult{Status::kGetAffinityFailed, ::GetLastError(),
                            WDA_NONE};
  }
  if (claim.wrote_affinity) {
    // Windows releases before 10 version 2004 can report the older
    // WDA_MONITOR behavior after accepting 0x11. Remember the exact read-back
    // so a failed verification can still restore the pre-existing value.
    claim.last_written_affinity = observed;
  }
  if (observed != WDA_EXCLUDEFROMCAPTURE) {
    return ProtectionResult{Status::kAffinityVerificationFailed, ERROR_SUCCESS,
                            observed};
  }

  // Protect the live replacement first. Then best-effort restore any older
  // ICA HWNDs. Failed restores stay in the claim list and are retried on the
  // next poll/release; they never prevent the current window being protected.
  for (std::size_t index = 0; index < kMaxClaimedWindows; ++index) {
    if (claims_[index].active && claims_[index].hwnd != current_hwnd_) {
      RestoreClaimLocked(index);
    }
  }

  return ProtectionResult{Status::kOk, ERROR_SUCCESS, observed};
}

std::size_t WindowProtector::FindClaim(HWND hwnd) const noexcept {
  for (std::size_t index = 0; index < claims_.size(); ++index) {
    if (claims_[index].active && claims_[index].hwnd == hwnd) {
      return index;
    }
  }
  return kMaxClaimedWindows;
}

std::size_t WindowProtector::FindEmptyClaim() const noexcept {
  for (std::size_t index = 0; index < kMaxClaimedWindows; ++index) {
    if (!claims_[index].active) {
      return index;
    }
  }
  return kMaxClaimedWindows;
}

void WindowProtector::EraseClaim(std::size_t index) noexcept {
  if (claims_[index].hwnd == current_hwnd_) {
    current_hwnd_ = nullptr;
  }
  claims_[index] = ClaimedWindow{};
}

ProtectionResult
WindowProtector::RestoreClaimLocked(std::size_t index) noexcept {
  const HWND hwnd = claims_[index].hwnd;
  OwnershipProbeResult probe = ProbeWindow(hwnd);
  if (!probe.ok()) {
    // A destroyed/recycled/different-owner HWND can never be written safely.
    // A GetWindowDisplayAffinity failure on an otherwise valid owned HWND can
    // be transient, so retain that claim and retry without losing the saved
    // pre-DENCAP value.
    if (probe.status == Status::kWindowOwnershipFailed) {
      EraseClaim(index);
    }
    return FromProbe(probe);
  }

  const ClaimedWindow claim = claims_[index];
  if (!claim.wrote_affinity) {
    const DWORD observed = probe.observed_affinity;
    EraseClaim(index);
    return ProtectionResult{Status::kOk, ERROR_SUCCESS, observed};
  }

  // Do not overwrite an affinity value installed by another component after
  // ours. Restore only while the exact value read back after our last write is
  // still present.
  if (probe.observed_affinity != claim.last_written_affinity) {
    const DWORD observed = probe.observed_affinity;
    EraseClaim(index);
    return ProtectionResult{Status::kOk, ERROR_SUCCESS, observed};
  }

  if (!::SetWindowDisplayAffinity(hwnd, claim.previous_affinity)) {
    const DWORD error = ::GetLastError();
    return ProtectionResult{Status::kSetAffinityFailed, error,
                            probe.observed_affinity};
  }

  DWORD observed = WDA_NONE;
  if (!::GetWindowDisplayAffinity(hwnd, &observed)) {
    return ProtectionResult{Status::kGetAffinityFailed, ::GetLastError(),
                            WDA_NONE};
  }
  if (observed != claim.previous_affinity) {
    return ProtectionResult{Status::kAffinityVerificationFailed, ERROR_SUCCESS,
                            observed};
  }

  EraseClaim(index);
  return ProtectionResult{Status::kOk, ERROR_SUCCESS, observed};
}

ProtectionResult WindowProtector::RestoreLocked() noexcept {
  ProtectionResult first_failure{};
  bool saw_failure = false;
  for (std::size_t index = 0; index < kMaxClaimedWindows; ++index) {
    if (!claims_[index].active) {
      continue;
    }
    const ProtectionResult result = RestoreClaimLocked(index);
    if (!result.ok() && !saw_failure) {
      first_failure = result;
      saw_failure = true;
    }
  }
  current_hwnd_ = nullptr;
  return saw_failure ? first_failure : ProtectionResult{};
}

ProtectionResult WindowProtector::Restore() noexcept {
  std::scoped_lock lock(mutex_);
  return RestoreLocked();
}

} // namespace dencap
