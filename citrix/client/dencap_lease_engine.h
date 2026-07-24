#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

#include "../protocol/dencap_protocol.h"
#include "dencap_window_protector.h"

namespace dencap {

class LeaseEngine {
public:
  static constexpr std::size_t kMaxLeases = 64;
  static constexpr std::uint64_t kProtectionRefreshMs = 1'000;

  explicit LeaseEngine(IProtectionController &protector) noexcept;
  ~LeaseEngine();

  LeaseEngine(const LeaseEngine &) = delete;
  LeaseEngine &operator=(const LeaseEngine &) = delete;

  Message HandleFrame(const void *bytes, std::size_t length,
                      std::uint64_t now_ms) noexcept;
  void Poll(std::uint64_t now_ms) noexcept;
  void NotifyWindowChanged() noexcept;
  void Shutdown() noexcept;

  [[nodiscard]] std::size_t active_lease_count() const noexcept;

private:
  struct Lease {
    std::array<std::uint8_t, 16> id{};
    std::uint64_t last_sequence = 0;
    std::uint64_t expires_at_ms = 0;
    bool active = false;
  };

  static std::uint32_t ClampLeaseMs(std::uint32_t requested) noexcept;
  static bool ValidateEnvelope(const Message &request, Status *error) noexcept;
  Lease *FindLease(const std::uint8_t (&id)[16]) noexcept;
  Lease *FindEmptyLease() noexcept;
  std::size_t PurgeExpired(std::uint64_t now_ms) noexcept;
  std::size_t CountActiveLocked() const noexcept;
  ProtectionResult ReconcileProtectionLocked(std::uint64_t now_ms,
                                             bool force) noexcept;

  IProtectionController &protector_;
  mutable std::mutex mutex_;
  std::array<Lease, kMaxLeases> leases_{};
  std::atomic_bool window_changed_{false};
  std::uint64_t last_protection_refresh_ms_ = 0;
  bool shutdown_ = false;
};

} // namespace dencap
