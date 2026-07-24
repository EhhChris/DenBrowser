#include "dencap_lease_engine.h"

#include <algorithm>
#include <cstring>

namespace dencap {

LeaseEngine::LeaseEngine(IProtectionController &protector) noexcept
    : protector_(protector) {}

LeaseEngine::~LeaseEngine() { Shutdown(); }

std::uint32_t LeaseEngine::ClampLeaseMs(std::uint32_t requested) noexcept {
  if (requested == 0) {
    requested = kDefaultLeaseMs;
  }
  return std::clamp(requested, kMinLeaseMs, kMaxLeaseMs);
}

bool LeaseEngine::ValidateEnvelope(const Message &request,
                                   Status *error) noexcept {
  if (request.magic != kMagic || request.size != sizeof(Message) ||
      request.flags != 0 || request.reserved != 0 || request.status != 0 ||
      request.win32_error != 0 || request.observed_affinity != 0 ||
      request.monotonic_ms != 0) {
    *error = Status::kInvalidMessage;
    return false;
  }
  if (request.version != kProtocolVersion) {
    *error = Status::kUnsupportedVersion;
    return false;
  }
  if (LeaseIdIsZero(request.lease_id) || request.sequence == 0) {
    *error = Status::kInvalidLeaseId;
    return false;
  }

  const auto type = static_cast<MessageType>(request.type);
  if (type != MessageType::kAcquire && type != MessageType::kRenew &&
      type != MessageType::kRelease) {
    *error = Status::kUnknownMessageType;
    return false;
  }
  if (type == MessageType::kRelease && request.lease_ms != 0) {
    *error = Status::kInvalidMessage;
    return false;
  }
  return true;
}

LeaseEngine::Lease *
LeaseEngine::FindLease(const std::uint8_t (&id)[16]) noexcept {
  for (auto &lease : leases_) {
    if (lease.active &&
        std::memcmp(lease.id.data(), id, lease.id.size()) == 0) {
      return &lease;
    }
  }
  return nullptr;
}

LeaseEngine::Lease *LeaseEngine::FindEmptyLease() noexcept {
  for (auto &lease : leases_) {
    if (!lease.active) {
      return &lease;
    }
  }
  return nullptr;
}

std::size_t LeaseEngine::PurgeExpired(std::uint64_t now_ms) noexcept {
  std::size_t purged = 0;
  for (auto &lease : leases_) {
    if (lease.active && now_ms >= lease.expires_at_ms) {
      lease = Lease{};
      ++purged;
    }
  }
  return purged;
}

std::size_t LeaseEngine::CountActiveLocked() const noexcept {
  std::size_t count = 0;
  for (const auto &lease : leases_) {
    count += lease.active ? 1U : 0U;
  }
  return count;
}

ProtectionResult LeaseEngine::ReconcileProtectionLocked(std::uint64_t now_ms,
                                                        bool force) noexcept {
  const bool active = CountActiveLocked() != 0;
  if (!active) {
    last_protection_refresh_ms_ = now_ms;
    window_changed_.store(false, std::memory_order_release);
    return protector_.Restore();
  }

  const bool changed =
      window_changed_.exchange(false, std::memory_order_acq_rel);
  const bool refresh_due =
      now_ms - last_protection_refresh_ms_ >= kProtectionRefreshMs;
  if (!force && !changed && !refresh_due) {
    return ProtectionResult{Status::kOk, ERROR_SUCCESS, WDA_EXCLUDEFROMCAPTURE};
  }

  last_protection_refresh_ms_ = now_ms;
  return protector_.Protect();
}

Message LeaseEngine::HandleFrame(const void *bytes, std::size_t length,
                                 std::uint64_t now_ms) noexcept {
  Message request{};
  if (bytes == nullptr || length != sizeof(request)) {
    return MakeStatusMessage(nullptr, Status::kInvalidMessage,
                             ERROR_INVALID_DATA, WDA_NONE, now_ms);
  }
  std::memcpy(&request, bytes, sizeof(request));

  Status validation_error = Status::kOk;
  if (!ValidateEnvelope(request, &validation_error)) {
    return MakeStatusMessage(&request, validation_error, ERROR_INVALID_DATA,
                             WDA_NONE, now_ms);
  }

  std::scoped_lock lock(mutex_);
  if (shutdown_) {
    return MakeStatusMessage(&request, Status::kNotInitialized,
                             ERROR_INVALID_STATE, WDA_NONE, now_ms);
  }

  const std::size_t active_before_purge = CountActiveLocked();
  PurgeExpired(now_ms);
  if (active_before_purge != 0 && CountActiveLocked() == 0) {
    protector_.Restore();
  }

  const auto type = static_cast<MessageType>(request.type);
  Lease *lease = FindLease(request.lease_id);
  std::uint32_t granted_ms = 0;

  if (type == MessageType::kAcquire) {
    if (lease == nullptr) {
      lease = FindEmptyLease();
      if (lease == nullptr) {
        return MakeStatusMessage(&request, Status::kLeaseTableFull,
                                 ERROR_TOO_MANY_NAMES, WDA_NONE, now_ms);
      }
      std::memcpy(lease->id.data(), request.lease_id, lease->id.size());
      lease->active = true;
    } else if (request.sequence <= lease->last_sequence) {
      return MakeStatusMessage(&request, Status::kStaleSequence,
                               ERROR_REQUEST_OUT_OF_SEQUENCE, WDA_NONE, now_ms);
    }

    granted_ms = ClampLeaseMs(request.lease_ms);
    lease->last_sequence = request.sequence;
    lease->expires_at_ms = now_ms + granted_ms;
  } else if (type == MessageType::kRenew) {
    if (lease == nullptr) {
      return MakeStatusMessage(&request, Status::kLeaseNotFound,
                               ERROR_NOT_FOUND, WDA_NONE, now_ms);
    }
    if (request.sequence <= lease->last_sequence) {
      return MakeStatusMessage(&request, Status::kStaleSequence,
                               ERROR_REQUEST_OUT_OF_SEQUENCE, WDA_NONE, now_ms);
    }

    granted_ms = ClampLeaseMs(request.lease_ms);
    lease->last_sequence = request.sequence;
    lease->expires_at_ms = now_ms + granted_ms;
  } else {
    if (lease == nullptr) {
      return MakeStatusMessage(&request, Status::kLeaseNotFound,
                               ERROR_NOT_FOUND, WDA_NONE, now_ms);
    }
    if (request.sequence <= lease->last_sequence) {
      return MakeStatusMessage(&request, Status::kStaleSequence,
                               ERROR_REQUEST_OUT_OF_SEQUENCE, WDA_NONE, now_ms);
    }
    *lease = Lease{};
  }

  const ProtectionResult result =
      ReconcileProtectionLocked(now_ms, /*force=*/true);
  return MakeStatusMessage(&request, result.status, result.win32_error,
                           result.observed_affinity, now_ms, granted_ms);
}

void LeaseEngine::Poll(std::uint64_t now_ms) noexcept {
  std::scoped_lock lock(mutex_);
  if (shutdown_) {
    return;
  }
  PurgeExpired(now_ms);
  ReconcileProtectionLocked(now_ms, /*force=*/false);
}

void LeaseEngine::NotifyWindowChanged() noexcept {
  window_changed_.store(true, std::memory_order_release);
}

void LeaseEngine::Shutdown() noexcept {
  std::scoped_lock lock(mutex_);
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  for (auto &lease : leases_) {
    lease = Lease{};
  }
  protector_.Restore();
}

std::size_t LeaseEngine::active_lease_count() const noexcept {
  std::scoped_lock lock(mutex_);
  return CountActiveLocked();
}

} // namespace dencap
