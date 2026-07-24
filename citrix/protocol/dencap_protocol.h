#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace dencap {

// Static Citrix virtual-channel names are limited to seven ASCII characters.
inline constexpr char kChannelName[] = "DENCAP";
// WFVirtualChannelOpen requires exactly seven visible bytes plus NUL, padding
// shorter channel names with spaces.
inline constexpr char kWfApiChannelName[8] = "DENCAP ";
inline constexpr std::uint32_t kMagic = 0x50434e44U; // "DNCP", little-endian.
inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::uint16_t kResponseFlag = 0x0001;
inline constexpr std::uint32_t kMinLeaseMs = 1'000;
inline constexpr std::uint32_t kDefaultLeaseMs = 30'000;
inline constexpr std::uint32_t kMaxLeaseMs = 60'000;

enum class MessageType : std::uint16_t {
  kAcquire = 1,
  kRenew = 2,
  kRelease = 3,
  kStatus = 0x8000,
};

enum class Status : std::uint32_t {
  kOk = 0,
  kInvalidMessage = 1,
  kUnsupportedVersion = 2,
  kUnknownMessageType = 3,
  kInvalidLeaseId = 4,
  kLeaseNotFound = 5,
  kStaleSequence = 6,
  kLeaseTableFull = 7,
  kIcaWindowQueryFailed = 8,
  kWindowOwnershipFailed = 9,
  kGetAffinityFailed = 10,
  kSetAffinityFailed = 11,
  kAffinityVerificationFailed = 12,
  kNotInitialized = 13,
  kWindowClaimTableFull = 14,
};

#pragma pack(push, 1)
struct Message {
  std::uint32_t magic;
  std::uint16_t version;
  std::uint16_t size;
  std::uint16_t type;
  std::uint16_t flags;
  std::uint8_t lease_id[16];
  std::uint64_t sequence;
  std::uint32_t lease_ms;
  std::uint32_t status;
  std::uint32_t win32_error;
  std::uint32_t observed_affinity;
  std::uint64_t monotonic_ms;
  std::uint32_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(Message) == 64,
              "DENCAP messages must remain exactly 64 bytes");
static_assert(sizeof(kWfApiChannelName) == 8);
static_assert(std::is_trivially_copyable_v<Message>);
static_assert(offsetof(Message, magic) == 0);
static_assert(offsetof(Message, version) == 4);
static_assert(offsetof(Message, size) == 6);
static_assert(offsetof(Message, type) == 8);
static_assert(offsetof(Message, flags) == 10);
static_assert(offsetof(Message, lease_id) == 12);
static_assert(offsetof(Message, sequence) == 28);
static_assert(offsetof(Message, lease_ms) == 36);
static_assert(offsetof(Message, status) == 40);
static_assert(offsetof(Message, win32_error) == 44);
static_assert(offsetof(Message, observed_affinity) == 48);
static_assert(offsetof(Message, monotonic_ms) == 52);
static_assert(offsetof(Message, reserved) == 60);

inline bool LeaseIdIsZero(const std::uint8_t (&lease_id)[16]) noexcept {
  std::uint8_t accumulator = 0;
  for (const auto byte : lease_id) {
    accumulator |= byte;
  }
  return accumulator == 0;
}

inline bool LeaseIdsEqual(const std::uint8_t (&lhs)[16],
                          const std::uint8_t (&rhs)[16]) noexcept {
  return std::memcmp(lhs, rhs, sizeof(lhs)) == 0;
}

inline Message MakeStatusMessage(const Message *request, Status status,
                                 std::uint32_t win32_error,
                                 std::uint32_t observed_affinity,
                                 std::uint64_t now_ms,
                                 std::uint32_t granted_lease_ms = 0) noexcept {
  Message response{};
  response.magic = kMagic;
  response.version = kProtocolVersion;
  response.size = sizeof(Message);
  response.type = static_cast<std::uint16_t>(MessageType::kStatus);
  response.flags = kResponseFlag;
  if (request != nullptr) {
    std::memcpy(response.lease_id, request->lease_id,
                sizeof(response.lease_id));
    response.sequence = request->sequence;
  }
  response.lease_ms = granted_lease_ms;
  response.status = static_cast<std::uint32_t>(status);
  response.win32_error = win32_error;
  response.observed_affinity = observed_affinity;
  response.monotonic_ms = now_ms;
  return response;
}

} // namespace dencap
