#include "../client/dencap_lease_engine.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace {

class FakeProtector final : public dencap::IProtectionController {
public:
  dencap::ProtectionResult Protect() noexcept override {
    ++protect_calls;
    protected_now = true;
    return next_protect_result;
  }

  dencap::ProtectionResult Restore() noexcept override {
    ++restore_calls;
    protected_now = false;
    return next_restore_result;
  }

  int protect_calls = 0;
  int restore_calls = 0;
  bool protected_now = false;
  dencap::ProtectionResult next_protect_result{
      dencap::Status::kOk, ERROR_SUCCESS, WDA_EXCLUDEFROMCAPTURE};
  dencap::ProtectionResult next_restore_result{};
};

struct StatusCollector {
  std::array<dencap::Message, dencap::LeaseEngine::kMaxLeases> messages{};
  std::size_t count = 0;
  std::size_t capacity = messages.size();

  static bool __cdecl Accept(void *context, const dencap::Message &message) {
    auto &collector = *static_cast<StatusCollector *>(context);
    if (collector.count == collector.capacity) {
      return false;
    }
    collector.messages[collector.count++] = message;
    return true;
  }
};

void Require(bool condition, const char *message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    std::exit(1);
  }
}

dencap::Message Request(dencap::MessageType type, std::uint8_t id_byte,
                        std::uint64_t sequence, std::uint32_t lease_ms) {
  dencap::Message request{};
  request.magic = dencap::kMagic;
  request.version = dencap::kProtocolVersion;
  request.size = sizeof(request);
  request.type = static_cast<std::uint16_t>(type);
  request.lease_id[0] = id_byte;
  request.sequence = sequence;
  request.lease_ms = lease_ms;
  return request;
}

dencap::Status ResponseStatus(const dencap::Message &response) {
  return static_cast<dencap::Status>(response.status);
}

} // namespace

int main() {
  Require(sizeof(dencap::kWfApiChannelName) == 8,
          "WFAPI channel name must be seven bytes plus NUL");
  Require(std::memcmp(dencap::kWfApiChannelName, "DENCAP ", 8) == 0,
          "WFAPI channel name must contain Citrix space padding");

  auto wire_layout = Request(dencap::MessageType::kAcquire, 0x7a, 1, 15'000);
  const auto *wire = reinterpret_cast<const std::uint8_t *>(&wire_layout);
  Require(sizeof(wire_layout) == 64, "wire message must be 64 bytes");
  Require(wire[0] == 0x44 && wire[1] == 0x4e && wire[2] == 0x43 &&
              wire[3] == 0x50,
          "wire magic must be DNCP");
  Require(wire[4] == 1 && wire[5] == 0, "wire version offset must be 4");
  Require(wire[6] == 64 && wire[7] == 0, "wire size offset must be 6");
  Require(wire[8] == 1 && wire[9] == 0, "wire type offset must be 8");
  Require(wire[12] == 0x7a, "wire lease ID offset must be 12");
  Require(wire[28] == 1, "wire sequence offset must be 28");
  Require(wire[36] == 0x98 && wire[37] == 0x3a,
          "wire lease duration offset must be 36");

  FakeProtector default_lease_protector;
  dencap::LeaseEngine default_lease_engine(default_lease_protector);
  auto default_lease_request =
      Request(dencap::MessageType::kAcquire, 0x44, 1, 0);
  auto default_lease_response = default_lease_engine.HandleFrame(
      &default_lease_request, sizeof(default_lease_request), 50);
  Require(default_lease_response.lease_ms == 30'000,
          "zero-duration request should receive the 30-second default");
  default_lease_engine.Shutdown();

  FakeProtector protector;
  dencap::LeaseEngine engine(protector);

  auto acquire = Request(dencap::MessageType::kAcquire, 1, 1, 2'000);
  auto response = engine.HandleFrame(&acquire, sizeof(acquire), 100);
  Require(ResponseStatus(response) == dencap::Status::kOk,
          "ACQUIRE should succeed");
  Require(response.lease_ms == 2'000, "ACQUIRE should echo granted lease");
  Require(engine.active_lease_count() == 1, "one lease should be active");
  Require(protector.protected_now, "first lease should protect the window");

  auto stale = Request(dencap::MessageType::kRenew, 1, 1, 2'000);
  response = engine.HandleFrame(&stale, sizeof(stale), 200);
  Require(ResponseStatus(response) == dencap::Status::kStaleSequence,
          "replayed sequence should be rejected");

  // Model a successful RENEW whose response is lost in transit. The browser
  // reopens the channel and uses ACQUIRE with the same UUID and a newer
  // sequence; that must safely refresh the existing lease in either case.
  auto lost_ack_renew =
      Request(dencap::MessageType::kRenew, 1, 2, 2'000);
  response =
      engine.HandleFrame(&lost_ack_renew, sizeof(lost_ack_renew), 225);
  Require(ResponseStatus(response) == dencap::Status::kOk,
          "RENEW preceding a lost ACK should update the lease");

  auto reconnect_acquire =
      Request(dencap::MessageType::kAcquire, 1, 3, 2'000);
  response = engine.HandleFrame(&reconnect_acquire,
                                sizeof(reconnect_acquire), 250);
  Require(ResponseStatus(response) == dencap::Status::kOk,
          "higher-sequence ACQUIRE should recover after a lost ACK");
  Require(engine.active_lease_count() == 1,
          "recovery ACQUIRE must not duplicate the existing lease");

  auto acquire_second = Request(dencap::MessageType::kAcquire, 2, 1, 2'000);
  response = engine.HandleFrame(&acquire_second, sizeof(acquire_second), 300);
  Require(ResponseStatus(response) == dencap::Status::kOk,
          "second ACQUIRE should succeed");
  Require(engine.active_lease_count() == 2, "two leases should be active");

  auto release_first = Request(dencap::MessageType::kRelease, 1, 4, 0);
  response = engine.HandleFrame(&release_first, sizeof(release_first), 400);
  Require(ResponseStatus(response) == dencap::Status::kOk,
          "first RELEASE should succeed");
  Require(protector.protected_now,
          "one remaining lease should keep protection active");

  engine.NotifyWindowChanged();
  const int calls_before_poll = protector.protect_calls;
  engine.Poll(450);
  Require(protector.protect_calls == calls_before_poll + 1,
          "window callback should trigger reapplication during poll");

  engine.Poll(2'301);
  Require(engine.active_lease_count() == 0,
          "expired final lease should be removed");
  Require(!protector.protected_now,
          "last lease expiry should restore the prior affinity");

  response = engine.HandleFrame(nullptr, 0, 3'000);
  Require(ResponseStatus(response) == dencap::Status::kInvalidMessage,
          "invalid frame length should be rejected");

  // Losing window protection between requests must notify every browser.
  // Backpressure must retain undelivered failures even before the next recheck.
  FakeProtector failure_protector;
  dencap::LeaseEngine failure_engine(failure_protector);
  auto first = Request(dencap::MessageType::kAcquire, 51, 1, 30'000);
  auto second = Request(dencap::MessageType::kAcquire, 52, 7, 30'000);
  failure_engine.HandleFrame(&first, sizeof(first), 100);
  failure_engine.HandleFrame(&second, sizeof(second), 100);
  failure_protector.next_protect_result = {
      dencap::Status::kSetAffinityFailed, ERROR_ACCESS_DENIED, WDA_NONE};
  failure_engine.NotifyWindowChanged();
  StatusCollector failures;
  failures.capacity = 1;
  Require(!failure_engine.Poll(200, &StatusCollector::Accept, &failures),
          "a full response queue must signal backpressure");
  Require(failures.count == 1 && failures.messages[0].lease_id[0] == 51 &&
              failures.messages[0].sequence == 1 &&
              ResponseStatus(failures.messages[0]) ==
                  dencap::Status::kSetAffinityFailed,
          "poll failure must identify the affected lease and last sequence");
  failures.capacity = failures.messages.size();
  Require(failure_engine.Poll(201, &StatusCollector::Accept, &failures) &&
              failures.count == 2 && failures.messages[1].lease_id[0] == 52 &&
              failures.messages[1].sequence == 7,
          "cached protection failure must retry unsent notifications");
  failure_engine.Poll(202, &StatusCollector::Accept, &failures);
  Require(failures.count == 2,
          "a persistent failure must not flood the response queue");
  failure_protector.next_protect_result = {
      dencap::Status::kOk, ERROR_SUCCESS, WDA_EXCLUDEFROMCAPTURE};
  failure_engine.Poll(1'200, &StatusCollector::Accept, &failures);
  failure_protector.next_protect_result = {
      dencap::Status::kWindowOwnershipFailed, ERROR_ACCESS_DENIED, WDA_NONE};
  failure_engine.Poll(2'200, &StatusCollector::Accept, &failures);
  Require(failures.count == 4,
          "a new failure after verified recovery must notify both leases");

  // A recorded loss of protection must survive recovery while output is full.
  // Cover recovery during both the periodic recheck and an incoming request.
  for (const bool recover_with_request : {false, true}) {
    FakeProtector recovery_protector;
    dencap::LeaseEngine recovery_engine(recovery_protector);
    auto acquire = Request(dencap::MessageType::kAcquire, 61, 1, 30'000);
    recovery_engine.HandleFrame(&acquire, sizeof(acquire), 100);
    recovery_protector.next_protect_result = {
        dencap::Status::kSetAffinityFailed, ERROR_ACCESS_DENIED, WDA_NONE};
    recovery_engine.NotifyWindowChanged();
    StatusCollector delayed;
    delayed.capacity = 0;
    Require(!recovery_engine.Poll(200, &StatusCollector::Accept, &delayed),
            "detected failure must remain pending when no output is available");

    recovery_protector.next_protect_result = {
        dencap::Status::kOk, ERROR_SUCCESS, WDA_EXCLUDEFROMCAPTURE};
    if (recover_with_request) {
      auto renew = Request(dencap::MessageType::kRenew, 61, 2, 30'000);
      const auto renewed = recovery_engine.HandleFrame(&renew, sizeof(renew), 250);
      Require(ResponseStatus(renewed) == dencap::Status::kOk,
              "renewal can restore protection while an earlier failure is pending");
    }
    delayed.capacity = delayed.messages.size();
    Require(recovery_engine.Poll(1'200, &StatusCollector::Accept, &delayed) &&
                delayed.count == 1 && delayed.messages[0].lease_id[0] == 61 &&
                delayed.messages[0].sequence == 1 &&
                delayed.messages[0].monotonic_ms == 200 &&
                delayed.messages[0].win32_error == ERROR_ACCESS_DENIED &&
                ResponseStatus(delayed.messages[0]) ==
                    dencap::Status::kSetAffinityFailed,
            "recovery cannot erase or rewrite an undelivered failure snapshot");
    recovery_engine.Poll(1'201, &StatusCollector::Accept, &delayed);
    Require(delayed.count == 1, "a drained snapshot is delivered exactly once");

    recovery_protector.next_protect_result = {
        dencap::Status::kWindowOwnershipFailed, ERROR_ACCESS_DENIED, WDA_NONE};
    recovery_engine.NotifyWindowChanged();
    recovery_engine.Poll(1'202, &StatusCollector::Accept, &delayed);
    Require(delayed.count == 2 &&
                ResponseStatus(delayed.messages[1]) ==
                    dencap::Status::kWindowOwnershipFailed,
            "delivery of an older snapshot cannot suppress a later failure episode");
  }

  // Removed leases have no remaining recipient. Do not deliver their pending
  // errors to a later browser instance or a new lease reusing the same slot.
  for (const bool remove_with_release : {false, true}) {
    FakeProtector removal_protector;
    dencap::LeaseEngine removal_engine(removal_protector);
    auto acquire = Request(dencap::MessageType::kAcquire, 71, 1, 1'000);
    removal_engine.HandleFrame(&acquire, sizeof(acquire), 100);
    removal_protector.next_protect_result = {
        dencap::Status::kSetAffinityFailed, ERROR_ACCESS_DENIED, WDA_NONE};
    removal_engine.NotifyWindowChanged();
    StatusCollector delayed;
    delayed.capacity = 0;
    Require(!removal_engine.Poll(200, &StatusCollector::Accept, &delayed),
            "failure is queued before lease removal");
    if (remove_with_release) {
      auto release = Request(dencap::MessageType::kRelease, 71, 2, 0);
      removal_engine.HandleFrame(&release, sizeof(release), 250);
    }
    delayed.capacity = delayed.messages.size();
    removal_engine.Poll(1'100, &StatusCollector::Accept, &delayed);
    Require(delayed.count == 0 && removal_engine.active_lease_count() == 0,
            "release or expiry clears the pending failure with its lease");
  }

  std::cout << "All DENCAP lease-engine tests passed.\n";
  return 0;
}
