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

  auto acquire_second = Request(dencap::MessageType::kAcquire, 2, 1, 2'000);
  response = engine.HandleFrame(&acquire_second, sizeof(acquire_second), 300);
  Require(ResponseStatus(response) == dencap::Status::kOk,
          "second ACQUIRE should succeed");
  Require(engine.active_lease_count() == 2, "two leases should be active");

  auto release_first = Request(dencap::MessageType::kRelease, 1, 2, 0);
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

  std::cout << "All DENCAP lease-engine tests passed.\n";
  return 0;
}
