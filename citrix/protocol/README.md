# DENCAP wire protocol v1

`DENCAP` is a classic Citrix static virtual channel. Every protocol frame is
exactly 64 bytes, little-endian, and represented by `dencap::Message` in
`dencap_protocol.h`. The fixed size makes input bounding and SDK-sample queueing
simple. Use `kWfApiChannelName` at WFAPI/`OPENVIRTUALCHANNEL` boundaries:
Citrix requires the six-character logical name to be space-padded to seven
visible bytes and followed by NUL.

| Offset | Size | Field | Request rule |
|---:|---:|---|---|
| 0 | 4 | magic | bytes `44 4e 43 50` (`DNCP`) |
| 4 | 2 | version | `1` |
| 6 | 2 | size | `64` |
| 8 | 2 | type | `1` ACQUIRE, `2` RENEW, `3` RELEASE, `0x8000` STATUS |
| 10 | 2 | flags | request `0`; response `0x0001` |
| 12 | 16 | lease ID | non-zero random UUID bytes |
| 28 | 8 | sequence | non-zero and strictly increasing per active UUID |
| 36 | 4 | lease ms | ACQUIRE/RENEW request; RELEASE must be zero |
| 40 | 4 | status | request zero; response `dencap::Status` |
| 44 | 4 | Win32 error | request zero; diagnostic response value |
| 48 | 4 | observed affinity | request zero; response WDA read-back |
| 52 | 8 | monotonic ms | request zero; endpoint diagnostic timestamp |
| 60 | 4 | reserved | zero |

The endpoint clamps requested leases to 1–60 seconds and uses 30 seconds when
the request is zero. DenBrowser should request 30 seconds and renew every 5
seconds. A RELEASE has no lease duration.

For a UUID that is still active, a sequence equal to or below the most recently
accepted sequence is rejected as stale and does not extend the expiry. A RENEW
or RELEASE for an unknown/expired UUID is rejected. An ACQUIRE may allocate a
new UUID or refresh that same active UUID when its sequence is newer. This lets
the browser recover from an uncertain/lost RENEW acknowledgement by reopening
the channel and sending ACQUIRE with a fresh sequence. A successful response
echoes the UUID and sequence; `lease_ms` contains the granted duration for
ACQUIRE/RENEW.

The virtual channel supplies session transport isolation, but this protocol is
not cryptographically authenticated. The endpoint treats every frame as
untrusted: exact length, envelope fields, message type, UUID, sequence, and
reserved fields are validated before state changes. It never accepts an HWND
or requested affinity from the VDA.

Lease expiry is a crash/disconnect safety property, not an authorization
boundary. Closing a Citrix virtual channel is not relied upon to restore WDA.
