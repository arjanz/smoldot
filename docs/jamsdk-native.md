# JAMSDK native query profile

This fork starts from Parity `skunert/jam-tip` at
`fb3eb3bc7c30212cb1ce782d4281032d9a738785`. Its JAMSDK interface is an
**in-process extension**, not a new JIP-2 wire standard. It targets GP 0.8.0 and
the prototype's PolkaJAM CE 130 finality format. CE 130 and CE 153 are not part
of PyJAMaz's pinned public JAMNP-S revision.

The Python `JamSmoldotClient` forces `jamsdk_disable_warp: true` in its local
chain specification. SDK queries are refused if that profile is absent. The
browser prototype retains its original warp path for upstream compatibility;
that path must not be used to claim chain-bound SDK verification. Native SDK
sync follows continuous authenticated ancestry from caller-trusted genesis or
an explicitly trusted checkpoint. Unavailable historical ancestors are not
replaced by a node's claimed finality.

## Roots and proof ownership

The complete, caller-trusted `genesis_state` map is committed with GP Appendix D.
SDK mode rejects a header-only export missing any fixed component C(1) through
C(16): a genesis header hash and shared initial authorities do not distinguish
all genesis state variants. An optional `checkpoint.state_root` is a 32-byte hex
posterior root that the caller must independently trust. When a checkpoint is
selected, SDK mode requires that field even if complete genesis state is also
present. A peer certificate never substitutes for the missing initial trust
anchor. Legacy browser prototype mode retains its original specification policy.

GRANDPA verifies the `(header hash, posterior state root, slot)` target, voter
signatures/quorum and ordered authority changes. Successful finality retains
that signed posterior root and the roots committed along its finalized
ancestry. New authenticated children cannot replace it. A conflicting
certificate is rejected before root advancement. In SDK mode, descendants that
contradict known signed parent roots are rejected or pruned.

Provisional state roots require opt-in and an authenticated child committing
the parent's posterior state. Conflicting sibling commitments fail closed.
Every returned service value/absence is checked with the CE 129 range proof at
one exact key against the selected root. Pending reads are checked again after
proof arrival in case finality superseded a provisional commitment.

Retained finalized headers and roots have a 512-record / 4 MiB encoded-header
budget. The existing header tree has independent bounds. CE 129 has a separate
32 MiB entry budget plus at most 496 64-byte boundary nodes; header/block
budgets stay unchanged. A maximum 4,000,000-byte service-code preimage is tested
through both the native frame decoder and trie verifier.

Catch-up pauses queued header imports before the block, epoch-record or byte
budget would prevent a pending finality proof from pruning old ancestry. In
particular, an already received CE 128 batch cannot overrun the epoch budget
while the other peer supplies a CE 130 certificate. Canceled state reads reset
only their exact CE 129 request stream and release its shared reservation. A
late outbound opening retains its original request ID and is discarded; it
cannot steal a replacement request on the same peer.

## In-process methods

Hashes and state keys are canonical padded base64; state keys are exactly 31
bytes. Standard `jamHead_unstable_follow`, `header`, `unpin` and `unfollow`
remain available for header events.

| Method | Parameters | Result |
|---|---|---|
| `jam_parameters` | `[]` | JIP-2 `V1` parameter object from the trusted spec and tracked validator dimensions |
| `jam_block` | `["best" / "finalized" / hash]` | `{header_hash, slot}` |
| `jam_parent` | `[hash]` | Parent block descriptor, if retained |
| `jam_header` | `[hash]` | Canonical JAM header bytes in hex |
| `jam_verificationContext` | `[hash, allow_provisional]` | `{genesis_hash, header_hash, state_root, level}` |
| `jam_stateValue` | `[hash, expected_root, key, allow_provisional]` | Proven value in base64, or proven absence `null` |
| `jam_cancel` | `[original_request_id]` | Abort the original local query; original ID receives `-32800` if cancelled |

Verification levels are `trusted_anchor`, `finalized`, and `provisional`.
Queries are bounded by the configured maximum pending count (hard ceiling 64)
and a 30-second native deadline. Errors preserve the original request ID,
including zero. `-32040` means verification/state unavailable, `-32041` means
read/request capacity busy, `-32042` means unsafe warp-enabled profile,
`-32043` means a cryptographically invalid state proof after peer attempts,
`-32801` means historical header unavailable, and `-32602` means invalid
parameters. Dropping the frontend cancels owned pending query futures and
subscriptions. No external RPC endpoint is consulted.

## Verification

```sh
CARGO_TARGET_DIR=/private/tmp/jam-core-target cargo +1.99.1 test --locked -p smoldot --no-default-features --features std --lib jam::
CARGO_TARGET_DIR=/private/tmp/jam-light-target cargo +1.99.1 test --locked -p smoldot-light --no-default-features --features std --lib jam
```

Tests cover native finality fixtures, root pinning, provisional conflicts,
profile rejection, malformed proofs and canonical state commitments. These are
header/finality/state-proof checks, not full JAM execution or service simulation.
Live network qualification and Python wheel results are recorded separately by
JAMSDK's validation notes.

## Native WebTransport

`DefaultPlatform` uses `wtransport` 0.7.2 and a lazily created two-thread Tokio
runtime. Ordinary TCP/WebSocket users do not start that runtime. Each connection
has bounded 64-entry opening and delivery queues, at most 64 bidirectional QUIC
streams, a 256 KiB per-stream receive window and 4 MiB connection receive/send
windows. Handshake and stream-opening deadlines are 20 seconds; QUIC idle
timeout is 90 seconds with a 15-second keepalive. Dropping an unfinished stream
sends the standard WebTransport application cancellation code independently on
its read and write halves. HTTP/3 reserved reset codes are translated according
to draft-ietf-webtrans-http3-14 section 4.4, including its skipped codepoints.

The JAM peer key comes from the caller-trusted specification or proof-verified
validator state. The native adapter reconstructs certificate DER and pins its
SHA-256 digest for the previous, current and next ten-day validity periods.
TLS verifies the exact certificate, its current validity (at most 14 days),
P-256 key type and possession of that key in the TLS handshake. Authentication
uses those caller-derived certificate pins. No accept-all verifier,
trust-on-first-use, peer-supplied certificate pin or RPC trust anchor is used.

Two explicitly recognized deterministic certificate encodings are accepted:

- The pinned prototype uses the peer ID for subject/issuer CN and the validity
  period index as its serial number.
- Public PolkaJAM 0.1.29 uses `CN=jam` and serial zero, with the same P-256 key,
  peer-ID SAN, validity interval and placeholder certificate signature. A
  captured public certificate is a byte-exact regression fixture. This native
  compatibility profile does not alter the browser's newer issuer/serial policy.

The public macOS aarch64 binaries inspected during qualification have SHA-256:

| Release archive | `polkajam` SHA-256 |
|---|---|
| GP `v0.8.0`, PolkaJAM 0.1.29 | `30a8af4d529033108f41374a021862b10faec89c50637e481f8e4d6a27e85ed8` |
| PolkaJAM `v0.1.29` | `85d8b93d490382f74a1c48a40bf69e9a7ba7bbca1d03da105a665db8abb30cf2` |

Both require CONNECT headers `sec-webtransport-http3-draft02: 1` and `origin`.
The native client sends `origin: null`, the serialized opaque origin. A browser
handshake and independent pinned-certificate HTTP/3 client established these
requirements; omitting Origin produced HTTP/3 `H3_MESSAGE_ERROR`. Loopback tests
assert both headers. This is the qualified PolkaJAM extension profile and does
not imply universal JAM networking compatibility.

Streams preserve partial reads, independent FIN state and reset codes. Existing
streams retain their connection owner after its public handle is dropped. The
last owner aborts its connection actor. Native users should remove chains and
drop the client/response streams before calling `DefaultPlatform::shutdown()`
from outside its worker threads. Shutdown cancels owned tasks, joins the smol
workers and shuts down the Tokio runtime; Python bindings invoke it outside the
GIL. Cancellation and queue overflow do not create detached network tasks.

The bounded diagnostic below uses only local chain-spec input and native peer
connections. It disables warp and exits unsuccessfully unless at least one
proof-verified C(11) value is received; synchronized headers alone do not pass.
It never opens a node JSON-RPC connection.

```sh
RUST_LOG=debug cargo +1.99.1 run --locked -p smoldot-light \
  --no-default-features --features std --example jam_native -- \
  /path/to/trusted-jam-spec.json 45
cargo +1.99.1 test --locked -p smoldot-light --no-default-features \
  --features std platform::default
cargo +1.99.1 test --locked -p smoldot-light --no-default-features \
  --features std jam_webtransport_cert
```

The separate `.github/workflows/jamsdk-native.yml` runs these public fixture and
loopback tests on Linux, macOS and Windows with Rust 1.99.1. It also checks the
existing no-std API and compiles the native diagnostic. The commands deliberately
use `--no-default-features --features std` to omit optional Wasmtime support.
JAM header/proof verification does not execute service PVM code. These checks
require neither a private node binary, a node RPC endpoint nor credentials.
Live PolkaJAM qualification is a separate local acceptance check; a CI pass alone
does not establish compatibility with a deployed network.
