# udplbd2 Changelog

## v2.3.0

### ChainLoadBalancer: Load Balancer Chaining

v2.3.0 introduces **load balancer chaining** -- the ability to connect multiple udplbd instances into a hierarchical forwarding topology. A downstream LB registers itself as a receiver on an upstream LB with `keepLbHeader = true`, so traffic flows through a chain of load balancers before reaching the final receivers. This enables multi-stage fan-out, geographic distribution, and hierarchical event routing.

#### New RPCs

**`ChainLoadBalancer`** -- Registers the local LB as a receiver on an upstream control plane, creating a chain link. The local LB's data-plane address is registered upstream with `keepLbHeader = true`, and aggregated `SendState` updates are forwarded periodically.

```protobuf
rpc ChainLoadBalancer (ChainLoadBalancerRequest) returns (ChainLoadBalancerReply) {};

message ChainLoadBalancerRequest {
    string lbId = 1;              // local reservation ID
    string ejfatUri = 2;          // EJFAT URI of the upstream control plane (including token and lb_id)
    IpFamily ipFamily = 3;        // IPV4 or IPV6 only (DUAL_STACK not allowed)
    float weight = 4;             // relative weight for upstream calendar
    float minFactor = 5;          // min slot factor (see Register)
    float maxFactor = 6;          // max slot factor (see Register)
    repeated SlotRange slotDemands = 7;
}
message ChainLoadBalancerReply {
    string chainId = 1;           // database identifier for this upstream chain
}
```

**`UnchainLoadBalancer`** -- Removes an upstream chain link by ID, deregistering from the upstream control plane.

```protobuf
rpc UnchainLoadBalancer (UnchainLoadBalancerRequest) returns (UnchainLoadBalancerReply) {};

message UnchainLoadBalancerRequest {
    string lbId = 1;              // local reservation ID
    string chainId = 2;           // chain ID from ChainLoadBalancerReply
}
message UnchainLoadBalancerReply {}
```

**`GetChainGraph`** -- Returns the transitive upstream chain graph by recursing to each upstream's control plane. Used internally for cycle detection and useful for operators to visualize the full topology.

```protobuf
rpc GetChainGraph (GetChainGraphRequest) returns (GetChainGraphReply) {};

message GetChainGraphRequest {
    string lbId = 1;
    repeated string visited = 2;  // compound IDs "{host}:{port}/{lb_id}" for cycle detection
}
message ChainGraphEdge {
    string upstreamLbId = 1;
    string upstreamDataIpv4 = 2;
    string upstreamDataIpv6 = 3;
    string downstreamLbId = 4;
    string downstreamDataIpv4 = 5;
    string downstreamDataIpv6 = 6;
    string chainId = 7;
}
message GetChainGraphReply {
    repeated ChainGraphEdge edges = 1;
    bool cycleDetected = 2;
}
```


#### Testing

- **`udplbd dataplane doctor --chain`**: Automated integration test that reserves two LBs, chains them, sends traffic through the chain, verifies packets arrive at the downstream receiver, tests cycle detection, and cleans up.
- **Test topologies**: `test/dataplane/chain/` includes `linear-chain.json`, `diamond-topology.json`, and `multi-sender-chain.json` for `udplbd dataplane test`.

#### Database

New `upstream_chain` table (migration `0004_upstream_chain.sql`) stores chain state: upstream gRPC connection details, EJFAT token, session credentials, and upstream data-plane addresses. Chains are soft-deleted on `UnchainLoadBalancer` or `FreeLoadBalancer`.

---

### New Features

#### LB Protocol v3 Support
- The sender, receiver, and mock data plane now support LB header version 3, which introduces a dedicated `slot_select` field and `port_select` field. The mock data plane correctly computes calendar slots using `slot_select_bit_cnt` and `slot_select_xor` parameters from the P4 epoch rules.
- `udplbd dataplane send --v2` flag added to send with the legacy v2 header format.

#### TLS Certificate Hot-Reloading
- TLS certificates are now automatically reloaded when the file changes on disk, enabling zero-downtime certificate renewal (e.g., certbot, Kubernetes secrets). Uses `notify` for filesystem watching.

#### `udplbd version` Subcommand
- New `version` subcommand prints the build version without starting the server. Includes a `COMPAT_TAG` (`0.3.1`) for protocol compatibility tracking.

#### `udplbd dataplane ping` Command
- Pings all configured load balancer data-plane addresses (IPv4 and IPv6) to verify network reachability. Runs pings concurrently with configurable count and timeout.

#### Doctor Improvements
- **JUnit XML output**: `udplbd dataplane doctor --junit` outputs results as JUnit XML, suitable for CI/CD test reporting. Each strategy maps to a `<testsuite>` and each check to a `<testcase>`.
- **CI/CD integration**: New `doctor` stage in `.gitlab-ci.yml` runs the doctor against deployed instances and publishes JUnit artifacts.
- **Exit code**: Doctor now exits with code 1 if any tests fail.
- **Receiver stats validation**: Doctor verifies that `totalEventsReassembled > 0` in the Overview response.
- **Default addresses/ports**: Most dataplane commands (`recv`, `send`, `doctor`, `test`, `print`, `zero-mock-recv`) now default `--address` to the first `server.listen` address and `--port` to an available ephemeral port, reducing required arguments.

#### WorkerStatus Slot Data
- `LoadBalancerStatus` now returns populated `slots` and `slotDemands` fields in `WorkerStatus`, showing the actual slot ranges assigned in the latest epoch and the explicitly demanded slot ranges from the database.

#### Token Hierarchy Fix
- `ListChildTokens` and `RevokeToken` now operate on the full descendant tree (grandchildren, great-grandchildren, etc.) rather than only direct children. A grandparent can now list and revoke any of its descendants.

#### Frontend Refactor
- The monolithic `app.js` has been replaced with an ES module architecture (`js/main.js`, `js/state.js`, `js/api.js`, `js/ui.js`, `js/auth.js`, `js/charts.js`, `js/router.js`, `js/sidebar.js`, and view modules under `js/views/`).

#### Documentation (mdBook)
- Comprehensive administrator documentation added under `docs/` as an mdBook: Installation, Configuration Reference, User Management, Observability, Database Administration, and Troubleshooting.
- CI/CD `pages` stage publishes both mdBook and `cargo doc` API reference.

### Changes

#### Configuration
- `database.backup_before_migrate` option added (default `true`): creates a timestamped backup of the database file before applying schema migrations.
- Example config expanded to 8 LB instances (up from 4) with corresponding mock address mappings.
- Duplicate IP addresses in `lb.instances` are now rejected at config validation time.
- TLS config documentation updated to note certificate hot-reloading support.

#### Rust Edition
- Upgraded from Rust edition 2021 to 2024.

### Bug Fixes
- Fixed `keepLbHeader` handling in mock data plane -- packets forwarded to receivers with `keepLbHeader = true` now correctly retain the LB header.
- Fixed reassembled event stat reporting and `listen_and_reassemble` task shutdown/remove panic.
- Fixed idempotent `auto_configure_smartnics` -- now runs before applying rules and handles repeated calls gracefully.
- Fixed clearing of current sn-p4 rules state when sn-cfg is detected as out of sync.
- Fixed metric scopes that disappear are now deleted rather than left stale.
- Fixed token hierarchy: grandparents can now list/revoke descendants at any depth.
- Fixed slot layout data in `WorkerStatus` (was previously empty).

### Internal / Chore
- Dependency updates across the board (tonic 0.14.6, sqlx 0.9.0, tokio 1.52.3, sha2 0.11.0, etc.).
- `cleanup_soft_deleted` refactored.
- `AGENTS.md` added for AI-assisted development context.
- `.gitlab-ci.yml` reorganized: deploy targets updated, doctor stage added, pages stage replaces `build_docs`.
- Common gRPC client logic (channel creation, interceptors) extracted into `src/grpc_common.rs`, reducing repetition across `sncfg` and `snp4` clients.

## v2.2.0

### New Features

#### SmartNIC / Dataplane Integration
- **Metrics collector**: Background task that polls stats from `sn-p4` and inserts them into the database, with foreign key references to the `reservation` and `session` tables where relevant.
- **Healthcheck task**: Automatically detects workflow issues by comparing SmartNIC dataplane stats (from the metrics collector) against receiver-reported and control plane stats. First implemented healthcheck: `receiver_packet_stall`.
  - New `HealthIssue` message added to the protobuf schema, carrying `type`, `severity` (`warning`/`error`/`critical`), `message`, machine-readable `details` (Struct), and `detected_at` timestamp.
  - `WorkerStatus` now includes `repeated HealthIssue healthIssues` (field 21) and a numeric `sessionId` (field 22, int64) alongside the existing string session identifier in Register/Deregister flows.
  - `LoadBalancerStatusReply` now includes `repeated HealthIssue healthIssues` (field 12) at the LB level.
- **`udplbd sncfg setup` command**: Equivalent to the previous setup script, but driven by udplbd's own config to determine which `sn-cfg` instance to talk to. Provides a more reliable path for handling dataplane restarts ahead of a planned uptime-detection feature.
- **`udplbd config autoconfigure` command**: Generates the `smartnic` section of the udplbd config from one or more `sn-p4` `.env` files.
- **`udplbd dataplane zero-mock-recv` command**: Simulates a receiver without opening a port — used to validate the `receiver_packet_stall` healthcheck.

#### New Load Balancer Lifecycle gRPCs
- **`ResetLoadBalancer` RPC**: Reinitializes selective aspects of a load balancer (time sync, epochs, sender list, worker sessions) without tearing down the reservation. Intended for recovery from dataplane restarts. Note: causes event loss if used during an active workflow.
- **`ExtendReservation` RPC**: Extends the expiration time of an existing load balancer reservation without re-reserving.

#### EJFAT URI now returned
- `ReserveLoadBalancerReply` now includes `ejfatUri` (field 12): a fully-formed `ejfat[s]://token@host:port/lb/id?sync=...&data=...` URI encoding all connection parameters for the reserved LB.
- `CreateTokenReply` now includes `ejfatUri` (field 2): an `ejfat[s]://token@host:port/` URI scoped to the new token.

#### Frontend
- Healthcheck issues visible in the frontend dashboard.
- New timeseries exposed from SmartNIC metrics.
- Reserve and Free load balancer actions available directly in the UI.
- Improved timeseries filtering and labeling.
- Various visual refinements.

#### Event Sync Data Seeding
- Event sync data is now seeded with control plane's Unix time, workflows that use microsecond timestamps as specified in EJFAT LB v3 header can now start in sync
- udplbd sender timestamps now use microsecond resolution for compatibility with this

#### Multiple LBs supported in Mock Mode
- `mock.address_map` config option added to support multiple load balancer reservations in mock mode.

### Changes

#### Timeseries Refactor
- `src/db/timeseries.rs` was completely refactored to remove the `/reservation` path prefix from timeseries selectors, simplifying wildcard queries (e.g., `/lb/1/*` now directly reaches session-level series without an intermediate `/reservation` segment).

#### Configuration
- `lb.allow_private`, `lb.allow_loopback`, and `lb.require_registration_from_dataplane` config options added
- `lb.data_plane_interface` config option added to filter route lookups for MAC address resolution by interface

### Bug Fixes
- Fixed `SetSlotDemands` race condition, added `--slot` option to `udplbd dataplane send` for testing explicit slots and a script demonstrating this
- Fixed dummy MAC address handling and mock behavior when MAC address is null.
- Fixed `doctor` timing and
- Fixed timeseries filtering on the frontend.

### Internal / Chore
- Renamed a migration.
- Updated `sn_p4_v2.proto`, including stat clearing support.
- Version bump and dependency updates.
- **`udplbd sncfg stats` command**: Dumps raw gRPC stat responses from `sn-cfg` for inspection and debugging.
- **`udplbd dataplane stats` command**: Dumps raw gRPC stat responses from `sn-p4` for inspection and debugging.
