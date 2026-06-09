# Configuration Reference

udplbd is configured via a YAML file, defaulting to `/etc/udplbd/config.yml`. The path can be overridden with the `--config` flag or the `UDPLBD_CONFIG` environment variable.

## Supplying the configuration file

```sh
# single file (default)
udplbd start

# explicit path
udplbd start --config /custom/path/config.yml

# multiple files (later files take precedence)
udplbd start --config /etc/udplbd/base.yml --config /etc/udplbd/host-override.yml

# environment variable (colon-separated)
UDPLBD_CONFIG=/etc/udplbd/base.yml:/etc/udplbd/host-override.yml udplbd start
```

## Multi-file merging

When multiple config files are supplied, they are merged: YAML mappings (objects) are merged recursively, while YAML sequences (lists) are replaced wholesale by the later file. This means you can maintain a shared base configuration and override only what differs per host.

**Example:** base config has 8 LB instances; a host-override file sets a different `mac_unicast` without re-listing all instances — the `mac_unicast` key is merged, the `instances` list is unchanged because only the scalar key is present in the override.

However, if the override includes an `instances` key with a list value, that list completely replaces the base list.

## Environment variables

| Variable        | Description                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------- |
| `UDPLBD_CONFIG` | Colon-separated list of config file paths                                                    |
| `RUST_LOG`      | Overrides `log.level`; uses `tracing-subscriber` directives (e.g. `udplbd=debug,tonic=warn`) |
| `EJFAT_URI`     | Pre-built connection string for `udplbd client` and `udplbd dataplane` subcommands           |

## Duration format

Duration fields accept a numeric value followed by a unit suffix:

| Suffix | Unit         |
| ------ | ------------ |
| `ms`   | milliseconds |
| `s`    | seconds      |
| `h`    | hours        |
| `d`    | days         |

Examples: `"800ms"`, `"60s"`, `"4h"`, `"7d"`.


---

## Complete annotated example

The file [`etc/example-config.yml`](https://github.com/esnet/udplbd2/blob/main/etc/example-config.yml) in the repository root is the canonical annotated reference. Every field is commented with its type, units, and purpose. Use it as the starting point for new deployments.


---

## `lb` — Load balancer instances

```yaml
lb:
  mac_unicast: null
  data_plane_interface: null
  instances:
    - ipv4: "192.0.2.1"
      ipv6: "2001:db8::1"
      event_number_port: 19531
```

| Field                            | Type                 | Required                  | Description                                                                                                                                                                          |
| -------------------------------- | -------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mac_unicast`                    | string \| null       | No                        | Unicast MAC address for L2 forwarding rules (e.g. `"aa:bb:cc:dd:ee:ff"`). If `null`, the MAC is fetched automatically from sn-cfg. Must be set manually if sn-cfg is not configured. |
| `data_plane_interface`           | string \| null       | No                        | Network interface name to use when looking up the MAC address locally. If `null`, all interfaces are searched.                                                                       |
| `instances`                      | list                 | Yes                       | One entry per logical load balancer slot on the FPGA. Each instance occupies one FPGA LB ID.                                                                                         |
| `instances[*].ipv4`              | IPv4 address \| null | At least one of ipv4/ipv6 | IPv4 address assigned to this FPGA LB instance.                                                                                                                                      |
| `instances[*].ipv6`              | IPv6 address \| null | At least one of ipv4/ipv6 | IPv6 address assigned to this FPGA LB instance.                                                                                                                                      |
| `instances[*].event_number_port` | u16                  | Yes                       | UDP port for event-number (sync) traffic on this instance.                                                                                                                           |

The number of instances determines how many concurrent load balancers can be active, up to a maximum of 8.

The IPv4 and IPv6 addresses must be routable for the nodes sending/receiving, these are the addresses you are assigning to be used as load balancer addresses, and the addresses the UDP traffic from the senders will send to.

---

## `database` — SQLite state store

```yaml
database:
  file: "/var/lib/udplbd/udplbd.db"
  cleanup_interval: "60s"
  cleanup_age: "4h"
  fsync: false
  archive_dir: "/var/lib/udplbd/archive"
  archive_rotation: "72h"
  archive_keep: 10
  backup_before_migrate: true
```

| Field                   | Type         | Default | Description                                                                                                                                                               |
| ----------------------- | ------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `file`                  | path         | —       | Path to the SQLite database file. Created automatically on first start.                                                                                                   |
| `cleanup_interval`      | duration     | `"60s"` | How often the background cleanup task runs.                                                                                                                               |
| `cleanup_age`           | duration     | `"4h"`  | Soft-deleted rows older than this are permanently purged from the hot database.                                                                                           |
| `fsync`                 | bool         | `false` | Enable full fsync for every write. Increases durability at the cost of write performance. Suitable for deployments where the DB is on spinning rust or an unreliable SSD. |
| `archive_dir`           | path \| null | `null`  | Directory where purged rows are written as rotated archive SQLite databases. If `null`, purged rows are discarded. Set this to retain a long-term audit trail.            |
| `archive_rotation`      | duration     | `"1d"`  | How much wall-clock time each archive database covers before a new one is started.                                                                                        |
| `archive_keep`          | u32          | `7`     | Number of rotated archive databases to keep before the oldest is deleted.                                                                                                 |
| `backup_before_migrate` | bool         | `true`  | Create a timestamped copy of the database file before applying schema migrations. Strongly recommended in production.                                                     |

---

## `controller` — Reservation control loop

```yaml
controller:
  duration: "1s"
  offset: "800ms"
```

| Field      | Type     | Default   | Description                                                                                                                                                                          |
| ---------- | -------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `duration` | duration | `"1s"`    | How often the control loop ticks. Each tick recalculates slot assignments and pushes P4 rules for the next epoch.                                                                    |
| `offset`   | duration | `"800ms"` | Phase offset of the tick relative to the wall-clock second. The controller fires at `<next whole second> + offset`, giving it time to prepare rules for the upcoming epoch boundary. |

Reducing `duration` increases responsiveness to changes in worker fill percentages at the cost of more frequent SmartNIC gRPC calls.

---

## `server` — gRPC and REST server

```yaml
server:
  auth_token: "CHANGE_THIS"
  listen:
    - "0.0.0.0:19523"
    - "[::]:19523"
  allow_private: true
  allow_loopback: false
  require_registration_from_dataplane: false
  tls:
    enable: false
    cert_file: null
    key_file: null
```

| Field                                 | Type                   | Default | Description                                                                                                                                                                                                 |
| ------------------------------------- | ---------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth_token`                          | string                 | —       | **The root admin token.** This is the credential for all gRPC and REST API calls. It must be a long, randomly generated string (e.g. `openssl rand -base64 32`). See [User Management](user-management.md). |
| `listen`                              | list\<socket address\> | —       | List of `host:port` addresses to listen on. Supports IPv4 and IPv6 (bracket the host for IPv6: `[::]:19523`). The same port serves gRPC, REST, and `/metrics`.                                              |
| `allow_private`                       | bool                   | `true`  | Allow workers to register from RFC 1918 (IPv4) or RFC 4193 (IPv6) private addresses. Set to `false` in internet-facing deployments if all workers use public IPs.                                           |
| `allow_loopback`                      | bool                   | `false` | Allow workers to register from loopback addresses (`127.0.0.0/8`, `::1`). Automatically set to `true` in mock mode.                                                                                         |
| `require_registration_from_dataplane` | bool                   | `false` | If `true`, the IP address a worker registers with must match the IP of the gRPC connection. Prevents workers from registering on behalf of other hosts.                                                     |
| `tls.enable`                          | bool                   | `false` | Enable TLS for the gRPC and REST server. See [Installation — TLS setup](installation.md#tls-setup).                                                                                                         |
| `tls.cert_file`                       | path \| null           | `null`  | Path to the PEM-encoded TLS certificate. Required when `tls.enable: true`.                                                                                                                                  |
| `tls.key_file`                        | path \| null           | `null`  | Path to the PEM-encoded TLS private key. Required when `tls.enable: true`.                                                                                                                                  |

---

## `rest` — REST API and web frontend

```yaml
rest:
  enable: true
```

| Field    | Type | Default | Description                                                                                                |
| -------- | ---- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `enable` | bool | `true`  | Enable the REST API server and embedded web frontend. When disabled, only the gRPC interface is available. |

The REST server is served on the same port and TLS configuration as the gRPC server.

---

## `log` — Logging

```yaml
log:
  level: info
```

| Field   | Type   | Default  | Description                                                                                                        |
| ------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `level` | string | `"info"` | Log verbosity. See [Observability — Logging](observability.md#logging) for the available levels and their meaning. |

The `RUST_LOG` environment variable overrides this field and accepts full `tracing-subscriber` filter directives for per-module control.

---

## `smartnic` — SmartNIC connections

```yaml
smartnic:
  - host: "fpga-host.example.net"
    port: 50055
    auth_token: "secret"
    mock: false
    tls:
      enable: false
      verify: false
      ca_file: null
    clear_table_repeats: 1
    cfg_host: "fpga-host.example.net"
    cfg_port: 50056
    cfg_auth_token: "cfg-secret"
```

This is a list; each entry configures one SmartNIC P4 service connection. Most deployments have one entry. Setting the list to `[]` disables SmartNIC integration (only useful with `udplbd mock`).

| Field                 | Type           | Default | Description                                                                                                                               |
| --------------------- | -------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `host`                | string         | —       | Hostname or IP of the sn-p4 gRPC service.                                                                                                 |
| `port`                | u16            | —       | Port of the sn-p4 gRPC service, generally the port traefik is listening on.                                                               |
| `auth_token`          | string         | —       | Authentication token for the sn-p4 gRPC service from `.env` of smartnic                                                                   |
| `mock`                | bool           | `false` | If `true`, skip connecting to this SmartNIC (used internally by `udplbd mock`).                                                           |
| `tls.enable`          | bool           | —       | Enable TLS for the sn-p4 gRPC connection.                                                                                                 |
| `tls.verify`          | bool           | —       | Verify the sn-p4 server certificate. Set to `false` only for self-signed certs without a `ca_file`.                                       |
| `tls.ca_file`         | path \| null   | `null`  | Path to a PEM CA certificate to trust for the sn-p4 connection. Use when the SmartNIC host uses a self-signed or internal CA certificate. |
| `clear_table_repeats` | usize          | `1`     | Number of times to repeat P4 table clear operations. Increase to 2–3 if stale rules persist after restart (firmware-specific workaround). |
| `cfg_host`            | string \| null | `null`  | Hostname or IP of the sn-cfg gRPC service. If omitted, automatic MAC discovery and pipeline statistics are unavailable.                   |
| `cfg_port`            | u16 \| null    | `null`  | Port of the sn-cfg gRPC service.                                                                                                          |
| `cfg_auth_token`      | string \| null | `null`  | Authentication token for the sn-cfg gRPC service from `.env` of smartnic                                                                  |

See ["Configuring the firmware runtime environment" of the README.STACK.INSTALL.md](https://github.com/esnet/esnet-smartnic-fw/blob/main/sn-stack/README.STACK.INSTALL.md#configuring-the-firmware-runtime-environment) for more information about the SmartNIC `.env`

---

## `metrics_collector` — SmartNIC statistics collection

```yaml
metrics_collector:
  enable: true
  interval: "5s"
```

| Field      | Type     | Default | Description                                                                                                                                 |
| ---------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `enable`   | bool     | `true`  | Collect P4 pipeline statistics from the SmartNIC and expose them via Prometheus metrics and the REST frontend. Also controls health checks. |
| `interval` | duration | `"5s"`  | How often to poll the SmartNIC for pipeline statistics.                                                                                     |

If the `metrics_collector` section is absent entirely, collection is enabled with a 30-second interval.

---

## `mock` — Mock dataplane address mapping

```yaml
mock:
  address_map:
    "192.0.2.1": "127.0.0.1:19522"
    "2001:db8::1": "[::1]:19522"
```

This section is only relevant when running `udplbd mock`. It maps FPGA LB instance IP addresses to local socket addresses, allowing the software dataplane to bind to localhost ports during testing.

| Field         | Type                      | Description                                                                                                                 |
| ------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `address_map` | map\<IP, socket address\> | Each key is an FPGA LB instance IP (from `lb.instances`); the value is the local address the mock dataplane should bind to. |

The `etc/example-config.yml` file in the repository includes a complete mapping for the default 8-instance configuration.
