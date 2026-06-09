# Troubleshooting

## Quick diagnostics

Ensure your `EJFAT_URI` is set to a token with sufficient scope to diagnose the problem, typically a token with UPDATE ALL or UPDATE LOAD_BALANCER on the control plane instance for the deployment where the problem is occuring.

```sh
# verify the daemon is reachable and check its build version
udplbd client version

# see all active load balancers, workers, and any health issues
udplbd client overview

# end-to-end dataplane send/receive test
udplbd dataplane doctor -a <dataplane_address> -p <recv_port>
```

When running inside Docker:

```sh
docker compose exec udplbd udplbd client version
docker compose logs -f
```

## Common errors

### Startup failures

| Error message                                                            | Cause                                                                                   | Fix                                                                                                                     |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `failed to clear tables`                                                 | sn-p4 gRPC unreachable at startup (no existing reservations, so tables must be cleared) | Check `smartnic.host`, `port`, `auth_token`, and `tls` settings; verify the `sn-p4` service is running on the FPGA host |
| `sn-cfg returned no mac addresses and lb.mac_unicast was not configured` | `cfg_*` fields not set and no manual MAC                                                | Set `lb.mac_unicast` in the config, or configure `cfg_host`, `cfg_port`, and `cfg_auth_token`                           |
| `no listen address in server config`                                     | `server.listen` is empty                                                                | Add at least one socket address to `server.listen`                                                                      |
| `TLS enabled but cert_file or key_file missing`                          | Incomplete TLS config                                                                   | Set both `server.tls.cert_file` and `server.tls.key_file`                                                               |
| `invalid suffix in duration: …`                                          | Wrong duration format in config                                                         | Use `ms`, `s`, `h`, or `d` suffixes (e.g. `"800ms"`, `"4h"`)                                                            |
| `Failed to load TLS config: …`                                           | Certificate or key file missing or malformed                                            | Check the file paths are correctly mounted into the container and that the PEM content is valid                         |

## Additional debugging commands

These commands are available as subcommands of `udplbd dataplane`. Most require `EJFAT_URI` or a `--url` pointing at a running server.

```sh
# pretty-print raw UDP payloads arriving on a port
udplbd dataplane print --address 0.0.0.0 --port <port>

# receive EJFAT events and pipe them to a command
udplbd dataplane recv --address <dataplane_address> --port <port> -- /bin/cat

# send a test event stream from a file
udplbd dataplane send --file /path/to/file

# reassemble events from a PCAP capture
udplbd dataplane pcap /path/to/capture.pcap

# run automated dataplane test scenarios from a JSON config
udplbd dataplane test --address <dataplane_address> --port <port> /path/to/test.json
```

## Increasing log verbosity

Temporarily enable debug logging without rebuilding the container by setting `RUST_LOG`:

```yaml
# docker-compose.yml
environment:
  UDPLBD_CONFIG: "/etc/udplbd/stable4.yml:/etc/udplbd/config.yml"
  RUST_LOG: "debug"
```

```sh
docker compose up -d
docker compose logs -f
```

Revert by removing `RUST_LOG` and restarting. Use `trace` for full wire-level detail (very high volume).

See [Observability — Logging](observability.md#logging) for a description of each level.

## Inspecting health issues

Health issues appear in `udplbd client overview` output under each load balancer and worker:

```
  health_issues:
    - [WARN] receiver_packet_stall (2026-06-09 12:34:00 UTC): Receiver example1 (session_id=123) is not reporting received packets despite FPGA sending 9001 packets
```

Each issue includes:
- **Severity** (`WARN` or `ERROR`)
- **Type** — a short identifier for the class of problem
- **Detection time** — when the issue was first observed
- **Message** — a human-readable description

Issues clear automatically when the underlying condition resolves. They are also visible in the web frontend dashboard.

See [Database Administration](database.md) for more about the udplbd2 database.
