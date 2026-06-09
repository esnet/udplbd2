# Observability

udplbd exposes three observability interfaces: **Prometheus metrics**, **structured logs**, and the **web frontend**. All three are available immediately after `udplbd start` with no additional configuration.

---

## Web frontend

The embedded web frontend is served at the root of the listen address:

```
http(s)://<listen-address>/
```

In other words, you can take an EJFAT URI, and replace the `ejfats` with `https` to access the HTTP interface.

It is enabled by default (`rest.enable: true`) and can be disabled in `config.yml` if not needed.

**Login:** enter any valid token in the login field. The frontend uses the same Bearer token authentication as the gRPC and REST APIs — permissions are enforced server-side.

### Dashboard

The dashboard provides:

- **Active load balancers:** names, FPGA IDs, sync and data addresses, current epoch, reservation expiry.
- **Worker sessions:** per-session fill percentage, slot count, control signal, event counters (received, reassembled, reassembly errors, dequeued).
- **Health issues:** warnings and errors reported by the health check subsystem, with severity, type, and detection timestamp.
- **Time-series charts:** fill percentage and slot distribution over time, useful for spotting imbalance or saturation trends.

### Token management

The **Tokens** view in the frontend mirrors the CLI token commands: create child tokens, inspect permissions, list descendants, and revoke tokens — all from the browser.

### Prometheus metrics link

The frontend includes a direct link to the raw `/metrics` endpoint for quick access when configuring Prometheus or checking raw counter values.

---

## Prometheus metrics

Metrics are exposed in the standard Prometheus text format at:

```
http(s)://<listen-address>/metrics
```

This endpoint is served on the same port and TLS configuration as the gRPC and REST API — no separate port is needed. The endpoint requires no authentication.

**Example scrape config:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: udplbd
    static_configs:
      - targets: ["udplbd.example.net:19523"]
    scheme: https   # match server.tls.enable
    tls_config:
      ca_file: /etc/prometheus/udplbd-ca.crt   # if using a private CA
```

### Metric reference

#### Control plane counters

| Metric                          | Labels | Description                                                                                                                                                           |
| ------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `udplbd_epochs_processed_total` | —      | Total number of P4 calendar epochs computed and pushed to the SmartNIC. Increments once per reservation per control loop tick when a new epoch boundary is scheduled. |
| `udplbd_inbound_grpc_total`     | —      | Total gRPC requests received by the control plane API.                                                                                                                |
| `udplbd_inbound_rest_total`     | —      | Total REST requests received by the REST/web frontend.                                                                                                                |

#### SmartNIC gRPC operations

| Metric                              | Labels      | Description                                                                                                                           |
| ----------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `udplbd_smartnic_grpc_total`        | `operation` | Total SmartNIC gRPC calls, labelled by operation name.                                                                                |
| `udplbd_smartnic_grpc_errors_total` | `operation` | Total SmartNIC gRPC errors, labelled by operation name. A sustained non-zero error rate indicates a connectivity or firmware problem. |

Operation names include: `get_pipeline_info`, `clear_tables`, `clear_table`, `insert_rule`, `update_rule`, `delete_rule`, `get_device_info`, `get_pipeline_stats`, `clear_pipeline_stats`, `get_stats`, `clear_stats`, `get_server_config`, `set_server_config`, `get_server_status`.

**Useful alert:** `rate(udplbd_smartnic_grpc_errors_total[1m]) > 0` — any SmartNIC gRPC error warrants investigation.

#### SmartNIC BulkUpdate latency

| Metric                                | Labels | Description                                                                                                                                                                                                                                 |
| ------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `udplbd_bulk_update_duration_seconds` | —      | Histogram of BulkUpdate gRPC call durations. Buckets span from 1 ms to ~16 s (exponential, base 2, 15 buckets). High p99 values here indicate the SmartNIC is slow to accept rule updates, which can cause epoch scheduling to fall behind. |

#### Per-LB instance gauges

All per-LB metrics carry the label `fpga_lb_id` (the 0-based FPGA slot index, as a string).

| Metric                            | Labels       | Description                                                                                                                                                        |
| --------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `udplbd_lb_is_active`             | `fpga_lb_id` | `1` when the LB instance has an active reservation; `0` otherwise.                                                                                                 |
| `udplbd_lb_active_sessions_total` | `fpga_lb_id` | Number of worker sessions currently registered on this LB instance.                                                                                                |
| `udplbd_lb_tick_duration_seconds` | `fpga_lb_id` | Wall-clock duration of the most recent control loop tick for this LB. Values consistently above `controller.duration` indicate the control loop is falling behind. |
| `udplbd_lb_epoch_boundary`        | `fpga_lb_id` | The event number at which the next epoch begins. Useful for correlating data-plane logs with control-plane state changes.                                          |
| `udplbd_lb_slots_avg`             | `fpga_lb_id` | Average number of P4 calendar slots assigned across all registered workers.                                                                                        |
| `udplbd_lb_slots_stddev`          | `fpga_lb_id` | Standard deviation of slot counts. High stddev with many workers may indicate the load-balancing algorithm is not converging.                                      |
| `udplbd_lb_slots_max`             | `fpga_lb_id` | Maximum slot count held by any single worker.                                                                                                                      |
| `udplbd_lb_slots_min`             | `fpga_lb_id` | Minimum slot count held by any single worker.                                                                                                                      |
| `udplbd_lb_fill_percent_avg`      | `fpga_lb_id` | Average fill percentage reported by workers. Near 100% means workers are saturated.                                                                                |
| `udplbd_lb_fill_percent_stddev`   | `fpga_lb_id` | Standard deviation of fill percentages. High stddev indicates uneven load distribution.                                                                            |
| `udplbd_lb_fill_percent_max`      | `fpga_lb_id` | Highest fill percentage among all workers.                                                                                                                         |
| `udplbd_lb_fill_percent_min`      | `fpga_lb_id` | Lowest fill percentage among all workers.                                                                                                                          |

### Suggested alerts

```yaml
# Prometheus alerting rules
groups:
  - name: udplbd
    rules:
      - alert: UdplbdSmartNICErrors
        expr: rate(udplbd_smartnic_grpc_errors_total[5m]) > 0
        for: 2m
        annotations:
          summary: "SmartNIC gRPC errors on {{ $labels.operation }}"

      - alert: UdplbdWorkersFull
        expr: udplbd_lb_fill_percent_avg > 90
        for: 1m
        annotations:
          summary: "LB {{ $labels.fpga_lb_id }} workers averaging >90% fill"

      - alert: UdplbdTickSlow
        expr: udplbd_lb_tick_duration_seconds > 2
        for: 30s
        annotations:
          summary: "Control loop tick taking >2s on LB {{ $labels.fpga_lb_id }}"
```

---

### Log levels

Set `log.level` in `config.yml` or override at runtime with `RUST_LOG`.

| Level      | What is logged                                                                                                                                                                    |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `error`    | Fatal and unrecoverable errors only.                                                                                                                                              |
| `warn`     | Recoverable errors: permission denials, certificate reload failures, SmartNIC transient errors.                                                                                   |
| `info`     | Default. Startup events, reservations created and freed, TLS certificate reloads, epoch boundaries. All log messages include relevant audit fields (token IDs, source addresses). |
| `info-all` | Same as `info` but includes `tonic`, `hyper`, and `tower_http` framework messages.                                                                                                |
| `debug`    | Per-request detail, P4 rule updates, slot recalculations, database queries summarized. Verbose but still readable in production for short periods.                                |
| `trace`    | Full wire-level detail: all gRPC frames, SQL queries, thread IDs. High volume; suitable only for targeted debugging.                                                              |

### Log format

In `info` mode, each line is a single-line human-readable message:

```
2026-01-15T12:34:56.789Z  INFO udplbd::api::handlers::lb: reserve_load_balancer: name=team-alpha, lb_id=1, source=10.0.0.5:52341
```

In `trace` mode, thread IDs and module targets are included for correlation with concurrent operations.


---

## Health checks

udplbd performs periodic health checks against the SmartNIC and worker sessions, controlled by `metrics_collector.enable` and `metrics_collector.interval` in `config.yml` (see [Configuration Reference](configuration.md#metrics_collector--smartnic-statistics-collection)).

Health check results appear in:

- The `health_issues` field of `udplbd client overview` output.
- The dashboard **Health issues** panel in the web frontend.
- Log messages at `warn` level when new issues are detected.

Each issue includes a `severity`, a `type` identifier, a human-readable `message`, and the timestamp when it was first detected. Issues clear automatically when the underlying condition resolves.
