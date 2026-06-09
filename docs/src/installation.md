# Installation

This chapter covers everything needed to get udplbd running in production: prerequisites, the Docker Compose deployment layout, configuration, TLS setup, SmartNIC integration, and upgrading.

## Prerequisites

### Hardware and firmware

- An ESnet SmartNIC (Alveo U55C or similar) flashed with the `udplb` P4 bitfile
  - [SmartNIC README.STACK.SETUP.md](https://github.com/esnet/esnet-smartnic-fw/blob/main/sn-stack/README.STACK.SETUP.md)
  - [SmartNIC README.STACK.INSTALL.md](https://github.com/esnet/esnet-smartnic-fw/blob/main/sn-stack/README.STACK.INSTALL.md)
  - [esnet/udplb repo](https://github.com/esnet/udplb)
- The `sn-p4` gRPC service and `sn-cfg` gRPC service running on the FPGA host (part of [esnet-smartnic-fw](https://github.com/esnet/esnet-smartnic-fw))

##  Creating a new instance

Each udplbd instance runs in its own directory. Multiple instances can coexist on the same host, each with its own data volume and configuration. To maxmimize the number of possible LB intstances, one control plane can be configured per stack. In scenarios such as this, the stack number is typically reflected in both the directory name (e.g. `prod4`) and the SmartNIC gRPC port (e.g. stack 4 uses port 8444 = 8440 + 4), which makes log correlation across stacks easier.

A typical host layout:

```
/usr/local/smartnic/udplbd/
├── prod4/
│   ├── docker-compose.yml
│   ├── data/               # database and archive files (mounted as /data)
│   └── etc/                # configuration files (mounted as /etc/udplbd)
│       └── config.yml      # udplbd configuration
├── prod9/
│   ├── docker-compose.yml
│   ├── data/
│   └── etc/
└── beta/
    ├── docker-compose.yml
    ├── data/
    └── etc/
```

### docker-compose.yml

```yaml
services:
  udplbd:
    image: esnet/udplbd2:latest
    platform: linux/amd64
    restart: always
    volumes:
      - ./data:/data
      - ./etc:/etc/udplbd
      - /etc/letsencrypt/archive:/certs/archive
      - /etc/letsencrypt/live:/certs/live
    environment:
      UDPLBD_CONFIG: "/etc/udplbd/config.yml"
    command: udplbd start
    network_mode: host
    logging:
      driver: "local"
      options:
        max-size: "100m"
        max-file: "3"
```

Key points:

- **`network_mode: host`** — required to access host interfaces ARP tables/IPv6 ND to populate MAC addresses in `udplb`
- **`UDPLBD_CONFIG`** — colon-separated list of config files merged left-to-right (later files take precedence). The per-instance file (`prod4.yml`) is listed first so the shared base (`config.yml`) can provide defaults that the instance file overrides. See [Configuration Reference](configuration.md#multi-file-merging) for merging semantics.
- **`/certs/*` mounts** — needed when pointing `tls.cert_file` and `tls.key_file` at Let's Encrypt paths (see [TLS setup](#tls-setup)).
- **`restart: always`** — the daemon automatically recovers from crashes and host reboots.
- **`logging`** — log rotation is handled by Docker's local driver; adjust `max-size` and `max-file` to suit your retention policy.

### Creating docker directory structure

```sh
mkdir -p /usr/local/smartnic/udplbd/prod4/{data,etc}
cd /usr/local/smartnic/udplbd/prod4
```


### Configuration

Then, write the `etc/config.yml` by copying [`etc/example-config.yml`](https://github.com/esnet/udplbd2/blob/main/etc/example-config.yml) to `etc/config.yml` and filling out the config appropiately. Typically, you will generally need to change at least the following:

  - 8 IPv4/IPv6 addresses to assign to load balancers, for the `lb.instances` section
  - An admin token you generated, for `server.auth_token`
  - The auth tokens and connection details from the SmartNIC `.env` and Docker Compose, see ["Configuring the firmware runtime environment" of the README.STACK.INSTALL.md](https://github.com/esnet/esnet-smartnic-fw/blob/main/sn-stack/README.STACK.INSTALL.md#configuring-the-firmware-runtime-environment) for the `smartnic` section

See [Configuration Reference](configuration.md) for a description of every field.


#### Set the auth token

Update the `server.auth_token` with a securely generated credential, which you can generate with `openssl rand -base64 32`

#### Assign addresses to the dataplane

Assign publicly routable addresses to your dataplane in the `lb.instances` section, and set `data_plane_interface` to the name of the interface that should be used for MAC address resolution, must be on the same network as your `lb.instances` addresses.

```yaml
# Load balancer configuration
lb:
  # [MAC address, string] Unicast MAC address for L2 rules, set to null or delete to fetch from sn-cfg
  mac_unicast: null # "02:00:DE:CA:FB:AD"
  # [String, optional] Network interface name to use for MAC address lookups (must be on same LAN as FPGA)
  # If not specified, all interfaces will be searched
  data_plane_interface: null # "eth0"
  # List of load balancer instances. Each instance must specify IPv4, IPv6, and event number port.
  # These are the addresses you are assigning to the FPGA
  instances:
    - ipv4: "192.0.2.1" # [IPv4 address] Load balancer instance 1
      ipv6: "2001:DB8::1" # [IPv6 address] Load balancer instance 1
      event_number_port: 19531 # [u16] UDP port for event number traffic
    - ipv4: "192.0.2.2"
      ipv6: "2001:DB8::2"
      event_number_port: 19532
    - ipv4: "192.0.2.3"
      ipv6: "2001:DB8::3"
      event_number_port: 19533
    - ipv4: "192.0.2.4"
      ipv6: "2001:DB8::4"
      event_number_port: 19534
    - ipv4: "192.0.2.5"
      ipv6: "2001:DB8::5"
      event_number_port: 19535
    - ipv4: "192.0.2.6"
      ipv6: "2001:DB8::6"
      event_number_port: 19536
    - ipv4: "192.0.2.7"
      ipv6: "2001:DB8::7"
      event_number_port: 19537
    - ipv4: "192.0.2.8"
      ipv6: "2001:DB8::8"
      event_number_port: 19538
```

#### Enabling TLS

TLS must be enabled for production deployments.

```yaml
server:
  tls:
    enable: true
    cert_file: "/certs/live/udplbd.example.net/fullchain.pem"
    key_file: "/certs/live/udplbd.example.net/privkey.pem"
```

Both fields are required when `enable: true`. Mount the Let's Encrypt live directory (or your CA's certificate paths) into the container as shown in the `docker-compose.yml` example above.

Mount the files into `/etc/udplbd/` alongside the config and reference them with:

```yaml
server:
  tls:
    enable: true
    cert_file: "/etc/udplbd/server.crt"
    key_file: "/etc/udplbd/server.key"
```

#### SmartNIC integration

udplbd programs the SmartNIC P4 pipeline via two gRPC services provided by [esnet-smartnic-fw](https://github.com/esnet/esnet-smartnic-fw):

| Service  | Purpose                                                            |
| -------- | ------------------------------------------------------------------ |
| `sn-p4`  | Insert, update, and delete P4 table rules (load balancer calendar) |
| `sn-cfg` | Read MAC address, collect pipeline statistics                      |

Each entry in the `smartnic` list describes one SmartNIC.

```yaml
smartnic:
  - host: "ejfat-lb.es.net"
    port: 8444                        # sn-p4 port; convention: 8440 + stack number
    auth_token: "sn-p4-secret"
    mock: false
    tls:
      enable: true
      verify: true
      ca_file: null                   # set if using a private CA cert
    clear_table_repeats: 1
    cfg_host: "ejfat-lb.es.net"       # sn-cfg host (usually same as sn-p4)
    cfg_port: 8444                    # sn-cfg port (usually same as sn-p4)
    cfg_auth_token: "sn-cfg-secret"
```

One of the key features of EJFAT is that it is possible to have one `udplbd` instance connect to multiple ESnet SmartNIC stacks running `udplb` to horizontally scale the bandwidth. In this deployment scenario, all FPGA ports must be connected in a LAG.

 See ["Configuring the firmware runtime environment" of the README.STACK.INSTALL.md](https://github.com/esnet/esnet-smartnic-fw/blob/main/sn-stack/README.STACK.INSTALL.md#configuring-the-firmware-runtime-environment) for more information about the `.env` where you can get these values.

#### Starting up udplbd

```
docker compose up -d
docker compose logs -f udplbd
```

You should see something like
```
2026-06-09T17:06:38.235878Z  INFO axum server starting: http://<server.listen>
```
at the bottom of the logs if the server started successfully.


The database is created automatically at `/data/udplbd.db` on first start. Schema migrations also run automatically on startup; if any are pending, a pre-migration backup is written first (see [Database Administration](database.md#migrations)).


### Verifying installation

The `doctor` tool verifies end-to-end EJFAT behavior:

Set the `EJFAT_URI` by combining a listen address with your auth token:

```sh
export EJFAT_URI=ejfats://<server.auth_token>@<server.listen>/
# address must be accessible to the same network as the `lb.instances`, port is arbitrary
docker compose exec udplbd udplbd doctor -a <dataplane_address> -p 19500
```

Verify the frontend is accessible by visiting `https://<server.listen>` and pasting in the token you generated. Then, you can use that interface to create tokens for users, see [User Management](user-management.md)

You can use the [e2sar_perf tool](https://github.com/JeffersonLab/E2SAR#control-plane-and-other-tools) for performance testing.

## Upgrading

1. Update the image tag in `docker-compose.yml`.
2. Pull and restart:

   ```sh
   docker compose pull
   docker compose up -d
   ```

   Migrations run automatically on startup. If any are pending, a pre-migration backup is created first at `/data/udplbd.db.pre-migrate.bak`. The startup log confirms the outcome:

   ```
   INFO udplbd: 1 pending migration(s), backing up database to /data/udplbd.db.pre-migrate.bak
   ```

3. Confirm a clean start:

   ```sh
   docker compose logs -f
   ```

### Rollback

```sh
docker compose stop
cp data/udplbd.db.pre-migrate.bak data/udplbd.db
# revert the image tag in docker-compose.yml, then:
docker compose up -d
```

### Active reservations during upgrade

When the container stops, the P4 forwarding state in the SmartNIC continues to work autonomously — the FPGA keeps forwarding with its current calendar. The control loop (epoch scheduling and slot rebalancing) pauses until the container restarts. Keep downtime minimal to avoid sessions becoming stale during downtime.
