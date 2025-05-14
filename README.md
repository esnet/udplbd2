# EJFAT Control Plane (udplbd)

## Overview

`udplbd` is the control plane for the EJFAT (ESnet-Jefferson Lab FPGA-Accelerated Transport) project. It provides
a gRPC API that EJFAT workflows use to coordinate changes to EJFAT load balancers. It also provides administration, testing, and debugging tools for EJFAT workflows.

`udplbd` works by updating the P4 tables of the udplb dataplane which is developed via the [ESnet
SmartNIC](https://github.com/esnet/esnet-smartnic-fw) project. Tables are updated via the sn-p4 API.
Setting up the data plane is a requirement before running `udplbd start`, as you need an FPGA to control
for `udplbd start` to do anything meaningful.

It is written in Rust for memory safety and to minimize the possibility of data races. It uses SQLite with
an append-only schema design (configurable retention) to enable seamless recovery and the ability to inspect
this historical state of the control plane. udplbd also integrates `turmoil` for testing in simulation.

## Features

- **gRPC Server**: Manages dynamic load balancers.
- **Static Configuration**: Applies static load balancer configurations from a YAML file.
- **Mock Server**: Starts the gRPC server with a simulated dataplane.
- **API Commands**: Interacts with the gRPC control plane.
- **Dataplane Testing**: Commands for testing the dataplane (e.g., recv, send, doctor, test, print, pcap).

## Installation

### Using Docker

1. **Build the Docker Image**

   ```bash
   docker build -t udplbd .
   ```

2. **Run the Docker Container**

   ```bash
   docker run -d --name udplbd -v /path/to/config.yml:/etc/udplbd/config.yml udplbd
   ```

### From Source

1. **Clone the Repository**

   ```bash
   git clone https://github.com/esnet/udplbd2.git
   cd udplbd2
   ```

2. **Build the Project**

   ```bash
   cargo install --path .
   ```

3. **Run the Application**

  Ensure that the ESnet SmartNIC applications are running, and that the udplb bitfile was flashed to an FPGA.
  Configure the `/etc/udplbd/config.yml` appropiately then

   ```bash
   udplbd start
   ```

## Configuration

All commands currently require a config file, you can use the example one if you are only using client/dataplane commands.

Configuration can be provided via a YAML file or environment variables. The configuration file is located at `/etc/udplbd/config.yml` by default, but this can be overridden using the `--config` flag or the `UDPLBD_CONFIG` environment variable.

### Example Configuration File

See `./etc/example-config.yml`. You can use this file directly plus an `EJFAT_URI` if you are only using client/dataplane commands, this will eventually be the default behavior.

## Usage

### Command-Line Interface

The `udplbd` command-line interface provides several subcommands for different operational modes and configuration options.

#### Start the gRPC Server

```bash
udplbd start  # uses /etc/udplbd/config.yml
udplbd start --config /path/to/config.yml
```

#### Apply Static Configuration

```bash
udplbd static --reservation-file /path/to/reservation.yml --apply
```

#### Start the Mock Server

```bash
udplbd mock # uses built-in testing config, only works on localhost
```

#### gRPC API Commands

```bash
udplbd client reserve --name "my_lb" --sender "192.168.1.123" --after "1hour"
```

#### Dataplane Testing Commands

```bash
udplbd dataplane --url "ejfats://your_auth_token@0.0.0.0:50051" recv --address "192.168.1.123" --port 50052 --command "cat"
```

### API Commands

The `client` subcommand provides several commands for interacting with the gRPC control plane. Client commands require an `EJFAT_URI` environment variable OR the specified config file to actually be running with `udplbd start` or `udplbd mock`.

- **Reserve a Load Balancer**

  ```bash
  udplbd client reserve --name "my_lb" --sender "192.168.1.1" --after "1hour"
  ```

- **Free a Reserved Load Balancer**

  ```bash
  udplbd client free
  ```

- **Display Load Balancer Overview**

  ```bash
  udplbd client overview
  ```

- **Manage Allowed Sender IP Addresses**

  ```bash
  udplbd client senders add --addresses "192.168.1.1" "192.168.1.2"
  udplbd client senders remove --addresses "192.168.1.1"
  ```

- **Manage Authentication Tokens**

  ```bash
  udplbd client tokens create --name "admin" --resource-type "ALL" --permission "READ"
  udplbd client tokens list-permissions
  udplbd client tokens list-children
  udplbd client tokens revoke --token 123
  ```

- **Display Version**

  ```bash
  udplbd client version
  ```

### Dataplane Commands

The `dataplane` subcommand provides several commands for testing the dataplane. Most dataplane commands require an `EJFAT_URI` environment variable OR the specified config file to actually be running with `udplbd start` or `udplbd mock`.

- **Receive EJFAT Events**

  ```bash
  udplbd dataplane recv --address "<public IP>" --port 12345 -- /bin/cat
  ```

- **Send a File**

  ```bash
  udplbd dataplane send --file /path/to/file.txt
  ```

- **Perform Tests**

  ```bash
  udplbd dataplane test --address "<public IP>" --port 12345 /path/to/test_config.json
  ```

- **Run Turmoil Network Simulation Tests**

  ```bash
  udplbd dataplane sim /path/to/turmoil_config.json
  ```

- **Pretty Print Received UDP Payloads**

  ```bash
  udplbd dataplane print --address "0.0.0.0" --port 50052
  ```

- **Reassemble Packets from a PCAP File**

  ```bash
  udplbd dataplane pcap /path/to/pcap_file.pcap
  ```

## Logging

Logging is configured via the `log_level` parameter in the configuration file or the `--log-level` command-line flag. The default log level is `info`.

## Copyright Notice

ESnet-JLab FPGA Accelerated Transport (control plane) [EJFAT (udplbd2)]
Copyright (c) 2025, The Regents of the University of California, through
Lawrence Berkeley National Laboratory (subject to receipt of any required
approvals from the U.S. Dept. of Energy). All rights reserved.

If you have questions about your rights to use or distribute this software,
please contact Berkeley Lab's Intellectual Property Office at IPO@lbl.gov.

NOTICE.  This Software was developed under funding from the U.S. Department
of Energy and the U.S. Government consequently retains certain rights.  As
such, the U.S. Government has been granted for itself and others acting on
its behalf a paid-up, nonexclusive, irrevocable, worldwide license in the
Software to reproduce, distribute copies to the public, prepare derivative
works, and perform publicly and display publicly, and to permit others to do so.
