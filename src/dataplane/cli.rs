// SPDX-License-Identifier: BSD-3-Clause-LBNL
// src/dataplane/cli.rs
use clap::{Args, Parser, Subcommand};
use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::{fs::File, mem::size_of, path::Path};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::Semaphore;
use zerocopy::FromBytes;

use crate::api::client::{ControlPlaneClient, EjfatUrl}; // Reuse for URL parsing
use crate::config::Config;
use crate::dataplane::doctor::{doctor, doctor_multi};
use crate::dataplane::meta_events::MetaEventContext;
use crate::dataplane::protocol::EjfatEvent;
use crate::dataplane::protocol::{
    LBPayload, ReassemblyPayload, LB_HEADER_SIZE, REASSEMBLY_HEADER_SIZE,
};
use crate::dataplane::sender::Sender;
use crate::dataplane::tester;
use crate::errors::{Error, Result};
use crate::proto::loadbalancer::v1::PortRange;

use crate::dataplane::meta_events::MetaEventType;
use crate::dataplane::pcap::{reassemble_from_pcap, PcapReassemblyReport};
use crate::dataplane::protocol::LBHeader;
use crate::dataplane::receiver::Receiver;

use crate::macaddr::get_mac_addr;
use std::net::IpAddr;

use super::turmoil::tester::run_turmoil_test;

/// Dataplane commands for testing the EJFAT protocol.
///
/// Invoked via:
///   udplbd dataplane --url "ejfat://..." <command>
///
/// If no URL is provided, the default connection string is built from the server config.
#[derive(Parser, Debug)]
#[command(
    name = "dataplane",
    about = "Commands for testing the dataplane (e.g. recv, send, doctor, test, print, pcap)"
)]
pub struct DataplaneCli {
    /// EJFAT URL with token, host, and port. If not provided, a default is constructed from the server config.
    #[arg(short, long, env = "EJFAT_URI")]
    pub url: Option<String>,

    /// Load balancer id (for admin URLs).
    #[arg(short, long)]
    pub lbid: Option<String>,

    /// Output CSV file for meta events.
    #[arg(long)]
    pub csv: Option<String>,

    #[command(subcommand)]
    pub command: DataplaneCommand,
}

#[derive(Subcommand, Debug)]
pub enum DataplaneCommand {
    /// Receive EJFAT events and process them with a command.
    Recv(RecvArgs),
    /// Send a file as an event to an EJFAT load balancer.
    Send(SendArgs),
    /// Perform tests to detect issues with the load balancer.
    Doctor(DoctorArgs),
    /// Run tests using the specified configuration file.
    Test(TestArgs),
    /// Run turmoil network simulation tests.
    Sim(SimArgs),
    /// Pretty print received UDP payloads.
    Print(PrintArgs),
    /// Reassemble the packets in a PCAP file and report errors.
    Pcap(PcapArgs),
    /// Resolve MAC addresses for given IP addresses.
    MacAddr(MacAddrArgs),
}

#[derive(Args, Debug)]
pub struct RecvArgs {
    /// IP address to listen on.
    #[arg(short, long)]
    pub address: String,
    /// UDP port to listen on.
    #[arg(short, long)]
    pub port: u16,
    /// Directory to store command outputs.
    #[arg(short, long)]
    pub output: Option<String>,
    /// Set point (in number of FIFO entries) for the PID controller.
    #[arg(short, long, default_value = "4")]
    pub setpoint: usize,
    /// Proportional gain for the PID controller.
    #[arg(long, default_value = "0.0")]
    pub kp: f64,
    /// Integral gain for the PID controller.
    #[arg(long, default_value = "0.0")]
    pub ki: f64,
    /// Derivative gain for the PID controller.
    #[arg(long, default_value = "0.0")]
    pub kd: f64,
    /// MTU.
    #[arg(long, default_value = "1500")]
    pub mtu: usize,
    /// Name of the backend.
    #[arg(long, default_value = "default_hostname")]
    pub name: String,
    /// Expect packets to still contain LB headers.
    #[arg(long)]
    pub lb: bool,
    /// Minimum scaling factor for slot assignments.
    #[arg(long, default_value = "0.0")]
    pub minf: f32,
    /// Maximum scaling factor for slot assignments.
    #[arg(long, default_value = "0.0")]
    pub maxf: f32,
    /// Number of worker threads.
    #[arg(short, long, default_value = "4")]
    pub threads: usize,
    /// Command and its arguments to run on each received file.
    #[arg(last = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct SendArgs {
    /// File to send.
    #[arg(value_name = "FILE")]
    pub file: String,

    /// Address and port to send packets to directly (e.g., 127.0.0.1:8080).  If provided, bypasses gRPC.
    #[arg(long, value_name = "address:port")]
    pub to: Option<String>,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// One or more IP addresses to test (comma-separated or repeated).
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,
    /// UDP port to listen on.
    #[arg(short, long)]
    pub port: u16,
    /// MTU.
    #[arg(long, default_value = "1500")]
    pub mtu: usize,
    /// Expect packets to still contain LB headers.
    #[arg(long)]
    pub lb: bool,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// IP address to listen on.
    #[arg(short, long)]
    pub address: String,
    /// UDP port to listen on.
    #[arg(short, long)]
    pub port: u16,
    /// Path to the test configuration file.
    #[arg(value_name = "CONFIG")]
    pub config: String,
}

#[derive(Args, Debug)]
pub struct SimArgs {
    /// Path to the turmoil test configuration file.
    #[arg(value_name = "CONFIG")]
    pub config: String,
}

#[derive(Args, Debug)]
pub struct PrintArgs {
    /// IP address to listen on.
    #[arg(short, long)]
    pub address: String,
    /// UDP port to listen on.
    #[arg(short, long)]
    pub port: u16,
}

/// New arguments for processing a PCAP file.
#[derive(Args, Debug)]
pub struct PcapArgs {
    /// Path to the PCAP file.
    #[arg(value_name = "PCAP_FILE")]
    pub file: String,
    /// Expect packets to still contain LB headers.
    #[arg(long)]
    pub lb: bool,
}

#[derive(Args, Debug)]
pub struct MacAddrArgs {
    /// IP addresses to resolve MAC addresses for.
    #[arg(value_name = "IP_ADDRS")]
    pub ips: Vec<String>,
}

impl DataplaneCli {
    /// Run the dataplane command. If no URL is provided, a default is built from the server config.
    /// If a CSV file is specified, meta events will be enabled.
    pub async fn run(&self, config: &Config) -> Result<()> {
        // Get URL from CLI or build default from config.
        let url = match &self.url {
            Some(u) => u.clone(),
            None => {
                let listen_addr = config.server.listen.first().ok_or(Error::Config(
                    "no listen address in server config".to_string(),
                ))?;
                format!("ejfat://{}@{}", config.server.auth_token, listen_addr)
            }
        };

        // Inject lbid if provided.
        let url = if let Some(lbid) = &self.lbid {
            let mut parsed_url: EjfatUrl = url.parse()?;
            parsed_url.lb_id = Some(lbid.clone());
            parsed_url.to_string()
        } else {
            url
        };

        // If CSV is provided, set up meta events.
        let (mut meta_event_manager, meta_event_receiver) =
            crate::dataplane::meta_events::MetaEventManager::new(true);
        if let Some(csv_path) = &self.csv {
            meta_event_manager.enabled = true;
            let csv_path_clone = csv_path.clone();
            tokio::spawn(async move {
                crate::dataplane::meta_events::write_events_to_csv(
                    meta_event_receiver,
                    &csv_path_clone,
                )
                .expect("failed to write events to CSV");
            });
        }

        match &self.command {
            DataplaneCommand::Recv(args) => {
                receive_files(
                    url.to_string(),
                    args.name.clone(),
                    args.command.clone(),
                    args.output.clone(),
                    args.setpoint,
                    args.kp,
                    args.ki,
                    args.kd,
                    args.mtu,
                    args.address.clone(),
                    args.port,
                    args.lb,
                    args.minf,
                    args.maxf,
                    args.threads,
                )
                .await?;
            }
            DataplaneCommand::Send(args) => {
                let target_addr: Option<SocketAddr> = args
                    .to
                    .as_ref()
                    .map(|addr| addr.parse().expect("Invalid address:port format"));
                send_file(args.file.clone(), target_addr, url.to_string(), 0).await?;
            }
            DataplaneCommand::Doctor(args) => {
                if args.addresses.len() == 1 {
                    let output = doctor(
                        url.to_string(),
                        args.addresses[0].parse()?,
                        args.port,
                        args.mtu,
                        args.lb,
                    )
                    .await?;
                    println!("{}", output);
                } else {
                    let results = doctor_multi(
                        url.to_string(),
                        args.addresses.clone(),
                        args.port,
                        args.mtu,
                        args.lb,
                    )
                    .await;
                    for res in results {
                        match res {
                            Ok(output) => println!("{}", output),
                            Err(e) => eprintln!("doctor error: {}", e),
                        }
                    }
                }
            }
            DataplaneCommand::Test(args) => {
                let config_file = tester::load_config_from_json(&args.config)?;
                let ip_addr: std::net::IpAddr = args.address.parse().expect("Invalid IP address");
                let output = tester::run_test(
                    url.to_string(),
                    config_file,
                    ip_addr,
                    args.port,
                    &meta_event_manager,
                )
                .await?;
                println!("{}", output);
            }
            DataplaneCommand::Print(args) => {
                print_udp_payloads(&args.address, args.port).await?;
            }
            DataplaneCommand::Sim(args) => {
                let config =
                    crate::dataplane::turmoil::tester::load_config_from_json(&args.config)?;
                match tokio::task::spawn_blocking(move || {
                    run_turmoil_test(&meta_event_manager, None, config)
                })
                .await
                {
                    Ok(Ok(_)) => {
                        println!("simulation completed successfully")
                    }
                    Ok(Err(e)) => {
                        println!("simulation {e}")
                    }
                    Err(e) => {
                        println!("simulation crashed: {e}")
                    }
                }
            }
            DataplaneCommand::Pcap(args) => {
                // Call our function that analyzes the PCAP file and prints the results.
                let file = args.file.clone();
                let lb = args.lb;
                tokio::task::spawn(async move {
                    tokio::task::block_in_place(move || {
                        if let Err(e) = run_pcap_analysis(&file, lb) {
                            eprintln!("pcap analysis failed: {}", e);
                        }
                    });
                });
            }
            DataplaneCommand::MacAddr(args) => {
                for ip_str in &args.ips {
                    match ip_str.parse::<IpAddr>() {
                        Ok(ip) => match get_mac_addr(ip).await {
                            Ok(mac) => println!("{} -> {}", ip, mac),
                            Err(e) => eprintln!("{} -> error: {}", ip, e),
                        },
                        Err(e) => {
                            eprintln!("{} -> invalid IP address: {}", ip_str, e);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

use std::net::SocketAddr;

pub async fn send_file(
    file_path: String,
    target: Option<SocketAddr>,
    url: String,
    data_id: u16,
) -> Result<()> {
    let mut file = tokio::fs::File::open(file_path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let packets_sent = match target {
        Some(addr) => {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let mut sender = Sender::from_data_socket(socket, addr, None).await?;
            sender.send_ts(&buffer, data_id).await
        }
        None => {
            let mut sender = Sender::from_url(&url.parse().expect("bad URL"), None, false).await?;
            sender.send_ts(&buffer, data_id).await
        }
    };

    println!("{}", packets_sent);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn register(
    url: String,
    hostname: String,
    weight: f32,
    ip_address: String,
    port: u16,
    port_range: PortRange,
    min_factor: f32,
    max_factor: f32,
    keep_lb_header: bool,
) -> Result<ControlPlaneClient> {
    let mut client = ControlPlaneClient::from_url(url.as_str()).await?;
    client
        .register(
            hostname.to_string(),
            weight,
            ip_address.to_string(),
            port,
            port_range,
            min_factor,
            max_factor,
            keep_lb_header,
        )
        .await?
        .into_inner();
    Ok(client)
}

#[allow(clippy::too_many_arguments)]
async fn receive_files(
    url: String,
    hostname: String,
    command: Vec<String>,
    output_dir: Option<String>,
    set_point: usize,
    kp: f64,
    ki: f64,
    kd: f64,
    mtu: usize,
    ip_address: String,
    port: u16,
    with_lb_headers: bool,
    min_factor: f32,
    max_factor: f32,
    max_concurrent_tasks: usize,
) -> Result<()> {
    if with_lb_headers {
        let mut parsed_url: EjfatUrl = url.parse().expect("bad URL");
        parsed_url.data_addr_v4 = Some(ip_address.clone());
        println!("export 'EJFAT_URI={parsed_url}'");
    }

    let mut client = register(
        url.clone(),
        hostname,
        1.0,
        ip_address.clone(),
        port,
        PortRange::PortRange1,
        min_factor,
        max_factor,
        with_lb_headers,
    )
    .await?;

    recieve_and_execute(
        &mut client,
        command,
        output_dir,
        set_point,
        kp,
        ki,
        kd,
        mtu,
        ip_address,
        port,
        with_lb_headers,
        max_concurrent_tasks,
        None,
    )
    .await;

    Ok(())
}

async fn process_event(
    event: EjfatEvent,
    subcommand: Vec<String>,
    output_dir: Option<String>,
) -> io::Result<()> {
    if let Some(ref dir) = output_dir {
        let file_path = format!("{}/{}", dir, event.tick);
        let file = File::create(file_path)?;
        let output = Stdio::from(file);

        let mut child = Command::new(&subcommand[0])
            .args(&subcommand[1..])
            .stdin(Stdio::piped())
            .stdout(output)
            .spawn()?;

        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        stdin.write_all(&event.data).await?;
        stdin.flush().await?;
        drop(stdin);
        child.wait().await?;
    } else {
        let mut child = Command::new(&subcommand[0])
            .args(&subcommand[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let stdout = child.stdout.take().expect("Failed to open stdout");
        let write_result = async {
            stdin.write_all(&event.data).await?;
            stdin.flush().await?;
            drop(stdin);
            Ok::<(), io::Error>(())
        };
        let read_result = async {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await? {
                let prefixed_line = format!("{} | {}", event.tick, line);
                println!("{}", prefixed_line);
            }
            Ok::<(), io::Error>(())
        };
        let (write_res, read_res) = tokio::join!(write_result, read_result);
        write_res?;
        read_res?;
    }
    Ok(())
}

pub async fn process_events(
    mut rx: tokio::sync::mpsc::Receiver<EjfatEvent>,
    subcommand: Vec<String>,
    output_dir: Option<String>,
    max_concurrent_tasks: usize,
    meta_event_context: Option<MetaEventContext>,
) {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_tasks));

    while let Some(event) = rx.recv().await {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let subcommand_clone = subcommand.clone();
        let output_dir_clone = output_dir.clone();
        let context = meta_event_context.clone();
        tokio::spawn(async move {
            let tick = event.tick;
            if let Err(err) = process_event(event, subcommand_clone, output_dir_clone).await {
                eprintln!("{} ! failed to process event: {}", tick, err);
            } else if let Some(ctx) = context {
                ctx.emit(MetaEventType::Complete { tick });
            }
            drop(permit);
        });
    }
}

fn print_user_payload(payload: &[u8]) {
    print!("  ");
    for (i, &byte) in payload.iter().enumerate() {
        print!("{:02X} ", byte);
        if (i + 1) % 16 == 0 {
            print!("\n  ");
        }
    }
    println!();
}

pub fn parse_and_print_udp_payload(payload: &[u8]) {
    if payload.len() < REASSEMBLY_HEADER_SIZE + LB_HEADER_SIZE {
        println!("Payload too short to contain required headers");
        return;
    }

    let lb_payload = match LBPayload::ref_from_bytes(payload) {
        Ok(data) => data,
        Err(_) => {
            println!("invalid lb header, printing raw");
            print_user_payload(payload);
            return;
        }
    };
    let reassembly_payload = match ReassemblyPayload::ref_from_bytes(&lb_payload.body) {
        Ok(data) => data,
        Err(_) => {
            println!("invalid reassembly header, printing raw");
            print_user_payload(payload);
            return;
        }
    };

    println!("{}", lb_payload.header);
    println!("{}", reassembly_payload.header);
    println!("Body");
    print_user_payload(&reassembly_payload.body);
    println!();
}

pub async fn print_udp_payloads(address: &str, port: u16) -> Result<()> {
    let socket = UdpSocket::bind((address, port)).await?;
    println!("listening on {}:{}", address, port);

    let mut buffer = vec![0u8; 65536];
    loop {
        let (size, _) = socket.recv_from(&mut buffer).await?;
        parse_and_print_udp_payload(&buffer[..size]);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn recieve_and_execute(
    client: &mut ControlPlaneClient,
    subcommand: Vec<String>,
    output_dir: Option<String>,
    set_point: usize,
    kp: f64,
    ki: f64,
    kd: f64,
    mtu: usize,
    listener_ip: String,
    listener_port: u16,
    with_lb_headers: bool,
    max_concurrent_tasks: usize,
    meta_event_context: Option<MetaEventContext>,
) {
    let mut offset = 0;
    if with_lb_headers {
        offset = size_of::<LBHeader>();
    }
    let meta_event_context_clone = meta_event_context.clone();

    let receiver = Receiver::new(
        "udplbd-executor",
        listener_ip,
        listener_port,
        1.0,
        mtu,
        1_073_741_824,
        kp,
        ki,
        kd,
        set_point,
        0.0,
        0.0,
        offset,
        client,
        meta_event_context_clone,
    )
    .await
    .unwrap();

    process_events(
        receiver.rx,
        subcommand,
        output_dir,
        max_concurrent_tasks,
        meta_event_context,
    )
    .await;
}

/// Run a PCAP analysis by processing the given file, then print any errors and incomplete events.
/// `pcap_path` accepts any type that implements `AsRef<Path>`.
pub fn run_pcap_analysis<P: AsRef<Path>>(pcap_path: P, lb: bool) -> Result<()> {
    // Process the PCAP file and collect a report.
    let report: PcapReassemblyReport = reassemble_from_pcap(pcap_path, lb)?;
    // Print final statistics.
    println!("{}", report);

    Ok(())
}
