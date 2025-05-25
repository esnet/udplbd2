// SPDX-License-Identifier: BSD-3-Clause-LBNL
pub mod receiver {
    use turmoil::net::*;
    include!("./receiver.rs");

    impl Receiver {
        #[allow(clippy::too_many_arguments)]
        pub async fn turmoil(
            name: &str,
            ip_address: String,
            port: u16,
            weight: f32,
            mtu: usize,
            max_buffer_size: usize,
            kp: f64,
            ki: f64,
            kd: f64,
            sp: usize,
            min_factor: f32,
            max_factor: f32,
            offset: usize,
            client: &mut ControlPlaneClient,
            meta_event_context: Option<MetaEventContext>,
        ) -> Result<Self, Error> {
            let (tx, rx) = mpsc::channel(1024);
            let pid_loop_tx = tx.clone();
            let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
            let keep_lb_header = offset > 0;

            let reg = client
                .register(
                    name.into(),
                    weight,
                    ip_address.clone(),
                    port,
                    PortRange::PortRange1,
                    min_factor,
                    max_factor,
                    keep_lb_header,
                )
                .await?
                .into_inner();

            let stats = Arc::new(RwLock::new(ReassemblyStats::default()));
            let stats_clone = stats.clone();

            // Create the reassembler and wrap in Arc<Mutex<>>
            let reassembler = Arc::new(Mutex::new(Reassembler::new(
                max_buffer_size,
                mtu,
                meta_event_context.clone(),
            )));
            let reassembler_clone = reassembler.clone();

            let listen_task_handle = tokio::spawn(async move {
                listen_and_reassemble_with_offset(
                    socket,
                    tx,
                    offset,
                    reassembler_clone,
                    stats_clone,
                )
                .await;
            });

            let mut receiver = Self {
                client: client.clone(),
                creation_time: Instant::now(),
                first_packet_start: None,
                rx,
                reassembler,
                listen_task: Some(listen_task_handle),
                pid_task: None,
            };

            let mut client2 = receiver.client.clone();
            client2.session_id = Some(reg.session_id.clone());
            let meta_event_ctx_clone2 = meta_event_context.clone();
            let pid_stats = stats.clone();

            let pid_task_handle = tokio::spawn(async move {
                pid_loop(
                    &mut client2,
                    &pid_loop_tx,
                    sp,
                    kp,
                    ki,
                    kd,
                    meta_event_ctx_clone2,
                    pid_stats,
                )
                .await
            });
            receiver.pid_task = Some(pid_task_handle);

            Ok(receiver)
        }
    }
}

pub mod sender {
    use turmoil::net::*;
    include!("./sender.rs");
}

pub mod mock {
    use turmoil::net::*;
    include!("./mock.rs");
}

pub mod tester {
    use crate::api::client::ControlPlaneClient;
    use crate::config::Config;
    use crate::dataplane::meta_events::{MetaEventManager, MetaEventType};
    use crate::dataplane::tester::{ReceiverConfig, SenderConfig};
    use crate::dataplane::turmoil::mock::MockDataplane;
    use crate::dataplane::turmoil::receiver::Receiver;
    use crate::dataplane::turmoil::sender::Sender;
    use crate::db::LoadBalancerDB;
    use crate::errors::{Error, Result};
    use crate::reservation::turmoil::ReservationManager;
    use crate::snp4::client::{MultiSNP4Client, SNP4Client};
    use serde::{Deserialize, Serialize};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::sleep;
    use tonic::transport::Server;
    use tracing::debug;
    use turmoil::lookup;
    use turmoil::{net::TcpListener, Builder};

    // ─────────────────────────────────────────────────────────────────────────────
    // Configuration types for multiple timelines.
    //
    // The simulation configuration now contains a list of timelines. Each timeline
    // contains a list of events (with a time in milliseconds relative to the timeline’s start)
    // and an end condition.
    //
    // In addition to a Tick end condition, we now support two types of host-ready checks:
    // TCPHostReady and UDPHostReady.
    // ─────────────────────────────────────────────────────────────────────────────
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TurmoilConfig {
        pub timelines: Vec<TimelineConfig>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TimelineConfig {
        /// A numeric id (and order) for this timeline.
        pub id: usize,
        /// A list of simulation events scheduled (in milliseconds) relative to the timeline’s start.
        pub events: Vec<SimulationEvent>,
        /// The end condition for this timeline. When the condition is met, the simulation
        /// will move to the next timeline.
        pub end_condition: TimelineEndCondition,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum TimelineEndCondition {
        /// End this timeline when the relative simulation time reaches or exceeds the given tick count.
        Tick { tick: u64 },
        /// End this timeline when a TCP connection can be established to the given host/port.
        TCPHostReady { host: String, port: u16 },
        /// End this timeline when a UDP packet can be sent to the given host/port.
        UDPHostReady { host: String, port: u16 },
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SimulationEvent {
        /// Time (in milliseconds) relative to the timeline’s start when this event should fire.
        pub time: u64,
        pub event: TimelineEvent,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum TimelineEvent {
        /// Spawn the dataplane host.
        SpawnDataplane,
        /// Spawn the server host.
        /// (Note: The `db_path` field in this event is ignored in favor of the `db_path` argument to `run_turmoil_test`.)
        SpawnServer,
        /// Partition the network between hosts `a` and `b`.
        LinkFailure { a: String, b: String },
        /// Repair the network between hosts `a` and `b`.
        LinkRecovery { a: String, b: String },
        /// Reserve (or “allocate”) a load balancer with the given name.
        ReserveLoadBalancer {
            name: String,
            addresses: Vec<String>,
        },
        /// Spawn a sender with the given configuration and load balancer reference.
        SpawnSender { config: SenderConfig, lb: String },
        /// Register a receiver with the given configuration and load balancer reference.
        RegisterReceiver { config: ReceiverConfig, lb: String },
        /// Free (or “deregister”) the given receiver.
        FreeReceiver { receiver: String },
        /// End the simulation.
        SimulationExit,
    }

    /// Load the simulation configuration from a JSON/YAML file.
    pub fn load_config_from_json(file_path: &str) -> Result<TurmoilConfig> {
        debug!("loading config from '{}'", file_path);
        let mut file = std::fs::File::open(file_path)?;
        let mut data = String::new();
        std::io::Read::read_to_string(&mut file, &mut data)?;
        let config: TurmoilConfig = serde_yaml::from_str(&data)?;
        debug!("config loaded");
        Ok(config)
    }

    /// Run the simulation. All simulation actions are defined as timeline events.
    ///
    /// The function remains synchronous (using a simulation “step” loop) so that it can
    /// manage its own Tokio runtime. The `db_path` argument is used to bootstrap the server.
    pub fn run_turmoil_test(
        meta_event_manager: &MetaEventManager,
        db_path: Option<String>,
        config: TurmoilConfig,
    ) -> Result<()> {
        debug!("starting simulation...");
        let mut sim = Builder::new().build();

        // Capture the db_path argument for use in the SpawnServer event.
        let global_db_path = db_path.clone();

        // Sort timelines by id to enforce sequential execution.
        let mut timelines = config.timelines;
        timelines.sort_by_key(|t| t.id);

        'timeline_overall: for timeline in timelines {
            debug!("starting timeline {}", timeline.id);
            let mut events = timeline.events;
            events.sort_by_key(|e| e.time);
            let mut event_iter = events.into_iter().peekable();
            let mut timeline_start_tick: Option<u64> = None;

            // If this timeline’s end condition is a host-ready check, spawn a helper task
            // that will update a shared flag when the host becomes reachable.
            let readiness_flag = match timeline.end_condition {
                TimelineEndCondition::TCPHostReady { ref host, port } => {
                    let flag = Arc::new(AtomicBool::new(false));
                    let flag_clone = flag.clone();
                    let check_ready_host = format!("check_ready_tcp_{}", timeline.id);
                    let host = host.clone();
                    sim.host(check_ready_host, move || {
                        let host = host.clone();
                        let flag_clone = flag_clone.clone();
                        async move {
                            let addr = (lookup(host), port);
                            while turmoil::net::TcpStream::connect(addr).await.is_err() {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            flag_clone.store(true, Ordering::Relaxed);
                            Ok(())
                        }
                    });
                    Some(flag)
                }
                TimelineEndCondition::UDPHostReady { ref host, port } => {
                    let flag = Arc::new(AtomicBool::new(false));
                    let flag_clone = flag.clone();
                    let check_ready_host = format!("check_ready_udp_{}", timeline.id);
                    let host = host.clone();
                    sim.host(check_ready_host, move || {
                        let host = host.clone();
                        let flag_clone = flag_clone.clone();
                        async move {
                            let addr = (lookup(host), port);
                            loop {
                                // Create an ephemeral UDP socket.
                                match turmoil::net::UdpSocket::bind(("0.0.0.0", 0)).await {
                                    Ok(sock) => {
                                        // Try sending a small datagram ("ping").
                                        match sock.send_to(b"ping", addr).await {
                                            Ok(n) if n > 0 => {
                                                flag_clone.store(true, Ordering::Relaxed);
                                                break;
                                            }
                                            _ => {
                                                tokio::time::sleep(Duration::from_millis(10)).await;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                    }
                                }
                            }
                            Ok(())
                        }
                    });
                    Some(flag)
                }
                _ => None,
            };

            'timeline: while sim.step().map_err(|e| Error::TestFailure(e.to_string()))? {
                let sim_elapsed = sim.elapsed().as_millis() as u64;
                if timeline_start_tick.is_none() {
                    timeline_start_tick = Some(sim_elapsed);
                    debug!(
                        "timeline {} started at simulation tick {}",
                        timeline.id, sim_elapsed
                    );
                }
                let relative_time = sim_elapsed - timeline_start_tick.unwrap();

                // Process all timeline events scheduled for (or before) the current relative time.
                while let Some(event) = event_iter.peek() {
                    if event.time > relative_time {
                        break;
                    }
                    let event = event_iter.next().unwrap();
                    match event.event {
                        TimelineEvent::SpawnDataplane => {
                            debug!(
                                "timeline {} at {} ms: spawning dataplane",
                                timeline.id, relative_time
                            );
                            sim.host("dataplane", || async move {
                                let port = 50051;
                                let addr = (IpAddr::from(Ipv4Addr::UNSPECIFIED), port);
                                debug!("dataplane: binding TcpListener to {:?}", addr);
                                let listener = TcpListener::bind(addr).await?;
                                debug!("dataplane: TcpListener bound");
                                let sim_dataplane = MockDataplane::new();
                                let sim_service = crate::proto::smartnic::p4_v2::smartnic_p4_server::SmartnicP4Server::new(sim_dataplane);
                                let incoming = async_stream::stream! {
                                    loop {
                                        match listener.accept().await {
                                            Ok((stream, _)) => yield Ok(super::incoming::Accepted(stream)),
                                            Err(e) => yield Err(e),
                                        }
                                    }
                                };
                                Server::builder()
                                    .add_service(sim_service)
                                    .serve_with_incoming(incoming)
                                    .await
                                    .map_err(|e| Error::TestFailure(e.to_string()))?;
                                Ok(())
                            });
                        }
                        TimelineEvent::SpawnServer => {
                            debug!(
                                "timeline {} at {} ms: spawning server",
                                timeline.id, relative_time
                            );
                            let db_path = global_db_path.clone();
                            sim.host("server", move || {
                                let db_path = db_path.clone();
                                async move {
                                    debug!("server: opening database");
                                    let (db, _temp_dir_guard) = if let Some(ref path) = db_path {
                                        (Arc::new(LoadBalancerDB::new(path).await?), None)
                                    } else {
                                        let temp_dir = tempfile::tempdir()
                                            .map_err(|e| Error::TestFailure(e.to_string()))?;
                                        let temp_db_path = temp_dir.path().join("udplbd-sim.db");
                                        let db = Arc::new(LoadBalancerDB::new(
                                            temp_db_path.to_str().unwrap(),
                                        ).await?);
                                        (db, Some(temp_dir))
                                    };

                                    debug!("server: syncing database");
                                    let conf = Config::turmoil();
                                    db.sync_config(&conf).await?;

                                    debug!("server: initializing ReservationManager");
                                    let sim_client = SNP4Client::turmoil().await?;
                                    let mut manager = ReservationManager::new(
                                        db.clone(),
                                        MultiSNP4Client::new(vec![sim_client]),
                                        conf.get_controller_duration().unwrap(),
                                        conf.get_controller_offset().unwrap(),
                                        "00:00:00:00:00:01".parse().unwrap(),
                                        (IpAddr::from(Ipv4Addr::UNSPECIFIED), 0).into(),
                                    );
                                    manager.initialize().await?;
                                    let manager_arc = Arc::new(Mutex::new(manager));

                                    let addr = (IpAddr::from(Ipv4Addr::UNSPECIFIED), 19523);
                                    debug!("server: binding TcpListener to {:?}", addr);
                                    let listener = TcpListener::bind(addr).await?;
                                    let incoming = async_stream::stream! {
                                        loop {
                                            match listener.accept().await {
                                                Ok((stream, _)) => yield Ok(super::incoming::Accepted(stream)),
                                                Err(e) => yield Err(e),
                                            }
                                        }
                                    };

                                    let lb_service = crate::api::turmoil::service::LoadBalancerService::new(
                                        db.clone(),
                                        manager_arc.clone(),
                                        addr.into(),
                                    );
                                    let svc = crate::proto::loadbalancer::v1::load_balancer_server::LoadBalancerServer::new(lb_service);
                                    Server::builder()
                                        .add_service(svc)
                                        .serve_with_incoming(incoming)
                                        .await
                                        .map_err(|e| Error::TestFailure(e.to_string()))?;
                                    Ok(())
                                }
                            });
                        }
                        TimelineEvent::LinkFailure { a, b } => {
                            debug!(
                                "timeline {} at {} ms: link failure between {} and {}",
                                timeline.id, relative_time, a, b
                            );
                            sim.partition(a, b);
                        }
                        TimelineEvent::LinkRecovery { a, b } => {
                            debug!(
                                "timeline {} at {} ms: link recovery between {} and {}",
                                timeline.id, relative_time, a, b
                            );
                            sim.repair(a, b);
                        }
                        TimelineEvent::ReserveLoadBalancer { name, addresses } => {
                            debug!(
                                "timeline {} at {} ms: reserving load balancer '{}' with addresses {:?}",
                                timeline.id, relative_time, name, addresses
                            );
                            sim.host("reserve_load_balancer", move || {
                                let name = name.clone();
                                let addresses = addresses.clone();
                                async move {
                                    let mut client = ControlPlaneClient::turmoil().await?;
                                    client.reserve_load_balancer(name, None, addresses).await?;
                                    Ok(())
                                }
                            });
                        }
                        TimelineEvent::SpawnSender { config, lb } => {
                            debug!(
                                "timeline {} at {} ms: spawning sender using load balancer '{}'",
                                timeline.id, relative_time, lb
                            );
                            sim.host("sender", move || {
                                let meta_event_context =
                                    meta_event_manager.create_context("sender".to_string());
                                async move {
                                    let dataplane_addr =
                                        SocketAddr::new(lookup("dataplane"), 19522);
                                    let sync_addr = SocketAddr::new(lookup("server"), 19524);
                                    let mut sender_instance = Sender::new(
                                        dataplane_addr,
                                        sync_addr,
                                        1500,
                                        meta_event_context,
                                    )
                                    .await?;
                                    let sender_rate_micros = 1_000_000 / config.rate;
                                    for i in 0..config.event_count {
                                        let data = (i as u64).to_ne_bytes();
                                        sender_instance.send_ts(&data, 0).await;
                                        sleep(Duration::from_micros(sender_rate_micros)).await;
                                    }
                                    Ok(())
                                }
                            });
                        }
                        TimelineEvent::RegisterReceiver { config, lb } => {
                            debug!(
                                "timeline {} at {} ms: registering receiver '{}' using load balancer '{}'",
                                timeline.id, relative_time, config.name, lb
                            );
                            let meta_event_context =
                                meta_event_manager.create_context(config.name.clone());
                            sim.host(config.name.clone(), move || {
                                let meta_event_ctx_clone = meta_event_context.clone();
                                let meta_event_ctx_clone2 = meta_event_context.clone();
                                let name = config.name.clone();
                                async move {
                                    let name2 = name.clone();
                                    let dataplane_addr = lookup(name).to_string();
                                    let mut client = ControlPlaneClient::turmoil()
                                        .await
                                        .expect("failed to create control plane client");
                                    let mut receiver = Receiver::turmoil(
                                        &name2,
                                        dataplane_addr,
                                        1234,
                                        1.0,
                                        1500,
                                        1024 * 1024,
                                        config.kp,
                                        config.ki,
                                        config.kd,
                                        config.sp,
                                        config.min_factor,
                                        config.max_factor,
                                        0,
                                        &mut client,
                                        meta_event_ctx_clone,
                                    )
                                    .await
                                    .expect("failed to initialize receiver");

                                    let receiver_rate_micros = 1_000_000 / config.rate;
                                    while let Some(event) = receiver.rx.recv().await {
                                        sleep(Duration::from_micros(receiver_rate_micros)).await;
                                        debug!("'{}' processed event {}", name2, event.tick);
                                        if let Some(ref ctx) = meta_event_ctx_clone2 {
                                            ctx.emit(MetaEventType::Complete { tick: event.tick });
                                        }
                                    }
                                    Ok(())
                                }
                            });
                        }
                        TimelineEvent::FreeReceiver { receiver } => {
                            debug!(
                                "timeline {} at {} ms: freeing receiver '{}'",
                                timeline.id, relative_time, receiver
                            );
                            sim.host("free_receiver", move || async move {
                                let mut client = ControlPlaneClient::turmoil()
                                    .await
                                    .expect("failed to create control plane client");
                                client.deregister().await.expect("failed to free receiver");
                                Ok(())
                            });
                        }
                        TimelineEvent::SimulationExit => {
                            debug!(
                                "timeline {} at {} ms: SimulationExit received",
                                timeline.id, relative_time
                            );
                            break 'timeline_overall;
                        }
                    }
                }

                // Check if the timeline’s end condition has been met.
                let timeline_done = match timeline.end_condition {
                    TimelineEndCondition::Tick { tick } => relative_time >= tick,
                    TimelineEndCondition::TCPHostReady { .. }
                    | TimelineEndCondition::UDPHostReady { .. } => readiness_flag
                        .as_ref()
                        .map(|flag| flag.load(Ordering::Relaxed))
                        .unwrap_or(false),
                };

                if timeline_done {
                    debug!(
                        "timeline {} end condition met at relative time {} ms",
                        timeline.id, relative_time
                    );
                    break 'timeline;
                }
            }
            debug!("timeline {} completed", timeline.id);
        }

        debug!("all timelines completed");
        Ok(())
    }
}

pub mod incoming {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tonic::transport::server::{Connected, TcpConnectInfo};
    use turmoil::net::TcpStream;

    pub struct Accepted(pub TcpStream);

    impl Connected for Accepted {
        type ConnectInfo = TcpConnectInfo;

        fn connect_info(&self) -> Self::ConnectInfo {
            Self::ConnectInfo {
                local_addr: self.0.local_addr().ok(),
                remote_addr: self.0.peer_addr().ok(),
            }
        }
    }

    impl AsyncRead for Accepted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Accepted {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

pub mod connector {
    use hyper::Uri;
    use hyper_util::rt::TokioIo;
    use std::{future::Future, pin::Pin};
    use tower::Service;
    use tracing::trace;
    use turmoil::net::TcpStream;

    type Fut = Pin<Box<dyn Future<Output = Result<TokioIo<TcpStream>, std::io::Error>> + Send>>;

    pub fn connector(
    ) -> impl Service<Uri, Response = TokioIo<TcpStream>, Error = std::io::Error, Future = Fut> + Clone
    {
        tower::service_fn(|uri: Uri| {
            trace!("connector attempting connection to {:?}", uri);
            Box::pin(async move {
                let conn = TcpStream::connect(uri.authority().unwrap().as_str()).await?;
                trace!("connector established connection");
                Ok::<_, std::io::Error>(TokioIo::new(conn))
            }) as Fut
        })
    }
}

#[cfg(test)]
pub mod test {
    use super::tester::{run_turmoil_test, TurmoilConfig};
    use crate::dataplane::meta_events::MetaEventManager;

    #[test]
    fn test_minimal_scenario() {
        let test_config = include_str!("../../test/sim/minimal.yaml");
        let (meta_event_manager, _) = MetaEventManager::new(false);
        let config: TurmoilConfig = serde_yaml::from_str(test_config).unwrap();
        let result = run_turmoil_test(&meta_event_manager, None, config);
        assert!(result.is_ok());
    }
}
