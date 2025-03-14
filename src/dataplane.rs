//! EJFAT sender, receiver, and a software implementation for the dataplane. Also includes turmoil implementations
//! for simulated network testing.
pub mod cli;
pub mod doctor;
pub mod meta_events;
pub mod pcap;
pub mod protocol;
pub mod tester;

pub mod receiver {
    use tokio::net::UdpSocket;
    include!("./dataplane/receiver.rs");
}

pub mod sender {
    use tokio::net::UdpSocket;
    include!("./dataplane/sender.rs");
}

pub mod mock {
    use tokio::net::UdpSocket;
    include!("./dataplane/mock.rs");
}

pub mod turmoil;
