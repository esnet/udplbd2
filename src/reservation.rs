//! Connects the `db` module with the `snp4` module to generate rules according to the database state.
//! Also contains the event id sync server.
//!
//! In active reservations, the rules are applied at a configurable interval. Only diffs are applied.
//! In static mode, the rules are generarted once and applied immediately.
pub mod event_id_sync {
    use tokio::net::UdpSocket;
    include!("reservation/event_id_sync.rs");
}

pub mod active_reservation {
    use super::event_id_sync::EventIdSyncServer;
    include!("reservation/active_reservation.rs");
}

pub mod static_reservation {
    use super::active_reservation::ActiveReservation;
    include!("reservation/static_reservation.rs");
}

pub mod turmoil {
    pub mod event_id_sync {
        use turmoil::net::UdpSocket;
        include!("reservation/event_id_sync.rs");
    }

    pub mod active_reservation {
        use super::event_id_sync::EventIdSyncServer;
        include!("reservation/active_reservation.rs");
    }

    pub mod static_reservation {
        use super::active_reservation::ActiveReservation;
        include!("reservation/static_reservation.rs");
    }

    use self::active_reservation::ActiveReservation;
    include!("reservation/reservation.rs");
}

use self::active_reservation::ActiveReservation;
include!("reservation/reservation.rs");
