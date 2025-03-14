//! gRPC API that provides ReserveLoadBalancer, Register, SendState, etc.
//! This API is the primary interface to udplbd in typical circumstances.
pub mod cli;
pub mod client;
mod types;

#[cfg(test)]
mod tests;

pub mod handlers {
    include!("api/handlers/mod.rs");
}

pub mod service {
    use crate::reservation::ReservationManager;

    impl LoadBalancerService {
        pub async fn get_mac_addr(
            &self,
            ip: std::net::IpAddr,
        ) -> crate::errors::Result<macaddr::MacAddr6> {
            crate::macaddr::get_mac_addr(ip).await
        }
    }

    include!("api/service.rs");
}

pub mod turmoil {
    pub mod handlers {
        include!("api/handlers/mod.rs");
    }

    pub mod service {
        use crate::reservation::turmoil::ReservationManager;

        impl LoadBalancerService {
            pub async fn get_mac_addr(
                &self,
                _ip: std::net::IpAddr,
            ) -> crate::errors::Result<macaddr::MacAddr6> {
                Ok(macaddr::MacAddr6::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB))
            }
        }

        include!("api/service.rs");
    }

    use service::LoadBalancerService;
    include!("api/api.rs");
}

use service::LoadBalancerService;
include!("api/api.rs");
