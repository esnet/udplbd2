//! tonic-generated modules for the gRPC protobuf definitions used
pub mod smartnic {
    pub mod p4_v2 {
        include!("smartnic/sn_p4.v2.rs");
    }
    pub mod cfg_v1 {
        include!("smartnic/sn_p4.v2.rs");
    }
}

pub mod loadbalancer {
    pub mod v1 {
        include!("loadbalancer/loadbalancer.rs");
    }
}
