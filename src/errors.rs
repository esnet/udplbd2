// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Common `Error` and `Result` types used throughout the library and application. Serves as a reference for all that can go wrong.
use crate::config::ConfigError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("db error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("client error: {0}")]
    ClientError(#[from] tonic::Status),

    #[error("config file error: {0}")]
    ConfigFileError(#[from] ConfigError),

    #[error("gRPC transport error: {0}")]
    TonicTransportError(#[from] tonic::transport::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("command error: {0}")]
    CommandExecution(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid socket address: {0}")]
    InvalidSocketAddress(#[from] std::net::AddrParseError),

    #[error("invalid network: {0}")]
    InvalidNetwork(#[from] ipnetwork::IpNetworkError),

    #[error("invalid MAC address: {0}")]
    InvalidMacAddress(#[from] macaddr::ParseError),

    #[error("MAC address not found: {0}")]
    MacAddressNotFound(String),

    #[error("token error: {0}")]
    Token(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("{0} not found")]
    NotFound(String),

    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("usage error: {0}")]
    Usage(String),

    #[error("could not apply changes: {0}")]
    NotInitialized(String),

    #[error("{0} already exists")]
    AlreadyExists(String),

    #[error("failed to apply migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("JSON parse error: {0}")]
    YamlParseError(#[from] serde_json::Error),

    #[error("malformed URL: {0}")]
    URLParseError(#[from] url::ParseError),

    #[error("invalid timestamp: {0}")]
    ProstTimestampError(#[from] prost_wkt_types::TimestampError),

    #[error("duration out of range: {0}")]
    DurationOutOfRange(#[from] chrono::OutOfRangeError),

    #[error("event reassembly error: {0}")]
    ReassemblyError(#[from] crate::dataplane::receiver::ReassemblyError),

    #[error("mock event reassembly error: {0}")]
    MockReassemblyError(#[from] crate::dataplane::turmoil::receiver::ReassemblyError),

    #[error("failed: {0}")]
    TestFailure(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("{0}")]
    Runtime(String),
}

pub type Result<T> = std::result::Result<T, Error>;
