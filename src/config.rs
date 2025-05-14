// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Structs used to configure `start_server` and the `udplbd` command line application in general.
//! Clients commands will use this if `EJFAT_URI` is not otherwise provided.
//!
//! Typically instantiated using `serde_yaml`.
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;

const DEFAULT_CONFIG_STR: &str = include_str!("../etc/example-config.yml");

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileRead(#[from] std::io::Error),
    #[error("Failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub lb: LoadBalancerConfig,
    pub database: DatabaseConfig,
    pub controller: ControllerConfig,
    pub server: ServerConfig,
    pub rest: RestServerConfig,
    pub log: LogConfig,
    pub smartnic: Vec<SmartNICConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub instances: Vec<LoadBalancerInstanceConfig>,
    #[serde(rename = "mac_unicast")]
    pub mac_unicast: String,
    #[serde(rename = "mac_broadcast")]
    pub mac_broadcast: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerInstanceConfig {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    #[serde(rename = "event_number_port")]
    pub event_number_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub file: PathBuf,

    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval: String,

    #[serde(default = "default_cleanup_age")]
    pub cleanup_age: String,

    #[serde(default)]
    pub fsync: bool,
}

fn default_cleanup_interval() -> String {
    "60s".to_string()
}

fn default_cleanup_age() -> String {
    "4h".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerConfig {
    #[serde(default = "default_tick_duration")]
    pub duration: String,
    #[serde(default = "default_tick_offset")]
    pub offset: String,
}

fn default_tick_duration() -> String {
    "1s".to_string()
}

fn default_tick_offset() -> String {
    "800ms".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(deserialize_with = "deserialize_socket_addrs")]
    pub listen: Vec<SocketAddr>,
    pub auth_token: String,
    pub tls: TlsConfig,
}

// Custom deserializer for SocketAddr vector
fn deserialize_socket_addrs<'de, D>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strs: Vec<String> = Vec::deserialize(deserializer)?;
    let mut addrs = Vec::with_capacity(strs.len());

    for addr_str in strs {
        let addr = addr_str.parse().map_err(|e| {
            serde::de::Error::custom(format!("Invalid socket address '{}': {}", addr_str, e))
        })?;
        addrs.push(addr);
    }

    Ok(addrs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enable: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestServerConfig {
    #[serde(default = "default_rest_enabled")]
    pub enable: bool,
}

fn default_rest_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientOptions {
    pub enable: bool,
    pub verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartNICConfig {
    pub mock: bool,
    pub host: String,
    pub auth_token: String,
    pub port: u16,
    pub tls: TlsClientOptions,
}

impl Config {
    pub fn turmoil() -> Self {
        Self {
            lb: LoadBalancerConfig {
                instances: vec![LoadBalancerInstanceConfig {
                    ipv4: "0.0.0.0".parse().unwrap(),
                    ipv6: "::1".parse().unwrap(),
                    event_number_port: 19524,
                }],
                mac_unicast: "00:00:00:00:00:01".to_string(),
                mac_broadcast: "ff:ff:ff:ff:ff:ff".to_string(),
            },
            database: DatabaseConfig {
                file: PathBuf::from("/tmp/udplbd-sim.db"),
                cleanup_interval: "60s".to_string(),
                cleanup_age: "4h".to_string(),
                fsync: false,
            },
            controller: ControllerConfig {
                duration: "1s".to_string(),
                offset: "0s".to_string(),
            },
            server: ServerConfig {
                listen: vec!["0.0.0.0:19523".parse().unwrap()],
                auth_token: "test".to_string(),
                tls: TlsConfig {
                    enable: false,
                    cert_file: None,
                    key_file: None,
                },
            },
            rest: RestServerConfig { enable: true },
            log: LogConfig {
                level: "debug".to_string(),
            },
            smartnic: vec![SmartNICConfig {
                mock: true,
                host: "dataplane".to_string(),
                port: 50051,
                auth_token: "".to_string(),
                tls: TlsClientOptions {
                    enable: false,
                    verify: false,
                },
            }],
        }
    }

    pub fn from_yaml_str(s: &str) -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Self::from_yaml_str(&contents),
            Err(e) => {
                warn!("could not open config ({e}), using default config");
                Self::from_yaml_str(DEFAULT_CONFIG_STR)
            }
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate MAC addresses
        if let Err(e) = self.lb.mac_unicast.parse::<MacAddr6>() {
            return Err(ConfigError::Invalid(format!("Invalid unicast MAC: {e}")));
        }
        if let Err(e) = self.lb.mac_broadcast.parse::<MacAddr6>() {
            return Err(ConfigError::Invalid(format!("Invalid broadcast MAC: {e}")));
        }

        // Validate durations
        if let Err(e) = parse_duration(&self.controller.duration) {
            return Err(ConfigError::Invalid(format!(
                "Invalid controller duration: {e}"
            )));
        }
        if let Err(e) = parse_duration(&self.controller.offset) {
            return Err(ConfigError::Invalid(format!(
                "Invalid controller offset: {e}"
            )));
        }
        if let Err(e) = parse_duration(&self.database.cleanup_interval) {
            return Err(ConfigError::Invalid(format!(
                "Invalid cleanup interval: {e}"
            )));
        }
        if let Err(e) = parse_duration(&self.database.cleanup_age) {
            return Err(ConfigError::Invalid(format!("Invalid cleanup age: {e}")));
        }

        // Validate TLS configurations
        if self.server.tls.enable
            && (self.server.tls.cert_file.is_none() || self.server.tls.key_file.is_none())
        {
            return Err(ConfigError::Invalid(
                "TLS enabled but cert_file or key_file missing".into(),
            ));
        }

        Ok(())
    }

    pub fn get_controller_duration(&self) -> Result<Duration, ConfigError> {
        parse_duration(&self.controller.duration)
            .map_err(|e| ConfigError::Invalid(format!("Failed to parse controller duration: {e}")))
    }

    pub fn get_controller_offset(&self) -> Result<Duration, ConfigError> {
        parse_duration(&self.controller.offset)
            .map_err(|e| ConfigError::Invalid(format!("Failed to parse controller offset: {e}")))
    }
}

pub fn parse_duration(duration_str: &str) -> Result<Duration, ConfigError> {
    let mut s = duration_str.to_string();
    if s.ends_with("ms") {
        s.truncate(s.len() - 2);
        Ok(Duration::from_millis(s.parse::<u64>().map_err(|e| {
            ConfigError::Invalid(format!("Invalid milliseconds value: {e}"))
        })?))
    } else if s.ends_with('s') {
        s.truncate(s.len() - 1);
        Ok(Duration::from_secs(s.parse::<u64>().map_err(|e| {
            ConfigError::Invalid(format!("Invalid seconds value: {e}"))
        })?))
    } else if s.ends_with('h') {
        s.truncate(s.len() - 1);
        Ok(Duration::from_secs(
            s.parse::<u64>()
                .map_err(|e| ConfigError::Invalid(format!("Invalid hours value: {e}")))?
                * 3600,
        ))
    } else if s.ends_with('d') {
        s.truncate(s.len() - 1);
        Ok(Duration::from_secs(
            s.parse::<u64>()
                .map_err(|e| ConfigError::Invalid(format!("Invalid days value: {e}")))?
                * 86400,
        ))
    } else {
        Err(ConfigError::Invalid(format!(
            "invalid suffix in duration: {duration_str}"
        )))
    }
}

#[cfg(test)]
mod test {
    use super::Config;

    #[test]
    fn test_default_config() {
        let res = Config::from_file("/nonexistent_file_path");

        match res {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{e}");
                panic!("could not parse default config")
            }
        };
    }
}
