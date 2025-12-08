// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! Structs used to configure `start_server` and the `udplbd` command line application in general.
//! Clients commands will use this if `EJFAT_URI` is not otherwise provided.
//!
//! Typically instantiated using `serde_yaml`.
pub mod cli;

use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

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
    #[serde(default)]
    pub metrics_collector: Option<MetricsCollectorConfigFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCollectorConfigFile {
    #[serde(default = "default_metrics_collector_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_collector_interval")]
    pub interval: String,
}

fn default_metrics_collector_enabled() -> bool {
    true
}
fn default_metrics_collector_interval() -> String {
    "5s".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub instances: Vec<LoadBalancerInstanceConfig>,
    #[serde(rename = "mac_unicast")]
    pub mac_unicast: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerInstanceConfig {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
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

    /// Directory where soft-deleted rows are archived as sqlite DBs
    #[serde(default)]
    pub archive_dir: Option<PathBuf>,

    /// How often to rotate the archive DB (e.g. "1d", "1w")
    #[serde(default = "default_archive_rotation")]
    pub archive_rotation: String,

    /// Number of rotated database to keep around
    #[serde(default = "default_archive_keep")]
    pub archive_keep: u32,
}

fn default_archive_rotation() -> String {
    "1d".to_string()
}

fn default_archive_keep() -> u32 {
    7
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
            serde::de::Error::custom(format!("Invalid socket address '{addr_str}': {e}"))
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
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartNICConfig {
    pub mock: bool,
    pub host: String,
    pub auth_token: String,
    pub port: u16,
    pub tls: TlsClientOptions,

    /// Number of times to repeat clear_table/clear_tables operations (default: 1)
    #[serde(default = "default_clear_table_repeats")]
    pub clear_table_repeats: usize,

    /// Optional SmartNIC config gRPC host for automatic FPGA configuration
    #[serde(default)]
    pub cfg_host: Option<String>,
    /// Optional SmartNIC config gRPC port for automatic FPGA configuration
    #[serde(default)]
    pub cfg_port: Option<u16>,
    /// Optional SmartNIC config gRPC auth token for automatic FPGA configuration
    #[serde(default)]
    pub cfg_auth_token: Option<String>,
}

fn default_clear_table_repeats() -> usize {
    1
}

impl Config {
    pub fn turmoil() -> Self {
        Self {
            lb: LoadBalancerConfig {
                instances: vec![LoadBalancerInstanceConfig {
                    ipv4: Some("127.0.0.1".parse().unwrap()),
                    ipv6: Some("::1".parse().unwrap()),
                    event_number_port: 19524,
                }],
                mac_unicast: Some("00:00:00:00:00:01".to_string()),
            },
            database: DatabaseConfig {
                file: PathBuf::from("/tmp/udplbd-sim.db"),
                cleanup_interval: "600s".to_string(),
                cleanup_age: "168h".to_string(),
                fsync: false,
                archive_dir: None,
                archive_rotation: "168h".to_string(),
                archive_keep: 1,
            },
            controller: ControllerConfig {
                duration: "1s".to_string(),
                offset: "800ms".to_string(),
            },
            server: ServerConfig {
                listen: vec![
                    "127.0.0.1:19523".parse().unwrap(),
                    "[::1]:19523".parse().unwrap(),
                ],
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
                    ca_file: None,
                },
                clear_table_repeats: 1,
                cfg_host: None,
                cfg_port: None,
                cfg_auth_token: None,
            }],
            metrics_collector: Some(MetricsCollectorConfigFile {
                enabled: default_metrics_collector_enabled(),
                interval: default_metrics_collector_interval(),
            }),
        }
    }

    pub fn from_yaml_str(s: &str) -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file<P: AsRef<std::path::Path> + std::marker::Copy>(
        path: P,
    ) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Self::from_yaml_str(&contents),
            Err(e) => {
                let path_disp = path.as_ref().display();
                eprintln!("warning: could not open {path_disp} ({e}), using default config");
                Self::from_yaml_str(DEFAULT_CONFIG_STR)
            }
        }
    }

    /// Merge two serde_yaml::Value configs, with `b` taking precedence over `a`.
    fn merge_yaml_values(a: serde_yaml::Value, b: serde_yaml::Value) -> serde_yaml::Value {
        use serde_yaml::Value;
        match (&a, &b) {
            (Value::Mapping(_), Value::Mapping(_)) => {
                let mut a_map = match a {
                    Value::Mapping(m) => m,
                    _ => unreachable!(),
                };
                let b_map = match b {
                    Value::Mapping(m) => m,
                    _ => unreachable!(),
                };
                for (k, v_b) in b_map {
                    let v_a = a_map.remove(&k);
                    let merged = if let Some(v_a) = v_a {
                        Config::merge_yaml_values(v_a, v_b.clone())
                    } else {
                        v_b.clone()
                    };
                    a_map.insert(k, merged);
                }
                Value::Mapping(a_map)
            }
            // For sequences (lists), always replace with b
            (_, Value::Sequence(_)) => b.clone(),
            // For all other types, b takes precedence
            (_, _) => b.clone(),
        }
    }

    /// Load and merge multiple config files. The first file in the list has lowest precedence,
    /// the last file has highest precedence (overrides previous).
    pub fn from_files<P: AsRef<std::path::Path>>(paths: &[P]) -> Result<Self, ConfigError> {
        use serde_yaml::Value;
        let mut merged: Value = {
            // Start with the first config, or default config if none
            if let Some(first) = paths.first() {
                let s = std::fs::read_to_string(first)
                    .unwrap_or_else(|_| DEFAULT_CONFIG_STR.to_string());
                serde_yaml::from_str(&s).map_err(ConfigError::Parse)?
            } else {
                serde_yaml::from_str(DEFAULT_CONFIG_STR).map_err(ConfigError::Parse)?
            }
        };
        for p in &paths[1..] {
            let s = std::fs::read_to_string(p).unwrap_or_else(|_| DEFAULT_CONFIG_STR.to_string());
            let next: Value = serde_yaml::from_str(&s).map_err(ConfigError::Parse)?;
            merged = Config::merge_yaml_values(merged, next);
        }
        let config: Config = serde_yaml::from_value(merged).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate MAC addresses
        if let Some(mac_unicast) = &self.lb.mac_unicast {
            if let Err(e) = mac_unicast.parse::<MacAddr6>() {
                return Err(ConfigError::Invalid(format!("Invalid unicast MAC: {e}")));
            }
        }

        // Validate that at least one of ipv4 or ipv6 is present for each instance
        for (i, inst) in self.lb.instances.iter().enumerate() {
            if inst.ipv4.is_none() && inst.ipv6.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "LoadBalancer instance at index {i} must have at least one of ipv4 or ipv6 specified"
                )));
            }
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

        // Validate metrics_collector config if present
        if let Some(mc) = &self.metrics_collector {
            if let Err(e) = parse_duration(&mc.interval) {
                return Err(ConfigError::Invalid(format!(
                    "Invalid metrics_collector interval: {e}"
                )));
            }
        }

        // Validate TLS configurations
        if self.server.tls.enable
            && (self.server.tls.cert_file.is_none() || self.server.tls.key_file.is_none())
        {
            return Err(ConfigError::Invalid(
                "TLS enabled but cert_file or key_file missing".into(),
            ));
        }

        // Warn if SmartNIC auto-configuration is not enabled due to missing config fields
        for (i, nic) in self.smartnic.iter().enumerate() {
            if nic.cfg_host.is_none() || nic.cfg_port.is_none() || nic.cfg_auth_token.is_none() {
                eprintln!(
                    "Warning: SmartNIC at index {i} will NOT be auto-configured (cfg_host, cfg_port, or cfg_auth_token missing). Dataplane statistics will be unavailable."
                );
            }
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

    /// Convert the config file section to the runtime MetricsCollectorConfig
    pub fn get_metrics_collector_config(
        &self,
    ) -> crate::snp4::metrics_collector::MetricsCollectorConfig {
        use crate::snp4::metrics_collector::MetricsCollectorConfig;
        let (enabled, interval) = if let Some(mc) = &self.metrics_collector {
            (
                mc.enabled,
                parse_duration(&mc.interval).unwrap_or_else(|_| Duration::from_secs(30)),
            )
        } else {
            (true, Duration::from_secs(30))
        };
        MetricsCollectorConfig { enabled, interval }
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

    #[test]
    fn test_config_merging() {
        // Config 1: sets log.level to "info", smartnic list to one entry, and lb.mac_unicast
        let yaml1 = r#"
log:
  level: "info"
smartnic:
  - host: "nic1"
    port: 1
    mock: true
    auth_token: "a"
    tls:
      enable: false
      verify: false
    clear_table_repeats: 1
lb:
  mac_unicast: "00:00:00:00:00:01"
  instances:
    - event_number_port: 1000
      ipv4: "10.0.0.1"
database:
  file: "/tmp/db1"
  cleanup_interval: "10s"
  cleanup_age: "1h"
  fsync: false
  archive_rotation: "1d"
  archive_keep: 1
controller:
  duration: "1s"
  offset: "1s"
server:
  listen: ["127.0.0.1:1234"]
  auth_token: "tok1"
  tls:
    enable: false
    cert_file: null
    key_file: null
rest:
  enable: true
"#;
        // Config 2: overrides log.level, replaces smartnic list, overrides lb.mac_unicast, and adds a new instance
        let yaml2 = r#"
log:
  level: "debug"
smartnic:
  - host: "nic2"
    port: 2
    mock: false
    auth_token: "b"
    tls:
      enable: true
      verify: true
    clear_table_repeats: 2
lb:
  mac_unicast: "00:00:00:00:00:02"
  instances:
    - event_number_port: 2000
      ipv4: "10.0.0.2"
database:
  file: "/tmp/db2"
  cleanup_interval: "20s"
  cleanup_age: "2h"
  fsync: true
  archive_rotation: "2d"
  archive_keep: 2
controller:
  duration: "2s"
  offset: "2s"
rest:
  enable: false
"#;

        let v1: serde_yaml::Value = serde_yaml::from_str(yaml1).unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(yaml2).unwrap();
        let merged_value = super::Config::merge_yaml_values(v1, v2);
        let merged: super::Config = serde_yaml::from_value(merged_value).unwrap();

        // log.level should be from config2
        assert_eq!(merged.log.level, "debug");
        // smartnic list should be replaced by config2
        assert_eq!(merged.smartnic.len(), 1);
        assert_eq!(merged.smartnic[0].host, "nic2");
        // lb.mac_unicast should be from config2
        assert_eq!(merged.lb.mac_unicast.as_deref(), Some("00:00:00:00:00:02"));
        // lb.instances should be replaced by config2
        assert_eq!(merged.lb.instances.len(), 1);
        assert_eq!(merged.lb.instances[0].event_number_port, 2000);
        // database.file should be from config2
        assert_eq!(merged.database.file.to_str(), Some("/tmp/db2"));
        // rest.enable should be from config2
        assert!(!merged.rest.enable);
        // server.listen should be from config2
        assert_eq!(merged.server.listen[0].to_string(), "127.0.0.1:1234");
        // controller.duration should be from config2
        assert_eq!(merged.controller.duration, "2s");
    }
}
