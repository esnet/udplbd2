// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! CLI subcommands for configuration management, including autoconfigure.
//! Outputs only the smartnic section as YAML, with port determined from SN_INGRESS_PORT in .env.

use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_yaml;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::errors::Result;

#[derive(Parser, Debug)]
#[command(name = "config", about = "Configuration management commands")]
pub struct ConfigCli {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Autoconfigure from one or more directories containing .env files.
    Autoconfigure(AutoconfigureArgs),
}

#[derive(Args, Debug)]
pub struct AutoconfigureArgs {
    /// Paths to .env files.
    #[arg(value_name = "DIR", required = true, num_args = 1..)]
    pub dirs: Vec<PathBuf>,
}

#[derive(Serialize)]
struct OutputSmartNICConfig {
    mock: bool,
    host: String,
    auth_token: String,
    port: u16,
    tls: OutputTlsClientOptions,
    clear_table_repeats: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    cfg_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cfg_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cfg_auth_token: Option<String>,
}

#[derive(Serialize)]
struct OutputTlsClientOptions {
    enable: bool,
    verify: bool,
}

impl ConfigCli {
    pub async fn run(&self) -> Result<()> {
        match &self.command {
            ConfigCommand::Autoconfigure(args) => autoconfigure(&args.dirs).await,
        }
    }
}

/// Parse a .env file into a HashMap.
fn parse_env_file(path: &Path) -> Result<HashMap<String, String>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            // Remove possible surrounding quotes from value
            let mut value = value.trim().to_string();
            if value.starts_with('"') && value.ends_with('"') && value.len() > 1 {
                value = value[1..value.len() - 1].to_string();
            }
            map.insert(key, value);
        }
    }
    Ok(map)
}

/// Extract tokens and host from .env.
fn extract_smartnic_fields(
    env: &HashMap<String, String>,
) -> (Option<String>, Option<String>, Option<String>) {
    let cfg_token = env.get("SN_CFG_AUTH_TOKEN").cloned();
    let p4_token = env.get("SN_P4_AUTH_TOKEN").cloned();
    let host = env.get("SN_HOST").cloned();
    (cfg_token, p4_token, host)
}

/// Parse SN_INGRESS_PORT, handling ${UNIQUE:-0} or ${UNIQUE} substitution.
fn parse_ingress_port(env: &HashMap<String, String>) -> u16 {
    let port_raw = env
        .get("SN_INGRESS_PORT")
        .cloned()
        .unwrap_or_else(|| "8440".to_string());
    let unique = env
        .get("UNIQUE")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);

    // Handle patterns like 844${UNIQUE:-0} or 844${UNIQUE}
    if let Some(start) = port_raw.find("${UNIQUE") {
        let prefix = &port_raw[..start];
        let suffix = &port_raw[start..];
        // Find the closing }
        if suffix.find('}').is_some() {
            // If there's a :-default, ignore it (we already default to 0)
            let port = format!("{}{}", prefix, unique);
            if let Ok(port) = port.parse::<u16>() {
                return port;
            }
        }
    }
    // Otherwise, just try to parse as u16
    port_raw.parse::<u16>().unwrap_or(8440)
}

/// Main autoconfigure logic.
async fn autoconfigure(paths: &[PathBuf]) -> Result<()> {
    let mut smartnics = Vec::new();

    for env_path in paths {
        let env = parse_env_file(env_path)?;

        let (cfg_token, p4_token, host) = extract_smartnic_fields(&env);

        // Determine port from SN_INGRESS_PORT and UNIQUE
        let port = parse_ingress_port(&env);

        if let (Some(host), Some(p4_token)) = (host, p4_token) {
            let mut nic = OutputSmartNICConfig {
                mock: false,
                host,
                auth_token: p4_token,
                port,
                tls: OutputTlsClientOptions {
                    enable: false,
                    verify: false,
                },
                clear_table_repeats: 1,
                cfg_host: None,
                cfg_port: None,
                cfg_auth_token: None,
            };
            // If we have SN_CFG_AUTH_TOKEN, set cfg_auth_token
            if let Some(cfg_token) = cfg_token {
                nic.cfg_auth_token = Some(cfg_token);
            }
            smartnics.push(nic);
        }
    }

    // Output as YAML, only the smartnic section
    let mut map = serde_yaml::Mapping::new();
    map.insert(
        serde_yaml::Value::String("smartnic".to_string()),
        serde_yaml::to_value(&smartnics)?,
    );
    let yaml = serde_yaml::to_string(&map)?;
    println!("{}", yaml);

    Ok(())
}
