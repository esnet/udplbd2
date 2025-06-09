// SPDX-License-Identifier: BSD-3-Clause-LBNL
//! udplbd entry point.
//!
//! Provides a command-line interface for managing the udplbd service,
//! handling configuration loading, and initializing the logging subsystem.
//!
//! The daemon supports configuration via both file and environment variables,
//! with environment variables taking precedence over file configuration.
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use udplbd::{
    apply_static_config, config::Config, errors::Result, start_mocked_server, start_server,
};

/// udplbd - the control plane for EJFAT load balancers.
///
/// Provides subcommands for different operational modes and configuration options.
/// Currently supports starting the daemon with a specified configuration file.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        value_name = "FILE",
        env = "UDPLBD_CONFIG",
        default_value = "/etc/udplbd/config.yml"
    )]
    config: PathBuf,

    /// Log level.
    #[arg(long, value_name = "LEVEL", default_value = "")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the gRPC server for dynamic load balancers
    Start,

    /// Apply a static load balancer configuration from a YAML file
    Static {
        /// Apply the rules to smartnic-p4 instead of printing them
        #[arg(long)]
        apply: bool,

        /// Path to the JSON configuration file
        #[arg(value_name = "FILE")]
        reservation_file: PathBuf,
    },

    /// Start the gRPC server with a software dataplane (for testing only)
    Mock {
        /// Path to the database file (optional)
        #[arg(short, long, value_name = "FILE")]
        db: Option<PathBuf>,
    },

    /// gRPC API commands.
    Client(udplbd::api::cli::ApiCli),

    /// Dataplane testing commands.
    Dataplane(udplbd::dataplane::cli::DataplaneCli),
}

/// Application entry point.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::from_file(&cli.config)?;
    let log_level = if cli.log_level.is_empty() {
        config.log.level.clone()
    } else {
        cli.log_level.clone()
    };
    setup_logging(&log_level)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    cli_main(cli, config).await
}

pub async fn cli_main(cli: Cli, config: Config) -> Result<()> {
    match cli.command {
        Commands::Start => start_server(config).await?,
        Commands::Static {
            apply,
            reservation_file,
        } => {
            apply_static_config(&config, reservation_file, apply).await?;
        }
        Commands::Mock { db } => {
            start_mocked_server(config, db).await?;
        }
        Commands::Client(api_cli) => {
            api_cli.run(&config).await?;
        }
        Commands::Dataplane(dp_cli) => {
            dp_cli.run(&config).await?;
        }
    }
    Ok(())
}

/// Configures the logging subsystem based on the specified log level. Filters out noisy modules.
///
/// # Arguments
/// * `level` - String representation of the desired log level
fn setup_logging(level: &str) -> Result<()> {
    let lower_level = level.to_ascii_lowercase(); // ding ding, elevator opens
    let (udplbd_level, other_level) = match lower_level.as_str() {
        "info-all" => ("info", "info"),
        "debug" => ("debug", "debug"),
        "trace" => ("trace", "trace"),
        "info" | "" => ("info", "warn"),
        other => (other, "warn"),
    };

    let filter_str = match level {
        "trace" => "udplbd=trace,tonic=trace,hyper=trace,tower_http=trace,sqlx::query=trace".to_string(),
        _ => format!("udplbd={udplbd_level},tonic={other_level},hyper={other_level},tower_http={other_level}"),
    };

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter_str))
        .expect("invalid log level in configuration or RUST_LOG");

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(level == "trace")
        .with_thread_ids(level == "trace")
        .with_thread_names(level == "trace")
        .init();
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{cli_main, setup_logging, Cli};
    use clap::Parser;
    use udplbd::config::Config;

    #[tokio::test(flavor = "multi_thread")]
    async fn end_to_end() {
        setup_logging("debug").unwrap();
        tokio::spawn(async move {
            let config = Config::turmoil();
            let cli = Cli::parse_from(vec!["udplbd", "mock", "--db", "/tmp/udplbd-test.db"]);
            let _ = std::fs::remove_file("/tmp/udplbd-test.db");
            let result = cli_main(cli, config).await;
            if let Err(e) = &result {
                eprintln!("cli_main error: {e:?}");
                panic!("mock server crashed");
            }
        });
        // Wait up to 5 seconds for the mock DP to listen on 127.0.0.1:19523
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        let mut ready = false;
        while start.elapsed() < timeout {
            match tokio::net::TcpStream::connect("127.0.0.1:19523").await {
                Ok(_) => {
                    ready = true;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        assert!(
            ready,
            "Timed out waiting for mock DP to listen on 127.0.0.1:19523"
        );

        let config = Config::turmoil();
        let cli = Cli::parse_from(vec![
            "udplbd",
            "dataplane",
            "-u",
            "ejfat://test@127.0.0.1:19523/",
            "doctor",
            "-a",
            "127.0.0.1",
            "-p",
            "33851",
        ]);
        assert!(cli_main(cli, config).await.is_ok())
    }
}
