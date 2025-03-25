//! udplbd entry point.
//!
//! Provides a command-line interface for managing the udplbd service,
//! handling configuration loading, and initializing the logging subsystem.
//!
//! The daemon supports configuration via both file and environment variables,
//! with environment variables taking precedence over file configuration.

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

    /// Start the gRPC server with a simulated dataplane
    Mock {
        /// Path to the in-memory database file (optional)
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
    cli_main(cli, config).await
}

pub async fn cli_main(cli: Cli, config: Config) -> Result<()> {
    match cli.command {
        Commands::Start => start(config).await?,
        Commands::Static {
            apply,
            reservation_file,
        } => {
            apply_static_config(&config, reservation_file, apply).await?;
        }
        Commands::Mock { db } => {
            start_mocked(config, db).await?;
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

/// Set up logging and start the server
///
/// # Arguments
/// * `config` - Loaded configuration
async fn start(config: Config) -> Result<()> {
    start_server(config).await
}

/// Set up logging and start the simulated server
///
/// # Arguments
/// * `config` - Loaded configuration
/// * `db` - Path to the in-memory database file (optional)
async fn start_mocked(config: Config, db: Option<PathBuf>) -> Result<()> {
    start_mocked_server(config, db).await
}

/// Configures the logging subsystem based on the specified log level. Filters out noisy modules.
///
/// # Arguments
/// * `level` - String representation of the desired log level
fn setup_logging(level: &str) -> Result<()> {
    let filter: EnvFilter = format!("udplbd={level}")
        .parse()
        .expect("invalid log level in udplbd.cfg");
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{cli_main, Cli};
    use clap::Parser;
    use udplbd::config::Config;

    #[tokio::test]
    async fn end_to_end() {
        tokio::spawn(async move {
            let config = Config::turmoil();
            let cli = Cli::parse_from(vec!["udplbd", "mock"]);
            let _ = cli_main(cli, config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let config = Config::turmoil();
        let cli = Cli::parse_from(vec![
            "udplbd",
            "dataplane",
            "doctor",
            "-a",
            "127.0.0.1",
            "-p",
            "33851",
        ]);
        assert!(cli_main(cli, config).await.is_ok())
    }
}
