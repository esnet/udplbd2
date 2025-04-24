/// CLI subcommands that interact with the gRPC API
use chrono::{TimeZone, Utc};
use clap::{Args, Parser, Subcommand};

use prost_wkt_types::Timestamp;

// Assume these are defined in your API modules.
use crate::api::client::{ControlPlaneClient, EjfatUrl};
use crate::config::{parse_duration, Config};
use crate::errors::{Error, Result};
use crate::proto::loadbalancer::v1::{
    token_permission::PermissionType, token_permission::ResourceType, TokenPermission,
};

/// API commands that call the gRPC control plane.
/// If no URL is provided, the default connection string is built from the server config.
#[derive(Parser, Debug)]
#[command(
    name = "client",
    version = "0.3.0",
    author = "Derek Howard <dhoward@es.net>",
    about = "Send or process files using the EJFAT protocol (API calls)"
)]
pub struct ApiCli {
    /// EJFAT URL with token, host, and port. If not provided, a default is constructed from the server config.
    #[arg(short, long, env = "EJFAT_URI")]
    pub url: Option<String>,

    /// Load balancer id (for admin URLs).
    #[arg(short, long)]
    pub lbid: Option<String>,

    #[command(subcommand)]
    pub command: ApiCommand,
}

#[derive(Subcommand, Debug)]
pub enum ApiCommand {
    /// Reserve an LB and print the EJFAT_URI with sync and data query parameters.
    Reserve(ReserveArgs),
    /// Free the reserved load balancer.
    Free,
    /// Display an overview of the load balancers
    Overview,
    /// Manage allowed sender IP addresses.
    Senders {
        #[command(subcommand)]
        action: SendersCommand,
    },
    /// Manage authentication tokens.
    Tokens {
        #[command(subcommand)]
        action: TokensCommand,
    },
    /// Display the version of the load balancer.
    Version,
}

#[derive(Subcommand, Debug)]
pub enum SendersCommand {
    /// Add allowed sender IP addresses.
    Add {
        /// IP addresses to add.
        #[arg(value_name = "ADDRESS", required = true, num_args = 1..)]
        addresses: Vec<String>,
    },
    /// Remove allowed sender IP addresses.
    Remove {
        /// IP addresses to remove.
        #[arg(value_name = "ADDRESS", required = true, num_args = 1..)]
        addresses: Vec<String>,
    },
}

#[derive(Args, Debug)]
pub struct ReserveArgs {
    /// Name of the new LB.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Timestamp for reservation expiration.
    #[arg(long)]
    pub until: Option<String>,
    /// Allowed sender IP addresses.
    #[arg(long, required = true, num_args = 1..)]
    pub sender: Vec<String>,
    /// Duration offset for reservation expiration (e.g., "1hour 30min 2s").
    #[arg(long)]
    pub after: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum TokensCommand {
    /// Create a new token with specified permissions.
    Create(TokenCreateArgs),
    /// List permissions for a token.
    ListPermissions(TokenListArgs),
    /// List all child tokens created by this token.
    ListChildren,
    /// Revoke a token and all its children.
    Revoke(TokenRevokeArgs),
}

#[derive(Args, Debug)]
pub struct TokenCreateArgs {
    /// Human readable name for the token.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Resource type (ALL, LOAD_BALANCER, RESERVATION, SESSION).
    #[arg(long, value_name = "TYPE")]
    pub resource_type: String,
    /// Optional resource ID the permission applies to.
    #[arg(long, value_name = "ID")]
    pub resource_id: Option<String>,
    /// Permission type (READ_ONLY, REGISTER, RESERVE, UPDATE).
    #[arg(long)]
    pub permission: String,
}

#[derive(Args, Debug)]
pub struct TokenListArgs {
    /// Token to list permissions for (defaults to token in URL).
    #[arg(value_name = "TOKEN")]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct TokenRevokeArgs {
    /// Token to revoke.
    #[arg(value_name = "TOKEN")]
    pub token: String,
}

impl ApiCli {
    /// Run the API command using either the provided URL or a default constructed from the server config.
    pub async fn run(&self, config: &Config) -> Result<()> {
        // Get URL from CLI or build default from config.
        let url = match &self.url {
            Some(u) => u.clone(),
            None => {
                let listen_addr = config.server.listen.first().ok_or(Error::Config(
                    "no listen address in server config".to_string(),
                ))?;
                format!("ejfat://{}@{}", config.server.auth_token, listen_addr)
            }
        };

        // Inject lbid into the URL if provided.
        let url = if let Some(lbid) = &self.lbid {
            let mut parsed_url: EjfatUrl = url.parse()?;
            parsed_url.lb_id = Some(lbid.clone());
            parsed_url.to_string()
        } else {
            url
        };

        match &self.command {
            ApiCommand::Version => {
                let mut client = ControlPlaneClient::from_url(&url).await?;
                let reply = client.version().await?.into_inner();
                println!("UDPLBD_COMMIT={}", reply.commit);
                println!("UDPLBD_BUILD={}", reply.build);
                println!("UDPLBD_COMPAT_TAG={}", reply.compat_tag);
            }
            ApiCommand::Free => {
                let mut client = ControlPlaneClient::from_url(&url).await?;
                client.free_load_balancer().await?.into_inner();
                println!(
                    "load balancer {} freed",
                    client.lb_id.unwrap_or("unknown".to_string())
                );
            }
            ApiCommand::Overview => {
                let overview = overview_to_string(url).await?;
                println!("{overview}");
            }
            ApiCommand::Senders { action } => match action {
                SendersCommand::Add { addresses } => {
                    add_senders(url, addresses.clone()).await?;
                    println!("senders added");
                }
                SendersCommand::Remove { addresses } => {
                    remove_senders(url, addresses.clone()).await?;
                    println!("senders removed");
                }
            },
            ApiCommand::Reserve(args) => {
                let expiration = match (&args.until, &args.after) {
                    (Some(ts_str), None) => Some(ts_str.parse()?),
                    (None, Some(duration_str)) => {
                        let duration = parse_duration(duration_str)?;
                        let now = std::time::SystemTime::now();
                        let expiration = now + duration;
                        Some(Timestamp::from(expiration))
                    }
                    (None, None) => None,
                    _ => {
                        return Err(Error::Usage(
                            "cannot specify both --until and --after".to_string(),
                        ))
                    }
                };
                reserve_lb(url, args.name.clone(), expiration, args.sender.clone()).await?;
            }
            ApiCommand::Tokens { action } => match action {
                TokensCommand::Create(args) => {
                    create_token(
                        url,
                        args.name.clone(),
                        args.resource_type.clone(),
                        args.resource_id.clone(),
                        args.permission.clone(),
                    )
                    .await?;
                }
                TokensCommand::ListPermissions(args) => {
                    list_token_permissions(url, args.token.clone()).await?;
                }
                TokensCommand::ListChildren => {
                    list_child_tokens(url).await?;
                }
                TokensCommand::Revoke(args) => {
                    revoke_token(url, args.token.clone()).await?;
                }
            },
        }
        Ok(())
    }
}

async fn reserve_lb(
    url: String,
    name: String,
    until: Option<Timestamp>,
    sender_addresses: Vec<String>,
) -> Result<()> {
    let mut parsed_url: EjfatUrl = url.parse().expect("bad URL");
    let mut client = ControlPlaneClient::from_url(url.as_str()).await?;
    let reply = client
        .reserve_load_balancer(name, until, sender_addresses)
        .await?
        .into_inner();
    parsed_url.update_from_reservation(&reply);
    println!("export 'EJFAT_URI={parsed_url}'");
    Ok(())
}

async fn add_senders(url: String, sender_addresses: Vec<String>) -> Result<()> {
    let mut client = ControlPlaneClient::from_url(&url).await?;
    client.add_senders(sender_addresses).await?;
    Ok(())
}

async fn remove_senders(url: String, sender_addresses: Vec<String>) -> Result<()> {
    let mut client = ControlPlaneClient::from_url(&url).await?;
    client.remove_senders(sender_addresses).await?;
    Ok(())
}

async fn create_token(
    url: String,
    name: String,
    resource_type: String,
    resource_id: Option<String>,
    permission: String,
) -> Result<()> {
    let resource_type = match resource_type.to_uppercase().as_str() {
        "ALL" => ResourceType::All,
        "LOAD_BALANCER" => ResourceType::LoadBalancer,
        "RESERVATION" => ResourceType::Reservation,
        "SESSION" => ResourceType::Session,
        _ => return Err(Error::Config(format!("{resource_type} is not a valid resource type. Options are: all, load_balancer, session"))),
    };

    let permission_type = match permission.to_uppercase().as_str() {
        "READ" => PermissionType::ReadOnly,
        "REGISTER" => PermissionType::Register,
        "RESERVE" => PermissionType::Reserve,
        "UPDATE" => PermissionType::Update,
        _ => {
            return Err(Error::Config(format!(
            "{permission} is not a valid permission. Options are: read, register, reserve, update"
        )))
        }
    };

    let mut client = ControlPlaneClient::from_url(&url).await?;
    let permission = TokenPermission {
        resource_type: resource_type.into(),
        resource_id: resource_id.unwrap_or_default(),
        permission: permission_type.into(),
    };

    let reply = client
        .create_token(name, vec![permission])
        .await?
        .into_inner();

    println!("Created token: {}", reply.token);
    Ok(())
}

async fn list_token_permissions(url: String, token: Option<String>) -> Result<()> {
    let mut client = ControlPlaneClient::from_url(&url).await?;

    let reply = match token {
        Some(t) => client
            .list_token_permissions_for_token(t)
            .await?
            .into_inner(),
        None => client.list_token_permissions().await?.into_inner(),
    };

    if let Some(details) = reply.token {
        println!("Token: {}", details.name);
        println!("Created at: {}", details.created_at);
        println!("\nPermissions:");
        for perm in details.permissions {
            let resource_type = match perm.resource_type() {
                ResourceType::All => "ALL",
                ResourceType::LoadBalancer => "LOAD_BALANCER",
                ResourceType::Reservation => "RESERVATION",
                ResourceType::Session => "SESSION",
            };

            let permission = match perm.permission() {
                PermissionType::ReadOnly => "READ_ONLY",
                PermissionType::Register => "REGISTER",
                PermissionType::Reserve => "RESERVE",
                PermissionType::Update => "UPDATE",
            };

            if perm.resource_id.is_empty() {
                println!("  - {} {} (all resources)", permission, resource_type);
            } else {
                println!(
                    "  - {} {} (id: {})",
                    permission, resource_type, perm.resource_id
                );
            }
        }
    } else {
        println!("Token not found");
    }
    Ok(())
}

async fn list_child_tokens(url: String) -> Result<()> {
    let mut client = ControlPlaneClient::from_url(&url).await?;
    let reply = client.list_child_tokens().await?.into_inner();

    if reply.tokens.is_empty() {
        println!("No child tokens found");
        return Ok(());
    }

    for token in reply.tokens {
        println!("\nToken: {}", token.name);
        println!("Created at: {}", token.created_at);
        println!("Permissions:");
        for perm in token.permissions {
            let resource_type = match perm.resource_type() {
                ResourceType::All => "ALL",
                ResourceType::LoadBalancer => "LOAD_BALANCER",
                ResourceType::Reservation => "RESERVATION",
                ResourceType::Session => "SESSION",
            };

            let permission = match perm.permission() {
                PermissionType::ReadOnly => "READ_ONLY",
                PermissionType::Register => "REGISTER",
                PermissionType::Reserve => "RESERVE",
                PermissionType::Update => "UPDATE",
            };

            if perm.resource_id.is_empty() {
                println!("  - {} {} (all resources)", permission, resource_type);
            } else {
                println!(
                    "  - {} {} (id: {})",
                    permission, resource_type, perm.resource_id
                );
            }
        }
    }
    Ok(())
}

async fn revoke_token(url: String, token: String) -> Result<()> {
    let mut client = ControlPlaneClient::from_url(&url).await?;
    client.revoke_token(token).await?;
    println!("Token revoked successfully");
    Ok(())
}

async fn overview_to_string(url: String) -> Result<String> {
    let mut client = ControlPlaneClient::from_url(&url).await?;
    let reply = client.overview().await?.into_inner();

    let mut output = String::new();
    if reply.load_balancers.is_empty() {
        return Ok("No load balancers currently active".to_string());
    }
    for lb in reply.load_balancers {
        if let Some(reservation) = lb.reservation {
            output.push_str(&format!("LB {} - {}\n", reservation.lb_id, lb.name));
            output.push_str(&format!(
                "  sync: {}:{}\n",
                reservation.sync_ip_address, reservation.sync_udp_port
            ));
            output.push_str(&format!(
                "  data: {}:19522\n",
                reservation.data_ipv4_address
            ));
        }

        if let Some(status) = lb.status {
            output.push_str(&format!(
                "  expires: {}\n",
                status
                    .expires_at
                    .map(|t| Utc
                        .timestamp_opt(t.seconds, t.nanos as u32)
                        .unwrap()
                        .to_rfc3339())
                    .unwrap_or_else(|| "Never".to_string())
            ));

            output.push_str("  workers:\n");
            for worker in status.workers {
                let last_updated = worker
                    .last_updated
                    .map(|t| {
                        Utc.timestamp_opt(t.seconds, t.nanos as u32)
                            .unwrap()
                            .to_rfc3339()
                    })
                    .unwrap_or_else(|| "Never".to_string());
                output.push_str(&format!(
                    "    - {} (slots: {}/512, queue: {:.2}%, control: {}, updated: {})\n",
                    worker.name,
                    worker.slots_assigned,
                    worker.fill_percent * 100.0,
                    worker.control_signal,
                    last_updated
                ));
            }

            output.push_str("  senders:\n");
            for sender in status.sender_addresses {
                output.push_str(&format!("    - {sender}\n"));
            }
        }
        output.push('\n');
    }

    Ok(output)
}
