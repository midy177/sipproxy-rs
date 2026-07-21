use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use sigproxy_rs::app;
use sigproxy_rs::config::{Config, ProxyGeoStartupRefresh, example_config};
use sigproxy_rs::proxy::build_ipdeny_cache;
use std::env;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "sigproxy")]
#[command(about = "Layer-7 SIP-aware proxy with active-standby HA boundaries")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(ConfigPath),
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    GeoCache {
        #[command(subcommand)]
        command: GeoCacheCommand,
    },
}

#[derive(Debug, Args)]
struct ConfigPath {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Init {
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
        #[arg(long)]
        stdout: bool,
    },
    Check(ConfigPath),
}

#[derive(Debug, Subcommand)]
enum GeoCacheCommand {
    Build(GeoCacheBuildArgs),
}

#[derive(Debug, Args)]
struct GeoCacheBuildArgs {
    #[arg(long, value_delimiter = ',', required = true)]
    countries: Vec<String>,
    #[arg(short, long, default_value = "/var/lib/sigproxy-rs/geo/geo.sgeo")]
    output: PathBuf,
    #[arg(
        long,
        default_value = "http://www.ipdeny.com/ipblocks/data/countries/{country}.zone"
    )]
    provider_base_url: String,
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 3)]
    retries: u32,
    #[arg(long)]
    allow_partial: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = env::var("RUST_LOG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "sigproxy_rs=info,warn".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(env_filter))
        .with_writer(std::io::stdout)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => {
            info!(config = %args.config.display(), "sigproxy starting");
            let config = Config::load(args.config)?;
            log_startup_mode(&config);
            app::run(config).await?;
        }
        Command::Config { command } => match command {
            ConfigCommand::Init { output, stdout } => {
                if stdout {
                    print!("{}", example_config());
                } else {
                    Config::write_example(output)?;
                }
            }
            ConfigCommand::Check(args) => {
                Config::load(args.config)?;
                println!("configuration OK");
            }
        },
        Command::GeoCache { command } => match command {
            GeoCacheCommand::Build(args) => {
                build_ipdeny_cache(
                    &args.countries,
                    &args.output,
                    &args.provider_base_url,
                    args.timeout_seconds,
                    args.retries,
                    args.allow_partial,
                )
                .await?;
                println!("geo cache written to {}", args.output.display());
            }
        },
    }
    Ok(())
}

fn log_startup_mode(config: &Config) {
    let mode = if config.ha.active_standby.enabled {
        "active-standby"
    } else {
        "standalone"
    };
    let xdp_enabled = config.proxy.listeners.iter().any(|listener| {
        config
            .proxy
            .effective_security_for_listener(listener)
            .xdp
            .enabled
    });
    let geo_startup_refresh = config
        .proxy
        .listeners
        .iter()
        .map(|listener| {
            config
                .proxy
                .effective_security_for_listener(listener)
                .geo
                .startup_refresh
        })
        .find(|refresh| !matches!(refresh, ProxyGeoStartupRefresh::Disabled))
        .unwrap_or(ProxyGeoStartupRefresh::Disabled);
    let persistence = config.persistence_config();

    info!(
        mode,
        node_id = config.node.id,
        listeners = config.proxy.listeners.len(),
        upstream_groups = config.proxy.upstream_groups.len(),
        active_standby_enabled = config.ha.active_standby.enabled,
        initial_role = ?config.ha.active_standby.initial_role,
        replication_enabled = config.ha.replication.enabled,
        persistence_enabled = persistence.enabled,
        persistence_path = %persistence.path,
        persistence_required = persistence.required,
        persistence_cleanup_interval_ms = persistence.cleanup_interval_ms,
        xdp_enabled,
        geo_startup_refresh = ?geo_startup_refresh,
        "sigproxy startup mode resolved"
    );
}
