use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use sigproxy_rs::app;
use sigproxy_rs::cluster::{SharedState, build_replicator};
use sigproxy_rs::config::{Config, example_config};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(name = "sigproxy")]
#[command(about = "Layer-7 SIP proxy with cluster and HA addon boundaries")]
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
    Cluster {
        #[command(subcommand)]
        command: ClusterCommand,
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
enum ClusterCommand {
    Status(ConfigPath),
    Bootstrap(ConfigPath),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sigproxy_rs=info,openraft=warn,warn".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => {
            let config = Config::load(args.config)?;
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
        Command::Cluster { command } => match command {
            ClusterCommand::Status(args) => {
                let config = Config::load(args.config)?;
                let state = Arc::new(SharedState::default());
                let replicator = build_replicator(config.node.id, &config.cluster, state).await?;
                println!("node_id={}", config.node.id);
                println!("role={:?}", replicator.role().await);
                println!("leader={:?}", replicator.leader().await);
                replicator.shutdown().await?;
            }
            ClusterCommand::Bootstrap(args) => {
                let config = Config::load(args.config)?;
                println!(
                    "bootstrap requested for node {} in {:?} mode",
                    config.node.id, config.cluster.mode
                );
                println!("openraft bootstrap wiring is planned in the raft implementation phase");
            }
        },
    }
    Ok(())
}
