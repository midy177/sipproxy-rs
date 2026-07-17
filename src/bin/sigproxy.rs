use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use sigproxy_rs::app;
use sigproxy_rs::config::{Config, example_config};
use std::path::PathBuf;

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sigproxy_rs=info,warn".into()),
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
    }
    Ok(())
}
