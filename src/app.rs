use crate::cluster::{ClusterReplicator, SharedState, build_replicator};
use crate::config::Config;
use crate::config::HaAddonConfig;
use crate::ha::{
    ActiveStandbyReplicator, ActiveStandbyRuntime, build_addon, run_active_standby,
    run_leader_monitor, run_state_replication,
};
use crate::persistence::HaPersistence;
use crate::proxy::ProxyServer;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

pub async fn run(config: Config) -> Result<()> {
    let persistence = HaPersistence::open(&config.ha.persistence)?;
    let state = Arc::new(SharedState::default());
    let base_replicator = build_replicator(state.clone(), persistence.clone()).await?;
    let active_standby_config = config.ha.active_standby.clone();
    let active_standby_runtime = active_standby_config
        .enabled
        .then(|| ActiveStandbyRuntime::new(config.node.id, active_standby_config.initial_role));
    let replicator: Arc<dyn ClusterReplicator> =
        if let Some(runtime) = active_standby_runtime.clone() {
            ActiveStandbyReplicator::new(base_replicator, runtime)
        } else {
            base_replicator
        };
    let leader_monitor_enabled = !matches!(&config.ha.addon, HaAddonConfig::Noop);
    let replication_config = config.ha.replication.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    if leader_monitor_enabled {
        let ha = build_addon(&config.ha.addon);
        tasks.spawn(run_leader_monitor(
            config.node.clone(),
            replicator.clone(),
            ha,
            shutdown_rx.clone(),
            Duration::from_millis(config.ha.leader_check_interval_ms),
        ));
    }
    let server = Arc::new(ProxyServer::new(
        config,
        state,
        replicator.clone(),
        persistence.clone(),
    )?);

    if let Some(runtime) = active_standby_runtime {
        tasks.spawn(run_active_standby(
            active_standby_config,
            runtime,
            shutdown_rx.clone(),
        ));
    }
    if replication_config.enabled {
        tasks.spawn(run_state_replication(
            replication_config,
            server.clone(),
            replicator.clone(),
            shutdown_rx.clone(),
        ));
    }
    if let Some(persistence) = persistence {
        let interval = Duration::from_millis(server.config().ha.persistence.cleanup_interval_ms);
        tasks.spawn(persistence.cleanup_loop(interval, shutdown_rx.clone()));
    }
    tasks.spawn(async move { server.run(shutdown_rx).await });

    let mut task_failure = None;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to wait for shutdown signal")?;
            info!("shutdown signal received");
        }
        result = tasks.join_next() => {
            task_failure = Some(match result {
                Some(Ok(Ok(()))) => anyhow::anyhow!("background task exited unexpectedly"),
                Some(Ok(Err(err))) => err,
                Some(Err(err)) => anyhow::anyhow!("background task panicked: {err}"),
                None => anyhow::anyhow!("all background tasks exited unexpectedly"),
            });
        }
    }
    let _ = shutdown_tx.send(true);
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) if task_failure.is_none() => task_failure = Some(err),
            Err(err) if task_failure.is_none() => {
                task_failure = Some(anyhow::anyhow!("background task panicked: {err}"));
            }
            _ => {}
        }
    }
    replicator.shutdown().await?;
    if let Some(err) = task_failure {
        return Err(err);
    }
    Ok(())
}
