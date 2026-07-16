use crate::cluster::{ClusterReplicator, SharedState, build_replicator};
use crate::config::Config;
use crate::ha::{
    ActiveStandbyReplicator, ActiveStandbyRuntime, build_addon, run_active_standby,
    run_leader_monitor, run_state_replication,
};
use crate::proxy::ProxyServer;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::info;

pub async fn run(config: Config) -> Result<()> {
    let state = Arc::new(SharedState::default());
    let base_replicator = build_replicator(config.node.id, &config.cluster, state.clone()).await?;
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
    let ha = build_addon(&config.ha.addon);
    let replication_config = config.ha.replication.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let ha_task = tokio::spawn(run_leader_monitor(
        config.node.clone(),
        replicator.clone(),
        ha,
        shutdown_rx.clone(),
        Duration::from_millis(config.ha.leader_check_interval_ms),
    ));
    let server = Arc::new(ProxyServer::new(config, state, replicator.clone()));

    let active_standby_task = active_standby_runtime.map(|runtime| {
        tokio::spawn(run_active_standby(
            active_standby_config,
            runtime,
            shutdown_rx.clone(),
        ))
    });
    let replication_task = tokio::spawn(run_state_replication(
        replication_config,
        server.clone(),
        replicator.clone(),
        shutdown_rx.clone(),
    ));
    let server_task = tokio::spawn(async move { server.run(shutdown_rx).await });

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    server_task.await??;
    replication_task.await??;
    if let Some(active_standby_task) = active_standby_task {
        active_standby_task.await??;
    }
    ha_task.await??;
    replicator.shutdown().await?;
    Ok(())
}
