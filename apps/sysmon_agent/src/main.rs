mod config;
mod event;
mod net;
mod sanitizer;
mod shipper;

#[cfg(windows)]
mod reader;

use anyhow::{Context, Result};
use std::net::IpAddr;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

fn main() -> Result<()> {
    init_logging();

    let endpoint_url = load_endpoint_from_env()?;
    let host_ip = detect_host_ip_logged();
    let sanitizer = sanitizer::Sanitizer::new()?;
    let runtime = build_tokio_runtime()?;

    runtime.block_on(run_agent(endpoint_url, host_ip, sanitizer))
}

async fn run_agent(
    endpoint_url: String,
    host_ip: Option<IpAddr>,
    sanitizer: sanitizer::Sanitizer,
) -> Result<()> {
    info!(
        endpoint = %endpoint_url,
        channel = %config::CHANNEL,
        host_ip = ?host_ip,
        "starting sysmon_agent"
    );

    let cancel_token = CancellationToken::new();
    let (event_sender, event_receiver) =
        mpsc::channel::<event::SysmonEvent>(config::CHANNEL_CAPACITY);

    let shipper_task = spawn_shipper(endpoint_url, host_ip, event_receiver, cancel_token.clone());

    #[cfg(windows)]
    let reader_task = spawn_reader(sanitizer, event_sender, cancel_token.clone());

    #[cfg(not(windows))]
    {
        let _ = (event_sender, sanitizer);
        cancel_token.cancel();
        let _ = shipper_task.await;
        return Err(anyhow::anyhow!("sysmon_agent only supports Windows"));
    }

    wait_for_shutdown_signal().await?;
    cancel_token.cancel();

    #[cfg(windows)]
    {
        let _ = reader_task.await;
    }
    let _ = shipper_task.await;

    info!("sysmon_agent stopped");
    Ok(())
}

fn spawn_shipper(
    endpoint_url: String,
    host_ip: Option<IpAddr>,
    event_receiver: mpsc::Receiver<event::SysmonEvent>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = shipper::run(endpoint_url, host_ip, event_receiver, cancel_token).await
        {
            error!(error = %error, "shipper terminated");
        }
    })
}

#[cfg(windows)]
fn spawn_reader(
    sanitizer: sanitizer::Sanitizer,
    event_sender: mpsc::Sender<event::SysmonEvent>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        if let Err(error) = reader::run(sanitizer, event_sender, cancel_token) {
            error!(error = %error, "reader terminated");
        }
    })
}

async fn wait_for_shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to install ctrl-c handler")?;
    info!("ctrl-c received");
    Ok(())
}

fn load_endpoint_from_env() -> Result<String> {
    std::env::var("SYSMON_AGENT_API_ENDPOINT").context("SYSMON_AGENT_API_ENDPOINT must be set")
}

fn detect_host_ip_logged() -> Option<IpAddr> {
    match net::detect_local_ip() {
        Some(address) => {
            info!(host_ip = %address, "detected local ip");
            Some(address)
        }
        None => {
            info!("could not detect local ip, continuing without it");
            None
        }
    }
}

fn build_tokio_runtime() -> Result<Runtime> {
    let runtime = RuntimeBuilder::new_multi_thread().enable_all().build()?;
    Ok(runtime)
}

fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
