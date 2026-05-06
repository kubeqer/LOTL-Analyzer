use crate::config::{
    API_TIMEOUT, BATCH_SIZE, FLUSH_INTERVAL, MAX_RETRIES, RETRY_BASE_DELAY, RETRY_MAX_DELAY,
};
use crate::event::SysmonEvent;
use anyhow::Result;
use reqwest::{Client, StatusCode};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::{interval, Interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

struct ShipperContext {
    http_client: Client,
    endpoint_url: String,
    host_ip: Option<IpAddr>,
}

enum SendOutcome {
    Success(StatusCode),
    ClientError(StatusCode),
    RetriableServerError(StatusCode),
    NetworkError(String),
}

pub async fn run(
    endpoint_url: String,
    host_ip: Option<IpAddr>,
    mut event_receiver: Receiver<SysmonEvent>,
    cancel_token: CancellationToken,
) -> Result<()> {
    let context = ShipperContext {
        http_client: build_http_client()?,
        endpoint_url,
        host_ip,
    };
    let mut pending_batch: Vec<SysmonEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut flush_ticker = build_flush_ticker();
    flush_ticker.tick().await;

    info!(
        endpoint = %context.endpoint_url,
        host_ip = ?context.host_ip,
        "shipper started"
    );

    loop {
        tokio::select! {
            biased;

            _ = cancel_token.cancelled() => {
                drain_remaining_into(&mut pending_batch, &mut event_receiver);
                flush_if_any(&context, &mut pending_batch).await;
                info!("shipper stopped");
                return Ok(());
            }

            _ = flush_ticker.tick() => {
                flush_if_any(&context, &mut pending_batch).await;
            }

            maybe_event = event_receiver.recv() => {
                match maybe_event {
                    Some(event) => {
                        pending_batch.push(event);
                        if pending_batch.len() >= BATCH_SIZE {
                            flush_if_any(&context, &mut pending_batch).await;
                        }
                    }
                    None => {
                        flush_if_any(&context, &mut pending_batch).await;
                        info!("upstream channel closed");
                        return Ok(());
                    }
                }
            }
        }
    }
}

fn build_http_client() -> Result<Client> {
    let client = Client::builder().timeout(API_TIMEOUT).build()?;
    Ok(client)
}

fn build_flush_ticker() -> Interval {
    let mut ticker = interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}

fn drain_remaining_into(
    pending_batch: &mut Vec<SysmonEvent>,
    event_receiver: &mut Receiver<SysmonEvent>,
) {
    while let Ok(event) = event_receiver.try_recv() {
        pending_batch.push(event);
    }
}

async fn flush_if_any(context: &ShipperContext, pending_batch: &mut Vec<SysmonEvent>) {
    if pending_batch.is_empty() {
        return;
    }
    let events_to_ship = std::mem::take(pending_batch);
    send_batch(context, events_to_ship).await;
}

async fn send_batch(context: &ShipperContext, events: Vec<SysmonEvent>) {
    let event_count = events.len();
    let request_body = build_payload(events, &context.host_ip);
    send_with_retry(context, &request_body, event_count).await;
}

fn build_payload(events: Vec<SysmonEvent>, host_ip: &Option<IpAddr>) -> serde_json::Value {
    serde_json::json!({
        "agent": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "host_ip": host_ip.map(|address| address.to_string()),
        "events": events,
    })
}

async fn send_with_retry(
    context: &ShipperContext,
    request_body: &serde_json::Value,
    event_count: usize,
) {
    let mut current_delay = RETRY_BASE_DELAY;

    for attempt_index in 0..=MAX_RETRIES {
        let outcome = send_once(context, request_body).await;
        match outcome {
            SendOutcome::Success(status) => {
                info!(
                    count = event_count,
                    attempt = attempt_index,
                    status = %status,
                    "batch shipped"
                );
                return;
            }
            SendOutcome::ClientError(status) => {
                warn!(
                    count = event_count,
                    status = %status,
                    "client error, dropping batch"
                );
                return;
            }
            SendOutcome::RetriableServerError(status) => {
                warn!(
                    attempt = attempt_index,
                    status = %status,
                    "server error, retrying"
                );
            }
            SendOutcome::NetworkError(message) => {
                warn!(
                    attempt = attempt_index,
                    error = %message,
                    "send failed, retrying"
                );
            }
        }

        if attempt_index < MAX_RETRIES {
            tokio::time::sleep(current_delay).await;
            current_delay = next_backoff(current_delay);
        }
    }
    error!(
        count = event_count,
        "batch dropped after {} retries", MAX_RETRIES
    );
}

async fn send_once(context: &ShipperContext, request_body: &serde_json::Value) -> SendOutcome {
    let response_result = context
        .http_client
        .post(&context.endpoint_url)
        .json(request_body)
        .send()
        .await;

    match response_result {
        Ok(response) => classify_response(response.status()),
        Err(error) => SendOutcome::NetworkError(error.to_string()),
    }
}

fn classify_response(status: StatusCode) -> SendOutcome {
    if status.is_success() {
        SendOutcome::Success(status)
    } else if status.is_client_error() {
        SendOutcome::ClientError(status)
    } else {
        SendOutcome::RetriableServerError(status)
    }
}

fn next_backoff(current_delay: Duration) -> Duration {
    current_delay.saturating_mul(2).min(RETRY_MAX_DELAY)
}
