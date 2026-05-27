#![cfg(windows)]

use crate::config::{bookmark_path, CHANNEL, POLL_INTERVAL};
use crate::event::{parse_event_xml, SysmonEvent};
use crate::sanitizer::Sanitizer;
use anyhow::{anyhow, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
    EvtQueryReverseDirection, EvtRender, EvtRenderEventXml,
};

type EvtHandle = isize;
const EVT_NEXT_BATCH_SIZE: usize = 64;
const EVT_NEXT_TIMEOUT_MS: u32 = 2000;
const SLEEP_STEP_MS: u64 = 200;

enum FetchResult {
    Events(Vec<EvtHandle>),
    Exhausted,
    Error(u32),
}

struct DrainOutcome {
    events_sent: usize,
    last_record_id: u64,
    downstream_closed: bool,
}

pub fn run(
    sanitizer: Sanitizer,
    event_sender: Sender<SysmonEvent>,
    cancel_token: CancellationToken,
) -> Result<()> {
    let channel_wide = encode_wide(CHANNEL);
    let bookmark_file = bookmark_path();
    let mut last_record_id = determine_starting_record_id(&channel_wide, &bookmark_file);

    info!(channel = %CHANNEL, "reader started");

    while !cancel_token.is_cancelled() {
        let poll_outcome = poll_once(
            &channel_wide,
            last_record_id,
            &sanitizer,
            &event_sender,
            &cancel_token,
        );

        last_record_id = poll_outcome.last_record_id;
        persist_bookmark_logging_errors(&bookmark_file, last_record_id);

        if poll_outcome.events_sent > 0 {
            debug!(
                count = poll_outcome.events_sent,
                last_record_id, "batch drained"
            );
        }
        if poll_outcome.downstream_closed {
            info!("downstream channel closed");
            return Ok(());
        }

        sleep_interruptible(POLL_INTERVAL, &cancel_token);
    }

    info!("reader stopped");
    Ok(())
}

fn poll_once(
    channel_wide: &[u16],
    last_record_id: u64,
    sanitizer: &Sanitizer,
    event_sender: &Sender<SysmonEvent>,
    cancel_token: &CancellationToken,
) -> DrainOutcome {
    let query_handle = match open_forward_query(channel_wide, last_record_id) {
        Some(handle) => handle,
        None => {
            return DrainOutcome {
                events_sent: 0,
                last_record_id,
                downstream_closed: false,
            };
        }
    };

    let outcome = drain_query(
        query_handle,
        last_record_id,
        sanitizer,
        event_sender,
        cancel_token,
    );
    close_handle(query_handle);
    outcome
}

fn drain_query(
    query_handle: EvtHandle,
    starting_record_id: u64,
    sanitizer: &Sanitizer,
    event_sender: &Sender<SysmonEvent>,
    cancel_token: &CancellationToken,
) -> DrainOutcome {
    let mut events_sent = 0usize;
    let mut last_record_id = starting_record_id;

    loop {
        let event_handles = match fetch_next_batch(query_handle) {
            FetchResult::Events(handles) => handles,
            FetchResult::Exhausted => break,
            FetchResult::Error(code) => {
                warn!(code, "EvtNext error");
                break;
            }
        };

        for event_handle in event_handles {
            let parsed_event = match parse_event_from_handle(event_handle) {
                Some(event) => event,
                None => continue,
            };

            if parsed_event.record_id > last_record_id {
                last_record_id = parsed_event.record_id;
            }

            let sanitized_event = match sanitizer.process(parsed_event) {
                Some(event) => event,
                None => continue,
            };

            if event_sender.blocking_send(sanitized_event).is_err() {
                return DrainOutcome {
                    events_sent,
                    last_record_id,
                    downstream_closed: true,
                };
            }
            events_sent += 1;
        }

        if cancel_token.is_cancelled() {
            break;
        }
    }

    DrainOutcome {
        events_sent,
        last_record_id,
        downstream_closed: false,
    }
}

fn determine_starting_record_id(channel_wide: &[u16], bookmark_file: &Path) -> u64 {
    match load_bookmark(bookmark_file) {
        Ok(Some(record_id)) => {
            info!(record_id, "resumed from bookmark");
            record_id
        }
        Ok(None) => {
            let record_id = most_recent_record_id(channel_wide).unwrap_or(0);
            info!(record_id, "starting from most recent event");
            record_id
        }
        Err(error) => {
            warn!(error = %error, "failed to read bookmark, starting from most recent");
            most_recent_record_id(channel_wide).unwrap_or(0)
        }
    }
}

fn open_forward_query(channel_wide: &[u16], after_record_id: u64) -> Option<EvtHandle> {
    let query_text = format!("*[System[EventRecordID > {}]]", after_record_id);
    let query_wide = encode_wide(&query_text);

    let query_handle = unsafe {
        EvtQuery(
            0,
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            EvtQueryChannelPath | EvtQueryForwardDirection,
        )
    };

    if query_handle == 0 {
        let error_code = unsafe { GetLastError() };
        warn!(code = error_code, "EvtQuery failed, retrying");
        return None;
    }
    Some(query_handle)
}

fn fetch_next_batch(query_handle: EvtHandle) -> FetchResult {
    let mut event_handles: [EvtHandle; EVT_NEXT_BATCH_SIZE] = [0; EVT_NEXT_BATCH_SIZE];
    let mut returned_count: u32 = 0;

    let call_succeeded = unsafe {
        EvtNext(
            query_handle,
            EVT_NEXT_BATCH_SIZE as u32,
            event_handles.as_mut_ptr(),
            EVT_NEXT_TIMEOUT_MS,
            0,
            &mut returned_count,
        )
    };

    if call_succeeded == 0 {
        let error_code = unsafe { GetLastError() };
        if error_code == ERROR_NO_MORE_ITEMS {
            return FetchResult::Exhausted;
        }
        return FetchResult::Error(error_code);
    }
    if returned_count == 0 {
        return FetchResult::Exhausted;
    }

    let returned_handles = event_handles[..returned_count as usize].to_vec();
    FetchResult::Events(returned_handles)
}

fn parse_event_from_handle(event_handle: EvtHandle) -> Option<SysmonEvent> {
    let render_result = render_event_xml(event_handle);
    close_handle(event_handle);

    let xml_text = match render_result {
        Ok(xml) => xml,
        Err(error) => {
            warn!(error = %error, "EvtRender failed");
            return None;
        }
    };

    match parse_event_xml(&xml_text) {
        Ok(event) => Some(event),
        Err(error) => {
            warn!(error = %error, "failed to parse sysmon event");
            None
        }
    }
}

fn render_event_xml(event_handle: EvtHandle) -> Result<String> {
    let required_size = probe_render_size(event_handle)?;
    let utf16_buffer = render_into_buffer(event_handle, required_size)?;
    Ok(String::from_utf16_lossy(&utf16_buffer))
}

fn probe_render_size(event_handle: EvtHandle) -> Result<u32> {
    let mut bytes_used: u32 = 0;
    let mut property_count: u32 = 0;

    unsafe {
        EvtRender(
            0,
            event_handle,
            EvtRenderEventXml,
            0,
            ptr::null_mut(),
            &mut bytes_used,
            &mut property_count,
        );
    }

    if bytes_used == 0 {
        return Err(anyhow!("EvtRender returned zero size"));
    }
    Ok(bytes_used)
}

fn render_into_buffer(event_handle: EvtHandle, required_bytes: u32) -> Result<Vec<u16>> {
    let mut byte_buffer = vec![0u8; required_bytes as usize];
    let mut bytes_used: u32 = 0;
    let mut property_count: u32 = 0;

    let call_succeeded = unsafe {
        EvtRender(
            0,
            event_handle,
            EvtRenderEventXml,
            byte_buffer.len() as u32,
            byte_buffer.as_mut_ptr() as *mut _,
            &mut bytes_used,
            &mut property_count,
        )
    };

    if call_succeeded == 0 {
        let error_code = unsafe { GetLastError() };
        return Err(anyhow!("EvtRender failed (code {error_code})"));
    }

    let utf16_units: Vec<u16> = byte_buffer
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    Ok(utf16_units)
}

fn most_recent_record_id(channel_wide: &[u16]) -> Option<u64> {
    let query_wide = encode_wide("*");
    let query_handle = unsafe {
        EvtQuery(
            0,
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if query_handle == 0 {
        return None;
    }

    let mut event_handles: [EvtHandle; 1] = [0; 1];
    let mut returned_count: u32 = 0;
    let _ = unsafe {
        EvtNext(
            query_handle,
            1,
            event_handles.as_mut_ptr(),
            EVT_NEXT_TIMEOUT_MS,
            0,
            &mut returned_count,
        )
    };

    let mut record_id = None;
    if returned_count >= 1 {
        if let Ok(xml) = render_event_xml(event_handles[0]) {
            if let Ok(event) = parse_event_xml(&xml) {
                record_id = Some(event.record_id);
            }
        }
        close_handle(event_handles[0]);
    }
    close_handle(query_handle);
    record_id
}

fn encode_wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn close_handle(handle: EvtHandle) {
    unsafe { EvtClose(handle) };
}

fn sleep_interruptible(total_duration: Duration, cancel_token: &CancellationToken) {
    let step = Duration::from_millis(SLEEP_STEP_MS);
    let mut remaining = total_duration;
    while remaining > Duration::ZERO && !cancel_token.is_cancelled() {
        let this_step = remaining.min(step);
        std::thread::sleep(this_step);
        remaining = remaining.saturating_sub(this_step);
    }
}

fn persist_bookmark_logging_errors(bookmark_file: &Path, last_record_id: u64) {
    if let Err(error) = save_bookmark(bookmark_file, last_record_id) {
        warn!(error = %error, "failed to persist bookmark");
    }
}

fn load_bookmark(bookmark_file: &Path) -> Result<Option<u64>> {
    if !bookmark_file.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(bookmark_file)
        .with_context(|| format!("reading bookmark {}", bookmark_file.display()))?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let record_id = trimmed
        .parse::<u64>()
        .with_context(|| format!("bookmark not a u64: {trimmed:?}"))?;
    Ok(Some(record_id))
}

fn save_bookmark(bookmark_file: &Path, record_id: u64) -> Result<()> {
    ensure_parent_directory(bookmark_file)?;
    let temporary_file = bookmark_file.with_extension("tmp");
    std::fs::write(&temporary_file, record_id.to_string())
        .with_context(|| format!("writing bookmark temp {}", temporary_file.display()))?;
    std::fs::rename(&temporary_file, bookmark_file)
        .with_context(|| format!("renaming bookmark to {}", bookmark_file.display()))?;
    Ok(())
}

fn ensure_parent_directory(file_path: &Path) -> Result<()> {
    let parent_directory: Option<PathBuf> = file_path.parent().map(Path::to_path_buf);
    if let Some(parent) = parent_directory {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(&parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    Ok(())
}
