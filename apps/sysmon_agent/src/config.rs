use std::path::PathBuf;
use std::time::Duration;

pub const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const CHANNEL_CAPACITY: usize = 4096;

pub const BATCH_SIZE: usize = 128;
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(10);
pub const API_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RETRIES: u32 = 5;
pub const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

pub const DROP_EVENT_IDS: &[u32] = &[];

pub const CMDLINE_FIELDS: &[&str] = &["CommandLine", "ParentCommandLine", "OriginalFileName"];

pub const SECRET_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)(--password|-password|/password|--pass|-pass|/pass)([=\s:])\S+",
        "$1$2[REDACTED]",
    ),
    (r"(?i)(--token|-token|/token)([=\s:])\S+", "$1$2[REDACTED]"),
    (
        r"(?i)\b(api[-_]?key|apikey|access[-_]?key)([=\s:])\S+",
        "$1$2[REDACTED]",
    ),
    (r"(?i)\b(secret|credential)([=\s:])\S+", "$1$2[REDACTED]"),
    (r"(?i)(bearer|authorization:)(\s+)\S+", "$1$2[REDACTED]"),
    (r"(?i)\b(password|pwd)(=)[^;\s]+", "$1$2[REDACTED]"),
];

pub fn bookmark_path() -> PathBuf {
    if let Some(p) = std::env::var_os("PROGRAMDATA") {
        let mut pb = PathBuf::from(p);
        pb.push("LOTL-Analyzer");
        pb.push("sysmon_agent");
        pb.push("bookmark");
        return pb;
    }
    PathBuf::from("sysmon_agent.bookmark")
}
