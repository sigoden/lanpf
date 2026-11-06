//! Small shared helpers.

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `2m ago`-style relative timestamp used by the tables.
pub fn relative_time(ts: i64) -> String {
    if ts <= 0 {
        return "-".into();
    }
    let now = now_ts();
    if ts > now {
        return "just now".into();
    }
    relative_delta(now - ts)
}

pub fn relative_delta(secs: i64) -> String {
    if secs < 2 {
        "just now".into()
    } else if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// `1h 02m 03s`-style uptime.
pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d {hours:02}h {minutes:02}m")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Simple deterministic jitter derived from a UUID (avoids pulling in a RNG
/// just for reconnect backoff).
pub fn jitter_millis(seed: &uuid::Uuid) -> u64 {
    let bytes = seed.as_bytes();
    (u16::from_be_bytes([bytes[14], bytes[15]]) as u64) % 250
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times() {
        let now = now_ts();
        assert_eq!(relative_time(0), "-");
        assert_eq!(relative_time(now - 5), "5s ago");
        assert_eq!(relative_time(now - 120), "2m ago");
        assert_eq!(relative_time(now - 7200), "2h ago");
        assert_eq!(relative_time(now - 172_800), "2d ago");
    }

    #[test]
    fn uptimes() {
        assert_eq!(format_uptime(5), "5s");
        assert_eq!(format_uptime(65), "1m 05s");
        assert_eq!(format_uptime(3665), "1h 01m 05s");
        assert_eq!(format_uptime(90_000), "1d 01h 00m");
    }

    #[test]
    fn bytes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }
}
