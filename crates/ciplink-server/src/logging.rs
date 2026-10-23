//! A small logger for the server: INFO and above, to stderr or to a file rotated at 10 MB with 5 kept.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

const MAX_BYTES: u64 = 10_000_000;
const BACKUPS: u32 = 5;

struct FileLog {
    path: PathBuf,
    file: File,
    size: u64,
}

struct Logger {
    file: Mutex<Option<FileLog>>,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {} {}: {}\n",
            timestamp(),
            record.level(),
            record.target(),
            record.args()
        );
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        match file.as_mut() {
            Some(log) => {
                if log.size + line.len() as u64 > MAX_BYTES {
                    rotate(log);
                }
                if log.file.write_all(line.as_bytes()).is_ok() {
                    log.size += line.len() as u64;
                }
            }
            None => eprint!("{line}"),
        }
    }

    fn flush(&self) {
        if let Some(log) = self
            .file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            let _ = log.file.flush();
        }
    }
}

/// `name.1` ... `name.5` as Python's RotatingFileHandler names them.
fn backup(path: &Path, n: u32) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

fn rotate(log: &mut FileLog) {
    let _ = std::fs::remove_file(backup(&log.path, BACKUPS));
    for n in (1..BACKUPS).rev() {
        let _ = std::fs::rename(backup(&log.path, n), backup(&log.path, n + 1));
    }
    let _ = log.file.flush();
    let _ = std::fs::rename(&log.path, backup(&log.path, 1));
    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log.path) {
        log.file = file;
        log.size = 0;
    }
}

/// `2026-10-23 14:17:33.768Z` (UTC).
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        now.subsec_millis()
    )
}

/// Installs the logger (once per process; later calls only fail if the file can't be opened).
pub fn init(file: Option<&Path>) -> Result<(), String> {
    let file = match file {
        None => None,
        Some(path) => {
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            let handle = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let size = handle.metadata().map_or(0, |m| m.len());
            Some(FileLog {
                path: path.to_owned(),
                file: handle,
                size,
            })
        }
    };
    let logger = Box::leak(Box::new(Logger {
        file: Mutex::new(file),
    }));
    if log::set_logger(logger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
    Ok(())
}
