//Modified simple_logger to add thread identification
//! A logger that prints all messages with a readable output format.

use super::innermain::hash;
use chrono::prelude::*;
use log::{Level, Log, Metadata, Record, SetLoggerError};
use std::io::Write;

#[cfg(not(windows))]
use std::os::unix::io::{IntoRawFd,FromRawFd};
#[cfg(not(windows))]
pub type SFd = std::os::unix::io::RawFd;

#[cfg(windows)]
use std::os::windows::io::{IntoRawHandle,FromRawHandle};
#[cfg(windows)]
pub type SFd = usize;

struct SfLogger {
    level: Level,
    sfonly: bool,
    fout: SFd,
}
impl SfLogger {
    fn get_file(&self) -> std::fs::File {
        unsafe {
            #[cfg(windows)]
            return std::fs::File::from_raw_handle(self.fout as std::os::windows::io::RawHandle);
            #[cfg(not(windows))]
            return std::fs::File::from_raw_fd(self.fout);
        }
    }
}

impl Log for SfLogger {
    fn enabled(&self, meta: &Metadata) -> bool {
        meta.level() <= self.level && (!self.sfonly || meta.target().starts_with("schadn"))
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let t = std::thread::current();
            let mut fout = self.get_file();
            writeln!(
                fout,
                "{}\t{:<5}\t{:08X}\t{}\t{}:{}\t{}",
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                record.level().to_string(),
                hash(&t.id()) as u32,
                t.name().unwrap_or("        "),
                record.file().unwrap_or_default(),
                record.line().unwrap_or_default(),
                record.args()
            ).unwrap_or_else(|e| eprintln!("{}", e));
            #[cfg(windows)]
            fout.into_raw_handle();
            #[cfg(not(windows))]
            fout.into_raw_fd();
        }
    }

    fn flush(&self) {}
}

/// Initializes the global logger with a SfLogger instance with
/// `max_log_level` set to a specific log level.
///
/// ```
/// # fn main() {
/// sflogger::init_with_level(log::Level::Warn, true).unwrap();
///
/// warn!("This is an example message.");
/// info!("This message will not be logged.");
/// # }
/// ```
pub fn init_with_level(level: Level, sfonly: bool, fout: SFd) -> Result<(), SetLoggerError> {
    let logger = SfLogger { level, sfonly, fout };
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

pub fn init_stdio_with_level(level: Level, sfonly: bool) -> Result<(), SetLoggerError> {
    #[cfg(not(windows))]
    use std::os::unix::io::AsRawFd;
    #[cfg(not(windows))]
    let outh = std::io::stdout().as_raw_fd();

    #[cfg(windows)]
    use std::os::windows::io::AsRawHandle;
    #[cfg(windows)]
    let outh = std::io::stdout().as_raw_handle() as usize;

    init_with_level(level, sfonly, outh)

}

