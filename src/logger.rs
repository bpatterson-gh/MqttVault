#[cfg(test)]
mod test {
    use crate::logger::{Logger, SILENT, VERBOSE};
    use std::sync::atomic::Ordering;

    #[test]
    fn logger_modes() {
        // Default mode - don't show info, show errors
        SILENT.store(false, Ordering::Relaxed);
        VERBOSE.store(false, Ordering::Relaxed);
        assert_eq!(Logger::should_log_info(), false);
        assert_eq!(Logger::should_log_error(), true);

        // Silent mode - don't show info or errors
        SILENT.store(true, Ordering::Relaxed);
        VERBOSE.store(false, Ordering::Relaxed);
        assert_eq!(Logger::should_log_info(), false);
        assert_eq!(Logger::should_log_error(), false);

        // Verbose mode - show info and errors
        SILENT.store(false, Ordering::Relaxed);
        VERBOSE.store(true, Ordering::Relaxed);
        assert_eq!(Logger::should_log_info(), true);
        assert_eq!(Logger::should_log_error(), true);

        // Silent + Verbose mode - show info, don't show errors
        SILENT.store(true, Ordering::Relaxed);
        VERBOSE.store(true, Ordering::Relaxed);
        assert_eq!(Logger::should_log_info(), true);
        assert_eq!(Logger::should_log_error(), false);
    }
}

use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use time::{OffsetDateTime, UtcOffset};

static SILENT: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static UTC_OFFSET: RwLock<UtcOffset> = RwLock::new(UtcOffset::UTC);

pub struct Logger {}
impl Logger {
    // Set the logging mode and try to determine the time zone
    pub fn init(silent: bool, verbose: bool) {
        SILENT.store(silent, Ordering::Relaxed);
        VERBOSE.store(verbose, Ordering::Relaxed);
        match UtcOffset::current_local_offset() {
            Ok(offset) => match UTC_OFFSET.write() {
                Ok(mut data) => *data = offset,
                Err(_) => (),
            },
            Err(_) => (),
        }
    }

    // Return true if information should be logged
    fn should_log_info() -> bool {
        VERBOSE.load(Ordering::Relaxed)
    }

    // Return true if errors should be logged
    fn should_log_error() -> bool {
        !SILENT.load(Ordering::Relaxed)
    }

    // Generate a timestamp string for logs
    fn timestamp() -> OffsetDateTime {
        match UTC_OFFSET.read() {
            Ok(data) => OffsetDateTime::now_utc().to_offset(*data),
            Err(_) => OffsetDateTime::now_utc(),
        }
    }

    // Maybe log information
    pub fn log_info<T>(message: T)
    where
        T: Display,
    {
        if Logger::should_log_info() {
            println!("[{}] {}", Logger::timestamp(), message);
        }
    }

    // Maybe log an error
    pub fn log_error<T>(error: T)
    where
        T: Display,
    {
        if Logger::should_log_error() {
            eprintln!("[{}] {}", Logger::timestamp(), error);
        }
    }
}

//  Copyright ©️ Bruce Patterson 2022-2024

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
