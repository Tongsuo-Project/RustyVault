extern crate diesel;

pub mod cli;
pub mod context;
pub mod core;
pub mod errors;
pub mod handler;
pub mod http;
pub mod logical;
pub mod module_manager;
pub mod modules;
pub mod mount;
pub mod router;
pub mod shamir;
pub mod storage;
pub mod utils;
pub mod schema;

/// Exit ok
pub const EXIT_CODE_OK: sysexits::ExitCode = sysexits::ExitCode::Ok;
/// Exit code when server exits unexpectedly
pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when server aborted
pub const EXIT_CODE_SERVER_ABORTED: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when loading configuration from file fails
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
/// Exit code when insufficient params are passed via CLI
pub const EXIT_CODE_INSUFFICIENT_PARAMS: sysexits::ExitCode = sysexits::ExitCode::Usage;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// rusty_vault version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
