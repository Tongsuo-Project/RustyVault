//! This is the 'application' part of RustyVault, a Rust replica of Hashicorp Vault.
//! The code here will be built into a binary (with a main function which utilize the
//! `rusty_vault::cli` module to run the application).
//!
//! This document is generated for the application part of RustyVault. But we don't organize the
//! real doc here, please go to RustyVault's [documentation site]
//!
//! [documentation site]: https://www.tongsuo.net

use std::process::ExitCode;

use clap::Command;
use rusty_vault::cli;

fn main() -> ExitCode {
    let mut app = Command::new("rusty_vault")
        .version(rusty_vault::VERSION)
        .help_expected(true)
        .disable_colored_help(false)
        .max_term_width(100)
        .about("A secure and high performance secret management software that is compatible with Hashicorp Vault.");
    app = cli::define_command_line_options(app);
    let mut app_cloned = app.clone();

    let matches = app.get_matches();
    let ret = cli::run(&matches);
    if !ret.is_success() {
        let _ = app_cloned.print_long_help();
    }

    ret.into()
}
