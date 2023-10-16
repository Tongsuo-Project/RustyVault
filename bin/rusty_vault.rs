use std::process::ExitCode;

use clap::{Command};
use rusty_vault::cli;

fn main() -> ExitCode {
    let mut app = Command::new("rusty_vault")
        .version(rusty_vault::VERSION)
        .help_expected(true)
        .disable_colored_help(false)
        .max_term_width(100)
        .about("A self-controlled, secure, and high-performance open-source software for key management that is compatible with Vault.");
    app = cli::define_command_line_options(app);
    let mut app_cloned = app.clone();

    let matches = app.get_matches();
    let ret = cli::run(&matches);
    if !ret.is_success() {
        let _ = app_cloned.print_long_help();
    }

    ret.into()
}
