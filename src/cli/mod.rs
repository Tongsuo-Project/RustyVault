use clap::{Arg, ArgAction, ArgMatches, Command};
use sysexits::ExitCode;

pub mod command;
pub mod config;

/// Defines command line options
pub fn define_command_line_options(mut app: Command) -> Command {
    app = app.subcommands([
        Command::new("server").about("Start a rusty_vault server").arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                .num_args(1)
                .action(ArgAction::Set)
                .required(true)
                .help("[CONFIG] Path to a configuration file or directory of configuration files."),
        ),
        Command::new("status").about("Print seal and HA status"),
    ]);

    app
}

#[inline]
pub fn run(matches: &ArgMatches) -> ExitCode {
    match matches.subcommand() {
        Some(("server", server_matches)) => command::server::execute(&server_matches),
        Some(("status", status_matches)) => command::status::execute(&status_matches),
        _ => crate::EXIT_CODE_INSUFFICIENT_PARAMS,
    }
}
