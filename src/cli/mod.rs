//! The `rusty_vault::cli` module is used to serve the RustyVault application.
//! This module basically accepts options from command-line and starts a server up.

use clap::{Parser, Subcommand};
use sysexits::ExitCode;

use crate::{VERSION, EXIT_CODE_INSUFFICIENT_PARAMS};

pub mod command;
pub mod config;

#[derive(Parser)]
#[command(
    version = VERSION,
    about = "A secure and high performance secret management software that is compatible with Hashicorp Vault."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Server(command::server::Server),
    Status(command::status::Status),
    Operator(command::operator::Operator),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        return match self {
            Commands::Server(server) => server.execute(),
            Commands::Status(status) => status.execute(),
            Commands::Operator(operator) => operator.execute(),
        }
    }
}

impl Cli {
    /// Do real jobs.
    #[inline]
    pub fn run(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
