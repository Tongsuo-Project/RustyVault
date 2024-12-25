use clap::Parser;
use derive_more::Deref;
use sysexits::ExitCode;

use crate::{errors::RvError, cli::command, EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Prints the current state of RustyVault including whether it is sealed and if HA
mode is enabled. This command prints regardless of whether the Vault is sealed."#
)]
pub struct Status {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output_options: command::OutputOptions,
}

impl Status {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        return (self.main().is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_INSUFFICIENT_PARAMS);
    }

    pub fn main(&self) -> Result<(), RvError> {
        let (_code, value) = self.request_read("/v1/sys/seal-status")?;
        self.output_options.print_value(&value)?;
        Ok(())
    }
}
