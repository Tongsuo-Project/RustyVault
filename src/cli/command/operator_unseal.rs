use clap::Parser;
use derive_more::Deref;
use sysexits::ExitCode;

use crate::{errors::RvError, cli::command, EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK};

#[derive(Parser, Deref)]
#[command(author, version, about = r#"Unseals the RustyVault server."#)]
pub struct Unseal {
    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl Unseal {
    #[inline]
    pub fn execute(&self) -> ExitCode {
        return (self.main().is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_INSUFFICIENT_PARAMS);
    }

    pub fn main(&self) -> Result<(), RvError> {
        println!("unseal: ok");
        Ok(())
    }
}
