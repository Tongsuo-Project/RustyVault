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
    output: command::OutputOptions,
}

impl Status {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        return (self.main().is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_INSUFFICIENT_PARAMS);
    }

    pub fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        match sys.seal_status() {
            Ok(ret) => {
                if ret.response_status == 200 {
                    self.output.print_value(ret.response_data.as_ref().unwrap())?;
                } else if ret.response_status == 204 {
                    println!("ok");
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{}", e),
        }
        Ok(())
    }
}
