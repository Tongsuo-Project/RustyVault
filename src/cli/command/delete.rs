use clap::Parser;
use derive_more::Deref;

use crate::{errors::RvError, cli::command::{self, CommandExecutor}};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Deletes secrets and configuration from RustyVault at the given path. The behavior
of "delete" is delegated to the backend corresponding to the given path.

Remove data in the status secret backend:

  $ vault delete secret/my-secret"#
)]
pub struct Delete {
    #[arg(
        next_line_help = false,
        value_name = "PATH",
    )]
    path: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Delete {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let logical = client.logical();

        match logical.delete(&self.path, None) {
            Ok(ret) => {
                if ret.response_status != 200 || ret.response_status != 204{
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{}", e),
        }
        Ok(())
    }
}
