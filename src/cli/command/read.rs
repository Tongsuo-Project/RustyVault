use clap::Parser;
use derive_more::Deref;
use clap::Args;

use crate::{errors::RvError, cli::command::{self, CommandExecutor}};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Reads data from RustyVault at the given path. This can be used to read secrets,
generate dynamic credentials, get configuration details, and more.

Read a secret from the static secrets engine:

  $ rvault read secret/my-secret

For a full list of examples and paths, please see the documentation that
corresponds to the secrets engine in use."#
)]
pub struct Read {
    #[arg(
        next_line_help = false,
        value_name = "PATH",
        help = r#"The path of secret."#
    )]
    path: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: LogicalOutputOptions,
}

#[derive(Args, Deref)]
#[group(required = false, multiple = true)]
pub struct LogicalOutputOptions {
    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        long_help = r#"Print only the field with the given name. Specifying this option will take precedence
over other formatting directives. The result will not have a trailing newline making
it ideal for piping to other processes."#,
    )]
    field: Option<String>,

    #[deref]
    #[command(flatten)]
    output: command::OutputOptions,
}

impl CommandExecutor for Read {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let logical = client.logical();

        match logical.read(&self.path) {
            Ok(ret) => {
                if ret.response_status == 200 {
                    self.output.print_secrets(ret.response_data.as_ref().unwrap(), self.output.field.as_deref())?;
                } else if ret.response_status == 204 {
                    println!("ok");
                } else if ret.response_status == 404 {
                    println!("No value found at {}", self.path);
                    return Err(RvError::ErrRequestNoData);
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("{}", e),
        }
        Ok(())
    }
}
