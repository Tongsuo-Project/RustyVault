use std::io::{self, Write};

use rpassword::read_password;
use clap::Parser;
use derive_more::Deref;
use sysexits::ExitCode;

use crate::{
    errors::RvError,
    cli::command::{self, CommandExecutor},
    EXIT_CODE_INSUFFICIENT_PARAMS,
    EXIT_CODE_OK,
};

#[derive(Parser, Deref)]
#[command(author, version, about = r#"Provide a portion of the root key to unseal a RustyVault server.
RustyVault starts in a sealed state. It cannot perform operations until it is unsealed.
This command accepts a portion of the root key (an "unseal key").

The unseal key can be supplied as an argument to the command, but this is
not recommended as the unseal key will be available in your history:

  $ rvault operator unseal 05ce1abc1f913de5407c86869bb298e5645748e01bdfd14c7ac43c05c4bc204b01

Instead, run the command with no arguments and it will prompt for the key:

  $ rvault operator unseal
  Key (will be hidden): 05ce1abc1f913de5407c86869bb298e5645748e01bdfd14c7ac43c05c4bc204b01"#)]
pub struct Unseal {
    #[arg(
        next_line_help = false,
        value_name = "KEY",
        help = r#"A portion of the root key to unseal a Vault server."#
    )]
    unseal_key: Option<String>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Unseal {
    #[inline]
    fn execute(&mut self) -> ExitCode {
        match self.main() {
            Ok(_) => EXIT_CODE_OK,
            Err(e) => {
                eprintln!("Error: {}", e);
                EXIT_CODE_INSUFFICIENT_PARAMS
            }
        }
    }

    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();


        let key = if let Some(unseal_key) = &self.unseal_key {
            unseal_key.clone()
        } else {
            let mut writer = io::stdout();
            write!(writer, "Unseal Key (will be hidden): ")?;
            writer.flush()?;
            let value = read_password().expect("Failed to read password");
            writeln!(writer)?;
            value
        };

        match sys.unseal(&key) {
            Ok(ret) => {
                if ret.response_status == 200 {
                    self.output.print_value(ret.response_data.as_ref().unwrap(), true)?;
                } else if ret.response_status == 204 {
                    println!("ok");
                } else {
                    ret.print_debug_info();
                }
            }
            Err(e) => eprintln!("Error sealing: {}", e),
        }
        Ok(())
    }
}
