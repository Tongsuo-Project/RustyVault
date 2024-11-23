use clap::Parser;
use derive_more::Deref;
use serde_json::{Value, Map};

use crate::{errors::RvError, cli::command::{self, CommandExecutor}};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Writes data to RustyVault at the given path. The data can be credentials, secrets,
configuration, or arbitrary data. The specific behavior of this command is determined
at the thing mounted at the path.

Data is specified as "key=value" pairs. If the value begins with an "@", then it is
loaded from a file. If the value is "-", RustyVault will read the value from stdin.

Persist data in the generic secrets engine:

  $ rvault write secret/my-secret foo=bar

Upload an AWS IAM policy from a file on disk:

  $ rvault write aws/roles/ops policy=@policy.json"#
)]
pub struct Write {
    #[arg(
        index = 1,
        required = true,
        next_line_help = false,
        value_name = "PATH",
        help = r#"The path of secret."#
    )]
    path: String,

    #[clap(
        index = 2,
        value_name = "DATA K=V...",
        help = r#"Data is specified as "key=value" pairs. If the value begins with an "@", then
it is loaded from a file. If the value is "-", Vault will read the value from
stdin."#
    )]
    data: Vec<String>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Write {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let logical = client.logical();

        let mut post_data: Map<String, Value> = Map::new();
        for pair in &self.data {
            let args: Vec<&str> = pair.split('=').collect();
            if args.len() == 2 {
                post_data.insert(args[0].to_string(), Value::String(args[1].to_string()));
            } else {
                eprintln!("Invalid pair: {}", pair);
            }
        }

        match logical.write(&self.path, Some(post_data)) {
            Ok(ret) => {
                if ret.response_status == 200 || ret.response_status == 204 {
                    println!("Success! Data written to: {}", self.path);
                } else if ret.response_status == 404 {
                    println!("Error writing data to {}: Error making API request.", self.path);
                    ret.print_debug_info();
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
