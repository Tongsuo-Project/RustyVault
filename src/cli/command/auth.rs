use std::sync::Arc;

use clap::{Parser, Subcommand};
use dashmap::DashMap;
use lazy_static::lazy_static;
use sysexits::ExitCode;

use super::{auth_disable, auth_enable, auth_help, auth_list, auth_move};
use crate::{
    api::auth::LoginHandler,
    cli::command::CommandExecutor,
    modules::credential::{cert::cli::CertAuthCliHandler, userpass::cli::UsesPassCliHandler},
    EXIT_CODE_INSUFFICIENT_PARAMS,
};

lazy_static! {
    pub static ref LoginHandlers: DashMap<String, Arc<dyn LoginHandler>> = {
        let map: DashMap<String, Arc<dyn LoginHandler>> = DashMap::new();

        map.insert("userpass".into(), Arc::new(UsesPassCliHandler::default()));
        map.insert("cert".into(), Arc::new(CertAuthCliHandler::default()));

        map
    };
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Perform operator-specific tasks",
    long_about = r#"This command groups subcommands for interacting with RustyVault's auth methods.
Users can list, enable, disable, and get help for different auth methods.

To authenticate to RustyVault as a user or machine, use the "rvault login" command instead. 
This command is for interacting with the auth methods themselves, not authenticating to RustyVault.

List all enabled auth methods:

    $ rvault auth list

Enable a new auth method "userpass";

    $ rvault auth enable userpass

Get detailed help information about how to authenticate to a particular auth method:

    $ rvault auth help github"#
)]
pub struct Auth {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    List(auth_list::List),
    Enable(auth_enable::Enable),
    Disable(auth_disable::Disable),
    Move(auth_move::Move),
    Help(auth_help::Help),
}

impl Commands {
    pub fn execute(&mut self) -> ExitCode {
        return match self {
            Commands::List(list) => list.execute(),
            Commands::Enable(enable) => enable.execute(),
            Commands::Disable(disable) => disable.execute(),
            Commands::Move(mv) => mv.execute(),
            Commands::Help(help) => help.execute(),
        };
    }
}

impl Auth {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        if let Some(ref mut cmd) = &mut self.command {
            return cmd.execute();
        }

        EXIT_CODE_INSUFFICIENT_PARAMS
    }
}
