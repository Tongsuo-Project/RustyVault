use clap::Parser;
use derive_more::Deref;

use crate::{
    cli::{
        command::{self, CommandExecutor},
        util,
    },
    errors::RvError,
    modules::auth::AUTH_ROUTER_PREFIX,
};

#[derive(Parser, Deref)]
#[command(
    author,
    version,
    about = r#"Moves an existing auth method to a new path. Any leases from the old
auth method are revoked, but all configuration associated with the method
is preserved. It initiates the migration and intermittently polls its status,
exiting if a final state is reached.

This command works within or across namespaces, both source and destination paths
can be prefixed with a namespace heirarchy relative to the current namespace.

WARNING! Moving an auth method will revoke any leases from the old method.

Move the auth method at approle/ to generic/:

    $ rvault auth move approle/ generic/

Move the auth method at ns1/approle/ across namespaces to ns2/generic/,
where ns1 and ns2 are child namespaces of the current namespace:

    $ rvault auth move ns1/approle/ ns2/generic/"#
)]
pub struct Move {
    #[arg(index = 1, required = true, next_line_help = false, value_name = "SOURCE", help = r#"The path of source."#)]
    source: String,

    #[arg(
        index = 2,
        required = true,
        next_line_help = false,
        value_name = "DESTINATION",
        help = r#"The path of destination."#
    )]
    destination: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for Move {
    #[inline]
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let sys = client.sys();

        let mut from = util::ensure_trailing_slash(&self.source);
        if !from.starts_with(AUTH_ROUTER_PREFIX) {
            from = format!("{}{}", AUTH_ROUTER_PREFIX, from);
        }

        let mut to = util::ensure_trailing_slash(&self.destination);
        if !to.starts_with(AUTH_ROUTER_PREFIX) {
            to = format!("{}{}", AUTH_ROUTER_PREFIX, to);
        }

        match sys.remount(&from, &to) {
            Ok(ret) => match ret.response_status {
                200 | 204 => {
                    println!("Success! Finished moving auth method {} to {}.", from, to);
                }
                _ => ret.print_debug_info(),
            },
            Err(e) => eprintln!("Error moving auth method {} to {}: {}", from, to, e),
        }
        Ok(())
    }
}
