use clap::{ArgMatches};
use sysexits::ExitCode;
use crate::{EXIT_CODE_OK, EXIT_CODE_INSUFFICIENT_PARAMS};
use crate::errors::RvError;

pub fn main() -> Result<(), RvError> {
    println!("status: ok");
    Ok(())
}

#[inline]
pub fn execute(_matches: &ArgMatches) -> ExitCode {
    return (main().is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_INSUFFICIENT_PARAMS);
}
