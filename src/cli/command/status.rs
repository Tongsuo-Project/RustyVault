use clap::ArgMatches;
use sysexits::ExitCode;

use crate::{errors::RvError, EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK};

pub fn main() -> Result<(), RvError> {
    println!("status: ok");
    Ok(())
}

#[inline]
pub fn execute(_matches: &ArgMatches) -> ExitCode {
    return (main().is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_INSUFFICIENT_PARAMS);
}
