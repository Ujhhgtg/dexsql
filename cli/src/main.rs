//! Command-line entry point for the DexSQL reimplementation.
//!
//! The command parser is deliberately kept independent of the future DEX and
//! SQL engines.  This lets the black-box compatibility work pin down command
//! behavior before we commit to an execution architecture.

mod cli;
mod query;

fn main() {
    if let Err(error) = cli::run(std::env::args_os().skip(1)) {
        if !error.to_string().is_empty() {
            eprintln!("Error: {error}");
        }
        std::process::exit(error.exit_code());
    }
}
