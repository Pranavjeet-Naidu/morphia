use morphia::cli;
use std::process;

fn main() {
    if let Err(e) = cli::command::run() {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}