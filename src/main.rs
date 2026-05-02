mod app;
mod cli;
mod config;
mod extract;
mod output;
mod search;
mod spec;

use std::{env::args_os, process::ExitCode};

fn main() -> ExitCode {
    match cli::Command::parse(args_os().skip(1)) {
        Ok(cli::Command::Help) => {
            print!("{}", cli::usage());
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Run(options)) => match app::run(&options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("forsmost: {message}");
                ExitCode::FAILURE
            }
        },
        Ok(cli::Command::Version) => {
            println!("{}", cli::version());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("forsmost: {message}");
            eprintln!("Try `forsmost -h` for more information.");
            ExitCode::FAILURE
        }
    }
}
