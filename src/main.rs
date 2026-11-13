#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod config;
mod engine;
mod gre;
mod keepalive;
mod packet;
mod status;
mod sys;

use std::process::ExitCode;

use config::{collect_env_map, parse_cli_and_env, print_help, CliOutcome};
use status::{evaluate_healthcheck, read_status_raw};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let env_vars = collect_env_map();

    let outcome = match parse_cli_and_env(&args, &env_vars) {
        Ok(o) => o,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    match outcome {
        CliOutcome::Help => {
            print_help();
            ExitCode::SUCCESS
        }
        CliOutcome::Version => {
            println!("easygre {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        CliOutcome::Status { status_file } => match read_status_raw(&status_file) {
            Ok((_ts, lines)) => {
                for line in lines {
                    println!("{line}");
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
        CliOutcome::Healthcheck { status_file } => match evaluate_healthcheck(&status_file, 30) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("unhealthy: {err}");
                ExitCode::from(1)
            }
        },
        CliOutcome::Run(app_cfg) => match engine::run_daemon(app_cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::from(1)
            }
        },
    }
}
