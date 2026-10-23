use std::process::ExitCode;

fn main() -> ExitCode {
    match ciplink_server::cli::main(std::env::args_os()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
