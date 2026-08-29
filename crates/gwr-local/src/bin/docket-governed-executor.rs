//! Docket-owned local process host for governed-executor transport V1.

use gwr_local::executor_process;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [operation, config] = arguments.as_slice() else {
        return Err("usage: docket-governed-executor plan-id|execute|reconcile CONFIG".to_owned());
    };
    let config = executor_process::config_path(config)?;
    match operation.as_str() {
        "plan-id" => {
            println!("{}", executor_process::plan_id(&config)?);
            Ok(())
        }
        "execute" => {
            let dispatch = executor_process::read_dispatch_stdin()?;
            let outcome = executor_process::execute(&config, &dispatch)?;
            executor_process::write_outcome_stdout(&outcome)
        }
        "reconcile" => {
            let dispatch = executor_process::read_dispatch_stdin()?;
            let outcome = executor_process::reconcile(&config, &dispatch)?;
            executor_process::write_outcome_stdout(&outcome)
        }
        _ => Err("usage: docket-governed-executor plan-id|execute|reconcile CONFIG".to_owned()),
    }
}
