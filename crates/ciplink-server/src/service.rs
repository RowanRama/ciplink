//! Runs the server at Windows startup as a Task Scheduler task (no extra software needed).
//!
//! The task runs `<launcher> service run`, which serves until stopped and starts the server again if it ever fails.
//! Installing and removing need an elevated (administrator) terminal.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Between a server failure and the next start.
const RESTART_DELAY: Duration = Duration::from_secs(5);

const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>ciplink-server: serves PLC tag values to web apps</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The task definition; `launcher` is the program and its first arguments (the exe, or python -m ciplink.server).
pub fn task_xml(launcher: &[String], config: &Path, log_file: &Path) -> String {
    let (command, prefix) = launcher
        .split_first()
        .map_or(("ciplink-server", &[][..]), |(c, p)| (c.as_str(), p));
    let mut arguments: Vec<String> = prefix.to_vec();
    arguments.push(format!(
        "service run --config \"{}\" --log-file \"{}\"",
        config.display(),
        log_file.display()
    ));
    TASK_XML
        .replace("{command}", &escape(command))
        .replace("{arguments}", &escape(&arguments.join(" ")))
        .replace(
            "{workdir}",
            &escape(
                &config
                    .parent()
                    .unwrap_or(Path::new("."))
                    .display()
                    .to_string(),
            ),
        )
}

fn schtasks(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("schtasks").args(args).output()
}

fn print_output(output: &std::process::Output) {
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    println!(
        "{}",
        if out.trim().is_empty() {
            err.trim()
        } else {
            out.trim()
        }
    );
}

fn code(output: &std::process::Output) -> u8 {
    u8::try_from(output.status.code().unwrap_or(1)).unwrap_or(1)
}

/// Registers and starts the task.
pub fn install(name: &str, launcher: &[String], config: &Path, log_file: &Path) -> u8 {
    let xml = task_xml(launcher, config, log_file);
    let path = std::env::temp_dir().join(format!("ciplink-server-task-{}.xml", std::process::id()));
    let mut bytes = vec![0xFF, 0xFE]; // UTF-16 LE with BOM, as the XML says
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    if let Err(err) = std::fs::write(&path, bytes) {
        println!("{}: {err}", path.display());
        return 1;
    }
    let path_text = path.display().to_string();
    let result = schtasks(&["/Create", "/TN", name, "/XML", &path_text, "/F"]);
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(output) if output.status.success() => {
            let _ = schtasks(&["/Run", "/TN", name]);
            println!(
                "Installed and started task '{name}'. It starts at every boot; logs go to {}",
                log_file.display()
            );
            0
        }
        Ok(output) => {
            print_output(&output);
            println!(
                "Installing needs an administrator terminal: right-click Terminal, 'Run as administrator'."
            );
            code(&output)
        }
        Err(err) => {
            println!("cannot run schtasks: {err}");
            1
        }
    }
}

/// Ends and deletes the task.
pub fn remove(name: &str) -> u8 {
    let _ = schtasks(&["/End", "/TN", name]);
    match schtasks(&["/Delete", "/TN", name, "/F"]) {
        Ok(output) => {
            print_output(&output);
            code(&output)
        }
        Err(err) => {
            println!("cannot run schtasks: {err}");
            1
        }
    }
}

/// Prints the task's state.
pub fn status(name: &str) -> u8 {
    match schtasks(&["/Query", "/TN", name, "/V", "/FO", "LIST"]) {
        Ok(output) => {
            print_output(&output);
            code(&output)
        }
        Err(err) => {
            println!("cannot run schtasks: {err}");
            1
        }
    }
}

/// Calls `serve` again whenever it fails, `RESTART_DELAY` later; returns when it ends normally (Ctrl+C).
pub fn supervise(mut serve: impl FnMut() -> Result<(), String>) {
    loop {
        match serve() {
            Ok(()) => return,
            Err(err) => log::error!(
                "server failed: {err}; starting it again in {} s",
                RESTART_DELAY.as_secs()
            ),
        }
        std::thread::sleep(RESTART_DELAY);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn task_runs_the_launcher_with_the_config() {
        let launcher = vec![
            "C:\\Python\\python.exe".to_owned(),
            "-m".into(),
            "ciplink.server".into(),
        ];
        let xml = task_xml(
            &launcher,
            Path::new("C:\\TS\\a&b.toml"),
            Path::new("C:\\TS\\ts.log"),
        );
        assert!(xml.contains("<Command>C:\\Python\\python.exe</Command>"));
        assert!(xml.contains(
            "<Arguments>-m ciplink.server service run --config \"C:\\TS\\a&amp;b.toml\" --log-file \"C:\\TS\\ts.log\"</Arguments>"
        ));
        assert!(xml.contains("<WorkingDirectory>C:\\TS</WorkingDirectory>"));
    }

    #[test]
    fn supervise_restarts_after_a_failure_only() {
        let mut calls = 0;
        supervise(|| {
            calls += 1;
            Ok(())
        });
        assert_eq!(calls, 1);
    }
}
