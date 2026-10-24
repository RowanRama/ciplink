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
    install_with(
        name,
        launcher,
        config,
        log_file,
        &mut schtasks,
        &mut std::io::stdout(),
    )
}

/// `install` with the schtasks call and the console as parameters, for tests.
fn install_with(
    name: &str,
    launcher: &[String],
    config: &Path,
    log_file: &Path,
    schtasks: &mut dyn FnMut(&[&str]) -> std::io::Result<std::process::Output>,
    out: &mut dyn std::io::Write,
) -> u8 {
    let xml = task_xml(launcher, config, log_file);
    let path = std::env::temp_dir().join(format!("ciplink-server-task-{}.xml", std::process::id()));
    let mut bytes = vec![0xFF, 0xFE]; // UTF-16 LE with BOM, as the XML says
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    if let Err(err) = std::fs::write(&path, bytes) {
        let _ = writeln!(out, "{}: {err}", path.display());
        return 1;
    }
    let path_text = path.display().to_string();
    let result = schtasks(&["/Create", "/TN", name, "/XML", &path_text, "/F"]);
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(output) if output.status.success() => {
            let _ = schtasks(&["/Run", "/TN", name]);
            let _ = writeln!(
                out,
                "Installed and started task '{name}'. It starts at every boot; logs go to {}",
                log_file.display()
            );
            0
        }
        Ok(output) => {
            // the error first, as schtasks puts it on stderr
            let err = String::from_utf8_lossy(&output.stderr);
            let text = String::from_utf8_lossy(&output.stdout);
            let shown = if err.trim().is_empty() {
                text.trim()
            } else {
                err.trim()
            };
            let _ = writeln!(out, "{shown}");
            let _ = writeln!(
                out,
                "Installing needs an administrator terminal: right-click Terminal, 'Run as administrator'."
            );
            code(&output)
        }
        Err(err) => {
            let _ = writeln!(out, "cannot run schtasks: {err}");
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
pub fn supervise(serve: impl FnMut() -> Result<(), String>) {
    supervise_with(serve, std::thread::sleep);
}

fn supervise_with(mut serve: impl FnMut() -> Result<(), String>, mut sleep: impl FnMut(Duration)) {
    loop {
        match serve() {
            Ok(()) => return,
            Err(err) => log::error!(
                "server failed: {err}; starting it again in {} s",
                RESTART_DELAY.as_secs()
            ),
        }
        sleep(RESTART_DELAY);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)] // Windows paths: elsewhere `C:\TS\a.toml` has no parent folder
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
    // ---- ports of ciplink-tagserver's tests/test_service.py

    fn output(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(code as u32)
        };
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(code << 8)
        };
        std::process::Output {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn task_xml_runs_the_supervisor_at_boot_as_system() {
        let dir = Path::new("C:\\Tag Server");
        let config = dir.join("tagserver.toml");
        let log_file = dir.join("tagserver.log");
        let launcher = vec![
            "C:\\Py & Co\\python.exe".to_owned(),
            "-m".into(),
            "ciplink.server".into(),
        ];
        let xml = task_xml(&launcher, &config, &log_file);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"));
        assert!(xml.contains("<Triggers>\n    <BootTrigger>"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        // escaped in the XML, intact once parsed
        assert!(xml.contains("<Command>C:\\Py &amp; Co\\python.exe</Command>"));
        assert!(xml.contains(&format!(
            "<Arguments>-m ciplink.server service run --config \"{}\" --log-file \"{}\"</Arguments>",
            config.display(),
            log_file.display()
        )));
        assert!(xml.contains(&format!(
            "<WorkingDirectory>{}</WorkingDirectory>",
            dir.display()
        )));
    }

    #[test]
    fn install_creates_and_starts_the_task() {
        let dir = crate::testing::TempDir::new();
        let mut calls: Vec<Vec<String>> = Vec::new();
        let mut schtasks = |args: &[&str]| {
            calls.push(args.iter().map(|a| (*a).to_owned()).collect());
            if args[0] == "/Create" {
                let bytes = std::fs::read(args[4]).unwrap();
                assert_eq!(bytes[..2], [0xFF, 0xFE]);
                let units: Vec<u16> = bytes[2..]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let text = String::from_utf16(&units).unwrap();
                assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"));
            }
            Ok(output(0, "SUCCESS", ""))
        };
        let mut out = Vec::new();
        let code = install_with(
            "ts",
            &["ciplink-server".to_owned()],
            &dir.path().join("c.toml"),
            &dir.path().join("c.log"),
            &mut schtasks,
            &mut out,
        );
        assert_eq!(code, 0);
        let firsts: Vec<&str> = calls.iter().map(|c| c[0].as_str()).collect();
        assert_eq!(firsts, ["/Create", "/Run"]);
        assert_eq!(calls[0][..3], ["/Create", "/TN", "ts"]);
        assert_eq!(calls[0].last().unwrap(), "/F");
    }

    #[test]
    fn install_without_admin_reports_it() {
        let dir = crate::testing::TempDir::new();
        let mut schtasks = |_: &[&str]| Ok(output(1, "", "ERROR: Access is denied."));
        let mut out = Vec::new();
        let code = install_with(
            "ts",
            &["ciplink-server".to_owned()],
            &dir.path().join("c.toml"),
            &dir.path().join("c.log"),
            &mut schtasks,
            &mut out,
        );
        assert_eq!(code, 1);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Access is denied") && out.contains("administrator"));
    }

    /// The Python supervisor also restarts after a normal return; here a normal return is Ctrl+C, which ends it.
    #[test]
    fn supervise_restarts_after_a_failure() {
        let mut runs = 0;
        let mut sleeps = Vec::new();
        supervise_with(
            || {
                runs += 1;
                match runs {
                    1 => Err("boom".into()),
                    2 => Err("cannot listen on 127.0.0.1:8765".into()), // the port is taken
                    _ => Ok(()),
                }
            },
            |d| sleeps.push(d),
        );
        assert_eq!(runs, 3);
        assert_eq!(sleeps, [RESTART_DELAY; 2]);
    }
}
