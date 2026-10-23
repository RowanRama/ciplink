//! The command line: `ciplink-server run | dump-tags | types | service`.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use crate::{codegen, config, logging, service};

#[derive(Parser)]
#[command(
    name = "ciplink-server",
    version,
    about = "Serves PLC tag values to web apps over a WebSocket"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve tag values over a WebSocket.
    Run {
        #[arg(long, default_value = "tagserver.toml")]
        config: PathBuf,
        /// Serve fake values from each PLC's mock_tags file.
        #[arg(long)]
        mock: bool,
        /// Write logs to this file (rotated at 10 MB, 5 kept) instead of the console.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Run at Windows startup (install and remove need an administrator terminal).
    Service {
        #[arg(value_enum)]
        action: ServiceAction,
        #[arg(long, default_value = "tagserver.toml")]
        config: PathBuf,
        /// Task Scheduler task name.
        #[arg(long, default_value = "ciplink-server")]
        name: String,
        /// Default: tagserver.log next to the config.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Write a PLC's tag list as a mock_tags file.
    DumpTags {
        #[arg(long, default_value = "tagserver.toml")]
        config: PathBuf,
        #[arg(long)]
        plc: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the typed tag tree of a running server as a TypeScript module.
    Types {
        #[arg(long, default_value = "http://127.0.0.1:8765")]
        url: String,
        #[arg(long)]
        token: String,
        /// Repeat for several PLCs; names are then qualified as PLC/tag.
        #[arg(long)]
        plc: Vec<String>,
        /// tree: interfaces and a tagTree const per PLC; names: the 0.2 union of tag names.
        #[arg(long, value_enum, default_value_t = Format::Tree)]
        format: Format,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ServiceAction {
    Install,
    Remove,
    Status,
    Run,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Tree,
    Names,
}

/// The CLI on these arguments (the program name first), as the `ciplink-server` executable.
pub fn main(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<u8, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    main_as(args, &[exe.display().to_string()])
}

/// The CLI on these arguments; `launcher` is how a Task Scheduler task starts this CLI again (the program and its
/// first arguments, e.g. `python -m ciplink.server` for the Python package).
pub fn main_as(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    launcher: &[String],
) -> Result<u8, String> {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return Ok(if err.use_stderr() { 2 } else { 0 });
        }
    };
    match cli.command {
        Command::Run {
            config,
            mock,
            log_file,
        } => {
            logging::init(log_file.as_deref())?;
            crate::run(&config, mock)?;
        }
        Command::Service {
            action,
            config,
            name,
            log_file,
        } => {
            let config = std::path::absolute(&config).map_err(|e| e.to_string())?;
            let log_file = match log_file {
                Some(f) => std::path::absolute(f).map_err(|e| e.to_string())?,
                None => config.with_file_name("tagserver.log"),
            };
            return Ok(match action {
                ServiceAction::Install => service::install(&name, launcher, &config, &log_file),
                ServiceAction::Remove => service::remove(&name),
                ServiceAction::Status => service::status(&name),
                ServiceAction::Run => {
                    logging::init(Some(&log_file))?;
                    service::supervise(|| crate::run(&config, false));
                    0
                }
            });
        }
        Command::DumpTags { config, plc, out } => {
            logging::init(None)?;
            dump_tags(&config, &plc, &out)?;
        }
        Command::Types {
            url,
            token,
            plc,
            format,
            out,
        } => {
            let plcs: Vec<Option<String>> = if plc.is_empty() {
                vec![None]
            } else {
                plc.into_iter().map(Some).collect()
            };
            let bodies = plcs
                .iter()
                .map(|p| codegen::fetch_tags(&url, &token, p.as_deref()))
                .collect::<Result<Vec<_>, _>>()?;
            let (text, summary) = match format {
                Format::Tree => {
                    let names: Vec<&str> = bodies
                        .iter()
                        .map(|b| {
                            b.get("plc")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("?")
                        })
                        .collect();
                    (
                        codegen::tree_module(&bodies, plcs.len() > 1)?,
                        format!("wrote the tag tree of {}", names.join(", ")),
                    )
                }
                Format::Names => {
                    let text = codegen::names_module(&bodies, &plcs);
                    let count = text.matches("\n  | ").count();
                    (text, format!("wrote {count} tag names"))
                }
            };
            std::fs::write(&out, text).map_err(|e| format!("{}: {e}", out.display()))?;
            println!("{summary} to {}", out.display());
        }
    }
    Ok(0)
}

/// Uploads the tag list of one PLC (reads only) and writes it in the mock_tags format.
fn dump_tags(config_path: &Path, plc: &str, out: &Path) -> Result<(), String> {
    use crate::plc::{LogixPlc, Plc};
    let config = config::load_config(config_path)?;
    let cfg = config
        .plcs
        .get(plc)
        .ok_or_else(|| format!("no PLC {plc} in {}", config_path.display()))?;
    let mut driver = LogixPlc::new(cfg)?;
    driver.open()?;
    let catalog = driver.catalog();
    driver.close();
    let tags: serde_json::Map<String, serde_json::Value> = catalog
        .tags
        .iter()
        .map(|(name, node)| {
            let dims = node.client_dims();
            let type_ = match dims.as_slice() {
                [n] => format!("{}[{n}]", node.client_type()),
                _ => node.client_type().to_owned(),
            };
            (name.clone(), serde_json::Value::String(type_))
        })
        .collect();
    let text = serde_json::to_string_pretty(&tags).map_err(|e| e.to_string())?;
    std::fs::write(out, text).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("wrote {} tags to {}", tags.len(), out.display());
    Ok(())
}
