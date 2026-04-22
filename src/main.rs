use clap::{Parser, ValueEnum};
use secret_sentinel::{apply_baseline, load_baseline, report_as_text, scan_paths, write_baseline};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "secret-sentinel",
    about = "Fast local scanner for potential secret leaks"
)]
struct Cli {
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    #[arg(long)]
    allowlist: Option<PathBuf>,

    #[arg(long)]
    baseline: Option<PathBuf>,

    #[arg(long)]
    write_baseline: Option<PathBuf>,

    #[arg(long)]
    install_pre_commit: bool,

    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    #[arg(long)]
    strict: bool,
}

fn install_pre_commit_hook() -> std::io::Result<()> {
    let hook_path = PathBuf::from(".git/hooks/pre-commit");
    if let Some(parent) = hook_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let script = r#"#!/usr/bin/env sh
set -e

if command -v secret-sentinel >/dev/null 2>&1; then
  secret-sentinel . --strict
else
  cargo run -- . --strict
fi
"#;
    fs::write(&hook_path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if cli.install_pre_commit {
        match install_pre_commit_hook() {
            Ok(()) => {
                println!("Installed pre-commit hook at .git/hooks/pre-commit");
                return;
            }
            Err(err) => {
                eprintln!("Failed to install pre-commit hook: {err}");
                std::process::exit(1);
            }
        }
    }

    let mut report = scan_paths(&cli.paths, cli.allowlist.as_deref());
    let baseline_signatures = load_baseline(cli.baseline.as_deref());
    report = apply_baseline(report, &baseline_signatures);

    if let Some(path) = &cli.write_baseline {
        if let Err(err) = write_baseline(path, &report) {
            eprintln!("Failed to write baseline to {}: {err}", path.display());
            std::process::exit(1);
        }
        println!("Wrote baseline to {}", path.display());
        return;
    }

    match cli.format {
        OutputFormat::Text => {
            println!("{}", report_as_text(&report));
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize report")
            );
        }
    }

    if cli.strict && !report.ok {
        std::process::exit(1);
    }
}
