use clap::{Parser, ValueEnum};
use secret_sentinel::{
    Severity, apply_baseline, build_scan_options, has_findings_at_or_above, load_baseline,
    load_config, report_as_sarif, report_as_text, scan_paths, write_baseline,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, ValueEnum)]
enum FailOn {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Parser, Debug)]
#[command(
    name = "secret-sentinel",
    about = "Fast local scanner for potential secret leaks"
)]
struct Cli {
    #[arg()]
    paths: Vec<PathBuf>,

    #[arg(long)]
    allowlist: Option<PathBuf>,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long)]
    baseline: Option<PathBuf>,

    #[arg(long)]
    write_baseline: Option<PathBuf>,

    #[arg(long)]
    install_pre_commit: bool,

    #[arg(long)]
    staged: bool,

    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    #[arg(long, value_enum, default_value = "medium")]
    fail_on: FailOn,

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

fn staged_files() -> Vec<PathBuf> {
    let output = Command::new("git")
        .arg("diff")
        .arg("--cached")
        .arg("--name-only")
        .output();
    let Ok(output) = output else {
        return vec![];
    };
    if !output.status.success() {
        return vec![];
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn map_fail_on(value: FailOn) -> Severity {
    match value {
        FailOn::Low => Severity::Low,
        FailOn::Medium => Severity::Medium,
        FailOn::High => Severity::High,
        FailOn::Critical => Severity::Critical,
    }
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

    let targets = if cli.staged {
        staged_files()
    } else if cli.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        cli.paths.clone()
    };

    let config = load_config(cli.config.as_deref());
    let scan_options = build_scan_options(&config, cli.allowlist.clone());

    let mut report = scan_paths(&targets, &scan_options);
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
        OutputFormat::Sarif => {
            println!("{}", report_as_sarif(&report));
        }
    }

    if cli.strict && has_findings_at_or_above(&report, map_fail_on(cli.fail_on)) {
        std::process::exit(1);
    }
}
