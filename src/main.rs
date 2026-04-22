use clap::{Parser, ValueEnum};
use secret_sentinel::{report_as_text, scan_paths};
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

    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    #[arg(long)]
    strict: bool,
}

fn main() {
    let cli = Cli::parse();
    let report = scan_paths(&cli.paths, cli.allowlist.as_deref());

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
