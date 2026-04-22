use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub snippet: String,
    pub severity: Severity,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub scanned_files: usize,
    pub total_findings: usize,
    pub ok: bool,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub signatures: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scanner: ScannerConfig,
}

#[derive(Debug, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_true")]
    pub respect_gitignore: bool,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub disable_rules: Vec<String>,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_entropy_min_length")]
    pub min_entropy_length: usize,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            respect_gitignore: true,
            exclude_paths: vec![],
            disable_rules: vec![],
            entropy_threshold: default_entropy_threshold(),
            min_entropy_length: default_entropy_min_length(),
            max_file_bytes: default_max_file_bytes(),
        }
    }
}

#[derive(Debug)]
struct Rule {
    name: &'static str,
    regex: Regex,
    severity: Severity,
}

#[derive(Debug)]
pub struct ScanOptions {
    pub allowlist_path: Option<PathBuf>,
    pub respect_gitignore: bool,
    pub exclude_paths: Vec<String>,
    pub disabled_rules: Vec<String>,
    pub entropy_threshold: f64,
    pub entropy_min_length: usize,
    pub max_file_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            allowlist_path: None,
            respect_gitignore: true,
            exclude_paths: vec![],
            disabled_rules: vec![],
            entropy_threshold: default_entropy_threshold(),
            entropy_min_length: default_entropy_min_length(),
            max_file_bytes: default_max_file_bytes(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_entropy_threshold() -> f64 {
    4.2
}

fn default_entropy_min_length() -> usize {
    20
}

fn default_max_file_bytes() -> u64 {
    1_000_000
}

fn compile_rules(disabled_rules: &HashSet<String>) -> Vec<Rule> {
    let mut rules = vec![
        Rule {
            name: "aws_access_key_id",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"),
            severity: Severity::Critical,
        },
        Rule {
            name: "github_token",
            regex: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{20,}").expect("valid regex"),
            severity: Severity::High,
        },
        Rule {
            name: "generic_token_assignment",
            regex: Regex::new(
                r#"(?i)(api[_-]?key|token|secret)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}"#,
            )
            .expect("valid regex"),
            severity: Severity::Medium,
        },
        Rule {
            name: "private_key_header",
            regex: Regex::new(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----")
                .expect("valid regex"),
            severity: Severity::Critical,
        },
    ];
    rules.retain(|r| !disabled_rules.contains(r.name));
    rules
}

fn shannon_entropy(input: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = input.as_bytes();
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn load_config(path: Option<&Path>) -> Config {
    let Some(path) = path else {
        return Config::default();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return Config::default();
    };
    toml::from_str::<Config>(&content).unwrap_or_default()
}

pub fn build_scan_options(config: &Config, allowlist_path: Option<PathBuf>) -> ScanOptions {
    ScanOptions {
        allowlist_path,
        respect_gitignore: config.scanner.respect_gitignore,
        exclude_paths: config.scanner.exclude_paths.clone(),
        disabled_rules: config.scanner.disable_rules.clone(),
        entropy_threshold: config.scanner.entropy_threshold,
        entropy_min_length: config.scanner.min_entropy_length,
        max_file_bytes: config.scanner.max_file_bytes,
    }
}

pub fn load_allowlist(path: Option<&Path>) -> Vec<String> {
    let Some(path) = path else {
        return vec![];
    };
    let Ok(content) = fs::read_to_string(path) else {
        return vec![];
    };
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

fn is_allowed(line: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|item| line.contains(item))
}

fn should_skip_file(path: &Path, exclude_paths: &[String]) -> bool {
    let ignored_suffixes = [
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar",
    ];
    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && name.starts_with('.')
        && name != ".env"
        && name != ".env.example"
    {
        return true;
    }
    if exclude_paths
        .iter()
        .any(|item| path.to_string_lossy().contains(item))
    {
        return true;
    }
    ignored_suffixes
        .iter()
        .any(|suffix| path.to_string_lossy().ends_with(suffix))
}

fn collect_files(paths: &[PathBuf], respect_gitignore: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
            continue;
        }
        if path.is_dir() {
            let mut builder = WalkBuilder::new(path);
            builder.hidden(false);
            if !respect_gitignore {
                builder
                    .git_ignore(false)
                    .git_exclude(false)
                    .git_global(false);
            }
            for entry in builder.build().filter_map(Result::ok) {
                if entry
                    .file_type()
                    .map(|file_type| file_type.is_file())
                    .unwrap_or(false)
                {
                    files.push(entry.into_path());
                }
            }
        }
    }
    files
}

pub fn finding_signature(finding: &Finding) -> String {
    format!("{}|{}|{}", finding.file, finding.rule, finding.snippet)
}

pub fn load_baseline(path: Option<&Path>) -> Vec<String> {
    let Some(path) = path else {
        return vec![];
    };
    let Ok(content) = fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(parsed) = serde_json::from_str::<Baseline>(&content) else {
        return vec![];
    };
    parsed.signatures
}

pub fn scan_paths(paths: &[PathBuf], options: &ScanOptions) -> ScanReport {
    let disabled: HashSet<String> = options.disabled_rules.iter().cloned().collect();
    let rules = compile_rules(&disabled);
    let allowlist = load_allowlist(options.allowlist_path.as_deref());
    let mut findings = Vec::new();
    let mut scanned_files = 0usize;

    for file in collect_files(paths, options.respect_gitignore) {
        if should_skip_file(&file, &options.exclude_paths) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&file) else {
            continue;
        };
        if metadata.len() > options.max_file_bytes {
            continue;
        }
        let Ok(bytes) = fs::read(&file) else {
            continue;
        };
        if bytes.contains(&0) {
            continue;
        }
        let content = String::from_utf8_lossy(&bytes);

        scanned_files += 1;
        for (idx, line) in content.lines().enumerate() {
            for rule in &rules {
                if rule.regex.is_match(line) && !is_allowed(line, &allowlist) {
                    findings.push(Finding {
                        file: file.display().to_string(),
                        line: idx + 1,
                        rule: rule.name.to_string(),
                        snippet: line.chars().take(200).collect(),
                        severity: rule.severity,
                    });
                }
            }
            if line.len() >= options.entropy_min_length && !is_allowed(line, &allowlist) {
                let entropy = shannon_entropy(line);
                if entropy >= options.entropy_threshold {
                    findings.push(Finding {
                        file: file.display().to_string(),
                        line: idx + 1,
                        rule: "high_entropy_string".to_string(),
                        snippet: line.chars().take(200).collect(),
                        severity: Severity::Medium,
                    });
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        (&a.file, a.line, &a.rule, &a.snippet).cmp(&(&b.file, b.line, &b.rule, &b.snippet))
    });

    ScanReport {
        schema_version: "1.0".to_string(),
        scanned_files,
        total_findings: findings.len(),
        ok: findings.is_empty(),
        findings,
    }
}

pub fn apply_baseline(report: ScanReport, baseline_signatures: &[String]) -> ScanReport {
    if baseline_signatures.is_empty() {
        return report;
    }
    let filtered_findings: Vec<Finding> = report
        .findings
        .into_iter()
        .filter(|finding| {
            let signature = finding_signature(finding);
            !baseline_signatures.iter().any(|item| item == &signature)
        })
        .collect();

    ScanReport {
        schema_version: report.schema_version,
        scanned_files: report.scanned_files,
        total_findings: filtered_findings.len(),
        ok: filtered_findings.is_empty(),
        findings: filtered_findings,
    }
}

pub fn prune_baseline(baseline_signatures: &[String], report: &ScanReport) -> Vec<String> {
    let current: HashSet<String> = report.findings.iter().map(finding_signature).collect();
    baseline_signatures
        .iter()
        .filter(|item| current.contains(*item))
        .cloned()
        .collect()
}

pub fn write_baseline(path: &Path, report: &ScanReport) -> std::io::Result<()> {
    let signatures = report.findings.iter().map(finding_signature).collect();
    write_baseline_signatures(path, signatures)
}

pub fn write_baseline_signatures(path: &Path, signatures: Vec<String>) -> std::io::Result<()> {
    let baseline = Baseline { signatures };
    let content = serde_json::to_string_pretty(&baseline).expect("serialize baseline");
    fs::write(path, content + "\n")
}

pub fn report_as_text(report: &ScanReport) -> String {
    let mut lines = vec![
        format!("Schema version: {}", report.schema_version),
        format!("Scanned files: {}", report.scanned_files),
        format!("Findings: {}", report.total_findings),
        format!("Status: {}", if report.ok { "ok" } else { "failed" }),
        String::new(),
    ];
    for finding in &report.findings {
        lines.push(format!(
            "- {}:{} [{}:{}] {}",
            finding.file,
            finding.line,
            finding.rule,
            format!("{:?}", finding.severity).to_lowercase(),
            finding.snippet
        ));
    }
    lines.join("\n").trim_end().to_string()
}

pub fn report_as_sarif(report: &ScanReport) -> String {
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.rule,
                "level": match finding.severity {
                    Severity::Low => "note",
                    Severity::Medium => "warning",
                    Severity::High | Severity::Critical => "error",
                },
                "message": {"text": finding.snippet},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {"startLine": finding.line}
                    }
                }]
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
      "version": "2.1.0",
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "runs": [{
        "tool": {
          "driver": {
            "name": "secret-sentinel",
            "informationUri": "https://github.com/Amnesiacman/secret-sentinel",
            "rules": []
          }
        },
        "results": results
      }]
    }))
    .expect("serialize sarif")
}

pub fn has_findings_at_or_above(report: &ScanReport, min_severity: Severity) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.severity >= min_severity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_secret() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("app.env");
        fs::write(&file_path, "TOKEN=abcdefghijklmnopqrstuvwxyz123456\n").expect("write file");

        let report = scan_paths(&[dir.path().to_path_buf()], &ScanOptions::default());
        assert!(!report.ok);
        assert!(report.total_findings >= 1);
    }

    #[test]
    fn allowlist_suppresses_finding() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("app.env");
        let allow_path = dir.path().join(".secrets-allowlist");
        fs::write(&file_path, "TOKEN=abcdefghijklmnopqrstuvwxyz123456\n").expect("write file");
        fs::write(&allow_path, "abcdefghijklmnopqrstuvwxyz123456\n").expect("write allowlist");

        let report = scan_paths(
            &[dir.path().to_path_buf()],
            &ScanOptions {
                allowlist_path: Some(allow_path),
                ..ScanOptions::default()
            },
        );
        assert!(report.ok);
        assert_eq!(report.total_findings, 0);
    }

    #[test]
    fn baseline_suppresses_known_finding() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("app.env");
        fs::write(&file_path, "TOKEN=abcdefghijklmnopqrstuvwxyz123456\n").expect("write file");

        let report = scan_paths(&[dir.path().to_path_buf()], &ScanOptions::default());
        assert!(report.total_findings >= 1);
        let signatures: Vec<String> = report.findings.iter().map(finding_signature).collect();

        let filtered = apply_baseline(report, &signatures);
        assert!(filtered.ok);
        assert_eq!(filtered.total_findings, 0);
    }

    #[test]
    fn supports_toml_config_loading() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("secret-sentinel.toml");
        fs::write(
            &config_path,
            r#"[scanner]
respect_gitignore = false
exclude_paths = ["target/"]
disable_rules = ["github_token"]
entropy_threshold = 4.5
min_entropy_length = 24
max_file_bytes = 2048
"#,
        )
        .expect("write config");
        let config = load_config(Some(&config_path));
        assert!(!config.scanner.respect_gitignore);
        assert_eq!(config.scanner.exclude_paths.len(), 1);
        assert_eq!(config.scanner.disable_rules.len(), 1);
        assert_eq!(config.scanner.max_file_bytes, 2048);
    }

    #[test]
    fn sarif_output_contains_runs() {
        let report = ScanReport {
            schema_version: "1.0".to_string(),
            scanned_files: 1,
            total_findings: 1,
            ok: false,
            findings: vec![Finding {
                file: "a.txt".to_string(),
                line: 1,
                rule: "generic_token_assignment".to_string(),
                snippet: "TOKEN=abc".to_string(),
                severity: Severity::Medium,
            }],
        };
        let sarif = report_as_sarif(&report);
        assert!(sarif.contains("\"runs\""));
        assert!(sarif.contains("\"ruleId\""));
    }
}
