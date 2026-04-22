use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scanned_files: usize,
    pub total_findings: usize,
    pub ok: bool,
    pub findings: Vec<Finding>,
}

#[derive(Debug)]
struct Rule {
    name: &'static str,
    regex: Regex,
}

fn compile_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "aws_access_key_id",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"),
        },
        Rule {
            name: "github_token",
            regex: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{20,}").expect("valid regex"),
        },
        Rule {
            name: "generic_token_assignment",
            regex: Regex::new(r#"(?i)(api[_-]?key|token|secret)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}"#)
                .expect("valid regex"),
        },
        Rule {
            name: "private_key_header",
            regex: Regex::new(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----")
                .expect("valid regex"),
        },
    ]
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

fn should_skip_file(path: &Path) -> bool {
    let ignored_suffixes = [".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar"];
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with('.') && name != ".env" && name != ".env.example" {
            return true;
        }
    }
    ignored_suffixes
        .iter()
        .any(|suffix| path.to_string_lossy().ends_with(suffix))
}

fn collect_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
            continue;
        }
        if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
    }
    files
}

pub fn scan_paths(paths: &[PathBuf], allowlist_path: Option<&Path>) -> ScanReport {
    let rules = compile_rules();
    let allowlist = load_allowlist(allowlist_path);
    let mut findings = Vec::new();
    let mut scanned_files = 0usize;

    for file in collect_files(paths) {
        if should_skip_file(&file) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        scanned_files += 1;
        for (idx, line) in content.lines().enumerate() {
            for rule in &rules {
                if rule.regex.is_match(line) && !is_allowed(line, &allowlist) {
                    findings.push(Finding {
                        file: file.display().to_string(),
                        line: idx + 1,
                        rule: rule.name.to_string(),
                        snippet: line.chars().take(200).collect(),
                    });
                }
            }
        }
    }

    ScanReport {
        scanned_files,
        total_findings: findings.len(),
        ok: findings.is_empty(),
        findings,
    }
}

pub fn report_as_text(report: &ScanReport) -> String {
    let mut lines = vec![
        format!("Scanned files: {}", report.scanned_files),
        format!("Findings: {}", report.total_findings),
        format!("Status: {}", if report.ok { "ok" } else { "failed" }),
        String::new(),
    ];
    for finding in &report.findings {
        lines.push(format!(
            "- {}:{} [{}] {}",
            finding.file, finding.line, finding.rule, finding.snippet
        ));
    }
    lines.join("\n").trim_end().to_string()
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

        let report = scan_paths(&[dir.path().to_path_buf()], None);
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

        let report = scan_paths(&[dir.path().to_path_buf()], Some(&allow_path));
        assert!(report.ok);
        assert_eq!(report.total_findings, 0);
    }
}
