# Changelog

## v1.0.0

- Stabilized CLI options for local and CI use.
- Added severity-based gating (`--fail-on`) and SARIF output.
- Added config-driven scanning via `secret-sentinel.toml`.
- Added git-aware staged scanning and `.gitignore` support.
- Added baseline write/apply/prune workflow.
- Added binary and large-file safeguards for reliable scanning.

## v0.3.0

- Added baseline pruning and deterministic report ordering.
- Added report schema versioning and sample config file.

## v0.2.0

- Added TOML config support and entropy-based detector.
- Added SARIF output and staged scanning mode.

## v0.1.0

- Initial Rust scanner MVP with regex rules, allowlist, strict mode, and release workflow.

