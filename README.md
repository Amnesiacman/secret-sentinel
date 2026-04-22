# secret-sentinel

![CI](https://github.com/Amnesiacman/secret-sentinel/actions/workflows/ci.yml/badge.svg)

`secret-sentinel` is a Rust CLI scanner for detecting potential secret leaks in local files and CI.
Current stability target: **v1.0**.

## Features

- Recursive scan of files/directories
- Detection rules for:
  - AWS access key IDs
  - GitHub token-like strings
  - Generic `token/api_key/secret` assignments
  - Private key headers
- Allowlist support
- Baseline file support for known findings
- `text` and `json` output
- `sarif` output for code scanning pipelines
- Strict mode for CI (`--strict`)
- Git-aware mode with `--staged`
- TOML config support (`--config secret-sentinel.toml`)

## Usage

```bash
cargo run -- . --strict
```

JSON output:

```bash
cargo run -- . --format json
```

SARIF output:

```bash
cargo run -- . --format sarif
```

With allowlist:

```bash
cargo run -- . --allowlist .secrets-allowlist --strict
```

Create a baseline from current findings:

```bash
cargo run -- . --write-baseline .secret-sentinel-baseline.json
```

Scan using baseline suppression:

```bash
cargo run -- . --baseline .secret-sentinel-baseline.json --strict
```

Prune baseline entries that no longer appear:

```bash
cargo run -- . --prune-baseline .secret-sentinel-baseline.json
```

Install pre-commit hook:

```bash
cargo run -- --install-pre-commit
```

Scan only staged changes:

```bash
cargo run -- --staged --strict --fail-on high
```

## Config example (`secret-sentinel.toml`)

```toml
[scanner]
respect_gitignore = true
exclude_paths = ["target/", "fixtures/"]
disable_rules = ["github_token"]
entropy_threshold = 4.2
min_entropy_length = 20
```

## Exit codes

- `0`: no blocking issues (or strict mode disabled)
- `1`: findings exist at or above selected threshold when `--strict` is enabled (`--fail-on`)
- `3`: IO/config processing error (for example, baseline write failure)

## Release notes

See `CHANGELOG.md` for version-by-version changes.
