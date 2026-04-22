# secret-sentinel

![CI](https://github.com/Amnesiacman/secret-sentinel/actions/workflows/ci.yml/badge.svg)

`secret-sentinel` is a Rust CLI scanner for detecting potential secret leaks in local files and CI.

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
- Strict mode for CI (`--strict`)

## Usage

```bash
cargo run -- . --strict
```

JSON output:

```bash
cargo run -- . --format json
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

Install pre-commit hook:

```bash
cargo run -- --install-pre-commit
```

## Exit codes

- `0`: no blocking issues (or strict mode disabled)
- `1`: findings exist and `--strict` is enabled
