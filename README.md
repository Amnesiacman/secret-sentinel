# secret-sentinel

[Русская версия](README.ru.md)

Rust CLI scanner for detecting potential secret leaks in local and CI workflows.

## Key capabilities

- regex-based rules + entropy detector
- severity model (`low|medium|high|critical`)
- strict gating with threshold (`--strict --fail-on`)
- baseline workflow (`--write-baseline`, `--baseline`, `--prune-baseline`)
- staged-only mode (`--staged`)
- `.gitignore`-aware traversal
- config via `secret-sentinel.toml`
- output formats: `text`, `json`, `sarif`

## Usage

```bash
cargo run -- . --strict --fail-on high
cargo run -- . --format sarif
cargo run -- . --write-baseline .secret-sentinel-baseline.json
cargo run -- . --baseline .secret-sentinel-baseline.json --strict
cargo run -- --staged --strict --fail-on medium
cargo run -- --install-pre-commit
```

## Config example

```toml
[scanner]
respect_gitignore = true
exclude_paths = ["target/", ".git/"]
disable_rules = []
entropy_threshold = 4.2
min_entropy_length = 20
max_file_bytes = 1000000
```

## Exit codes

- `0` successful scan / no blocking findings
- `1` strict gate failed
- `3` IO/config processing error
