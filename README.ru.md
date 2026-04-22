# secret-sentinel

[English version](README.md)

Rust CLI-сканер для поиска потенциальных утечек секретов в локальной разработке и CI.

## Ключевые возможности

- regex-правила + entropy-детектор
- модель severity (`low|medium|high|critical`)
- strict-гейтинг по порогу (`--strict --fail-on`)
- baseline-процесс (`--write-baseline`, `--baseline`, `--prune-baseline`)
- режим только staged-файлов (`--staged`)
- учёт `.gitignore`
- конфигурация через `secret-sentinel.toml`
- форматы вывода: `text`, `json`, `sarif`

## Использование

```bash
cargo run -- . --strict --fail-on high
cargo run -- . --format sarif
cargo run -- . --write-baseline .secret-sentinel-baseline.json
cargo run -- . --baseline .secret-sentinel-baseline.json --strict
cargo run -- --staged --strict --fail-on medium
cargo run -- --install-pre-commit
```

## Пример конфига

```toml
[scanner]
respect_gitignore = true
exclude_paths = ["target/", ".git/"]
disable_rules = []
entropy_threshold = 4.2
min_entropy_length = 20
max_file_bytes = 1000000
```

## Коды возврата

- `0` успешный скан / нет блокирующих находок
- `1` не пройден strict-гейт
- `3` ошибка IO/обработки конфига
