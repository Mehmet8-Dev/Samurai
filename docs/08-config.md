# Config

CLI, `--config` ile YAML bazli default degerleri yukler.
Kaynak: `ddos_samurai/cli/config.py`

## Merge Mantigi

1. Parser once bilinen argumanlarla config yolunu alir
2. YAML okunur ve flatten edilir
3. YAML degerleri parser defaults olarak set edilir
4. Komut satiri explicit degerleri YAML'i override eder

## Nested Key Mapping

YAML:

```yaml
http:
  scheme: https
  timeout: 5.0
```

Argparse `dest`:

- `http_scheme`
- `http_timeout`

## Pratik Dosya Ornegi

```yaml
target: 10.0.0.5
port: 443
protocol: tcp
attack_vector: http2
workers: 8
count: 200000
allow_target:
  - 10.0.0.0/8
safety_global_deny_target:
  - 10.10.10.0/24
run_report: true
run_report_format: both
```

## Config Tasariminda Kural

- Runtime tarafinda kritik policyleri explicit flag olarak da gecirin
- CI run'lari icin deterministic alanlari YAML'da sabitleyin:
  - sender backend/policy
  - pacing mode/rps
  - report out path

## Dogrulama Onerisi

Config degisikliginden sonra en az:

- `--dry-run`
- `--self-test`
- kritik test paketleri (`tests/test_cli_parser.py`, `tests/test_profile_resolver.py`)

ile smoke alin.
