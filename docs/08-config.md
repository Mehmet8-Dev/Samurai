# 08 - YAML Config

CLI, `--config` ile bir YAML dosyasindan default degerleri alabilir.

## Precedence

Genel kural:

- YAML dosyasindan gelen degerler "default" gibi davranir.
- Komut satirindan explicit verilen argumanlar YAML'i override eder.

## Nested Dict Flatten

YAML icinde nested dict varsa:

```yaml
http:
  scheme: https
  timeout: 5.0
```

Bu key'ler argparse tarafinda su sekle map edilir:

- `http_scheme`
- `http_timeout`

Kod: `ddos_samurai/cli.py` icindeki flatten dongusu.

## Oneri: Semayi Netlestirme

YAML semasini urun dokumani haline getirmek icin:

- Tum argparse `dest` isimlerini ve YAML mapping'ini tek yerde listeleyin.
- "deprecated" bayraklari temizlerken testleri de guncelleyin (`tests/test_cli_parser.py` gibi).

