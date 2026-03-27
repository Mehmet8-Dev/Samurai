# Mamba-2 Training (v1)

This directory contains offline supervised training and evaluation entrypoints.

- `mamba2_monolith.py`: single-file dataset build, train, resume, eval and infer-plan entrypoint.
- `capture_web_pcap.py`: standalone large web traffic capture helper.
- `configs/mamba2_v1.yaml`: baseline v1 hyperparameters.

## Standalone Mode

Mamba-2 is intentionally decoupled from the runtime orchestrator/CLI attack flow.
Use `training/mamba2_monolith.py` directly.

Current model contract:
- learned component: event sequence plus per-event fields (`event_type`, `delay_bucket`, `method`, `path_bucket`, `header_profile`, `payload_class`, `mutation_signature`)
- runtime materialization: token-conditioned expansion (`token_conditioned_v2`)
- still deterministic mapping layer: `delay_bucket -> delay_ms` and `path_bucket -> concrete path`

Feature engineering (CICIDS2017 CSV):
- Training now fits quantile-based flow statistics from train CSV only (`feature_engineering` block in checkpoint config).
- The same fitted stats are reused for val/eval/resume to avoid leakage and keep bucketization stable.

### Kaggle / Notebook-Friendly Commands

1. Build dataset:
   - `PYTHONPATH=. python training/mamba2_monolith.py build-dataset --input-format csv --raw-dir /kaggle/input/cicids2017 --out-dir /kaggle/working/cicids2017_v1 --csv-glob "*.csv" --split-mode trace_session --low-memory --csv-chunksize 25000 --parquet-chunk-rows 100000`
2. Train:
   - `PYTHONPATH=. python training/mamba2_monolith.py train --train-csv-dir /kaggle/working/cicids2017_v1/train --val-csv-dir /kaggle/working/cicids2017_v1/val --out-dir /kaggle/working/mamba2 --device cpu --config-file training/configs/mamba2_1650_4gb.yaml`
3. Evaluate:
   - `PYTHONPATH=. python training/mamba2_monolith.py eval --checkpoint-path /kaggle/working/mamba2/<checkpoint>.ckpt.pt --eval-csv-dir /kaggle/working/cicids2017_v1/test --device cpu`
4. Infer a plan:
   - `PYTHONPATH=. python training/mamba2_monolith.py infer-plan --checkpoint-path /kaggle/working/mamba2/<checkpoint>.ckpt.pt --protocol http2 --label evasive --session-count 4 --session-len 8 --out /kaggle/working/plan.json`

## Dataset Build (v1)

1. Put PCAP files under:
   - `data/raw/benign/`
   - `data/raw/evasive/`
   - `data/raw/aggressive/`
2. Run:
   - `PYTHONPATH=. python training/mamba2_monolith.py build-dataset --raw-dir data/raw --out-dir data/processed/v1`
   - Large PCAP safe mode example:
     `PYTHONPATH=. python training/mamba2_monolith.py build-dataset --raw-dir data/raw --out-dir data/processed/v1 --max-packets-per-file 2000000 --progress-every 250000`
   - Recommended anti-leakage split (default):
     `--split-mode trace_session` (prefers `trace_id`, falls back to `session_id`)
   - CSV mode (Improved CICIDS2017 / CSE-CICIDS2018):
     `PYTHONPATH=. python training/mamba2_monolith.py build-dataset --input-format csv --raw-dir data/raw/cicids2017 --out-dir data/processed/cicids2017_v1 --csv-glob "*.csv" --split-mode trace_session`
   - Large CSV safe mode example:
     `PYTHONPATH=. python training/mamba2_monolith.py build-dataset --input-format csv --raw-dir data/raw/csecicids2018 --out-dir data/processed/csecicids2018_v1 --max-rows-per-file 3000000 --csv-chunksize 250000 --progress-every 250000 --split-mode trace_session`
   - Low-memory CSV mode (recommended for multi-million-row CSV datasets):
     `PYTHONPATH=. python training/mamba2_monolith.py build-dataset --input-format csv --raw-dir data/raw/cicids2017 --out-dir data/processed/cicids2017_v1 --csv-glob "*.csv" --csv-chunksize 25000 --progress-every 250000 --split-mode trace_session --low-memory --parquet-chunk-rows 100000`
3. Outputs:
   - `train.parquet`, `val.parquet`, `test.parquet`
   - debug JSONL files and `summary.json` (includes leakage overlap counters)

Notes for CSV datasets:
- If files are under `benign/`, `evasive/`, `aggressive/` subfolders, folder label is used as fallback.
- Otherwise, `Label` column is mapped automatically:
  - `BENIGN` -> `benign`
  - known stealth attacks (e.g. `Web Attack`, `SQL`, `Slowloris`, `Heartbleed`) -> `evasive`
  - remaining attacks -> `aggressive`
- Low-memory mode writes a temporary spool file under `<out-dir>/.tmp_build` (or `--temp-dir`) and then creates split JSONL/Parquet artifacts without holding all rows in RAM.

## Large Web Capture (HTTP/1 + HTTP/2 + HTTP/3/QUIC)

You can generate standalone, large mixed web PCAPs with:

`PYTHONPATH=. python training/capture_web_pcap.py --out-dir data/raw/benign --prefix benign_webmix --duration-sec 900 --interface wlo1 --sites-file training/configs/web_sites_mixed.txt --protocols h1,h2,h3`

Notes:
- Script prefers `tshark` backend (works on many systems without `sudo` if capture capabilities are set).
- It writes rotating `.pcap` files and a JSON summary file.
- `SSLKEYLOGFILE` is exported automatically; key log file is saved next to captures.
- If HTTP/3 support is missing in local `curl`, `h3` requests will fail and be counted in summary.

## Train + Eval (CSV-Only)

1. Train baseline checkpoint directly from CSV:
   - `PYTHONPATH=. python training/mamba2_monolith.py train --train-csv-dir data/raw/cicids2017/train --val-csv-dir data/raw/cicids2017/val --out-dir data/processed/mamba2 --device cpu --config-file training/configs/mamba2_v1.yaml`
   - 4 GB VRAM profile example:
     `PYTHONPATH=. python training/mamba2_monolith.py train --train-csv-dir data/raw/cicids2017/train --val-csv-dir data/raw/cicids2017/val --out-dir data/processed/mamba2_1650 --device cuda --config-file training/configs/mamba2_1650_4gb.yaml`
2. Evaluate on CSV test source:
   - `PYTHONPATH=. python training/mamba2_monolith.py eval --checkpoint-path data/processed/mamba2/<checkpoint>.ckpt.pt --eval-csv-dir data/raw/cicids2017/test --device cpu`
