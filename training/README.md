# Mamba-2 Training (v1)

This directory contains lightweight entrypoints for offline supervised training and evaluation.

- `mamba2_train.py`: loads dataset and prints deterministic config summary (scaffold).
- `mamba2_eval.py`: loads checkpoint path and runs a tiny smoke evaluation (scaffold).
- `configs/mamba2_v1.yaml`: baseline v1 hyperparameters.

These scripts are intentionally minimal and safe for environments where ML dependencies may not be installed by default.

