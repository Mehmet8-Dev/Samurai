from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

try:
    import pandas as pd
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("pandas is required for VAE training pipeline") from exc

try:
    import torch
    from torch import nn
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("PyTorch is required for VAE training pipeline") from exc

from .config import VAEConfig
from .model import DenseVAE


@dataclass(frozen=True)
class TrainConfig:
    input_glob: str
    output_dir: Path
    model_version: str
    label_col: str
    normal_label: str
    hidden_dim: int
    latent_dim: int
    batch_size: int
    epochs: int
    lr: float
    beta_kl: float
    threshold_quantile: float
    seed: int


def _set_seed(seed: int) -> None:
    np.random.seed(int(seed))
    torch.manual_seed(int(seed))
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(int(seed))


def _iter_csv_paths(glob_pat: str) -> list[Path]:
    return sorted(Path().glob(glob_pat))


def _load_dataframe(paths: Iterable[Path]) -> pd.DataFrame:
    frames = []
    for p in paths:
        frames.append(pd.read_csv(p))
    if not frames:
        raise ValueError("No CSV files matched input_glob")
    return pd.concat(frames, ignore_index=True)


def _to_float_series(df: pd.DataFrame, col: str) -> np.ndarray:
    if col not in df.columns:
        raise ValueError(f"Missing required feature column: {col}")
    s = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
    return s.to_numpy(dtype=np.float32)


def _build_windows(arr: np.ndarray, *, window_size: int, step_size: int) -> np.ndarray:
    n = int(arr.shape[0])
    if n < window_size:
        return np.zeros((0, window_size, arr.shape[1]), dtype=np.float32)
    out = []
    for i in range(0, n - window_size + 1, step_size):
        out.append(arr[i : i + window_size])
    return np.asarray(out, dtype=np.float32)


def _split_normal_windows(windows: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    if windows.shape[0] < 4:
        raise ValueError("Not enough normal windows; need at least 4")
    cut = max(1, int(windows.shape[0] * 0.85))
    train = windows[:cut]
    val = windows[cut:]
    if val.shape[0] == 0:
        val = train[-1:]
    return train, val


def _fit_scaler(train_windows: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    flat = train_windows.reshape(-1, train_windows.shape[-1])
    mean = flat.mean(axis=0).astype(np.float32)
    std = flat.std(axis=0).astype(np.float32)
    std = np.where(std <= 1e-8, 1.0, std).astype(np.float32)
    return mean, std


def _normalize(windows: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return (windows - mean[None, None, :]) / std[None, None, :]


def _vae_loss(x: torch.Tensor, xr: torch.Tensor, mu: torch.Tensor, logvar: torch.Tensor, beta_kl: float) -> tuple[torch.Tensor, float, float]:
    rec = torch.mean((xr - x) ** 2)
    kl = -0.5 * torch.mean(1.0 + logvar - torch.square(mu) - torch.exp(logvar))
    loss = rec + (float(beta_kl) * kl)
    return loss, float(rec.detach().cpu().item()), float(kl.detach().cpu().item())


def _score(model: nn.Module, x: np.ndarray, *, beta_kl: float, device: torch.device) -> np.ndarray:
    model.eval()
    tx = torch.from_numpy(x.astype(np.float32)).to(device)
    with torch.no_grad():
        xr, mu, logvar = model(tx)
        rec = torch.mean((xr - tx) ** 2, dim=1)
        kl = -0.5 * torch.mean(1.0 + logvar - torch.square(mu) - torch.exp(logvar), dim=1)
        s = rec + (float(beta_kl) * kl)
    return s.detach().cpu().numpy().astype(np.float32)


def run_train(cfg: TrainConfig) -> dict:
    _set_seed(cfg.seed)
    paths = _iter_csv_paths(cfg.input_glob)
    df = _load_dataframe(paths)

    vae_cfg = VAEConfig(model_path=Path("x"), scaler_path=Path("x"), meta_path=Path("x"), model_version=cfg.model_version)
    feats = list(vae_cfg.feature_names)

    x_cols = np.stack([_to_float_series(df, c) for c in feats], axis=1)
    x_cols = np.where(np.isfinite(x_cols), x_cols, np.nan)
    # forward-fill then zero-fill
    for j in range(x_cols.shape[1]):
        col = x_cols[:, j]
        mask = np.isnan(col)
        if mask.any():
            idx = np.where(~mask, np.arange(mask.shape[0]), 0)
            np.maximum.accumulate(idx, out=idx)
            col = col[idx]
            col[np.isnan(col)] = 0.0
            x_cols[:, j] = col

    if cfg.label_col not in df.columns:
        raise ValueError(f"Missing label column: {cfg.label_col}")
    labels = df[cfg.label_col].astype(str).to_numpy()
    normal_mask = labels == str(cfg.normal_label)

    normal_rows = x_cols[normal_mask]
    if normal_rows.shape[0] < vae_cfg.window_size:
        raise ValueError("Not enough normal rows for window creation")

    normal_windows = _build_windows(normal_rows, window_size=vae_cfg.window_size, step_size=1)
    train_w, val_w = _split_normal_windows(normal_windows)

    mean, std = _fit_scaler(train_w)
    train_z = _normalize(train_w, mean, std).reshape(train_w.shape[0], -1)
    val_z = _normalize(val_w, mean, std).reshape(val_w.shape[0], -1)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = DenseVAE(in_dim=vae_cfg.input_dim, hidden_dim=cfg.hidden_dim, latent_dim=cfg.latent_dim).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=float(cfg.lr))

    train_ds = torch.utils.data.TensorDataset(torch.from_numpy(train_z.astype(np.float32)))
    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=max(1, int(cfg.batch_size)), shuffle=True, drop_last=False)

    history = []
    for epoch in range(1, int(cfg.epochs) + 1):
        model.train()
        loss_sum = 0.0
        rec_sum = 0.0
        kl_sum = 0.0
        n = 0
        for (xb,) in train_loader:
            xb = xb.to(device)
            opt.zero_grad(set_to_none=True)
            xr, mu, logvar = model(xb)
            loss, rec, kl = _vae_loss(xb, xr, mu, logvar, beta_kl=cfg.beta_kl)
            loss.backward()
            opt.step()
            b = int(xb.shape[0])
            n += b
            loss_sum += float(loss.detach().cpu().item()) * b
            rec_sum += float(rec) * b
            kl_sum += float(kl) * b

        val_scores = _score(model, val_z, beta_kl=cfg.beta_kl, device=device)
        row = {
            "epoch": int(epoch),
            "train_loss": float(loss_sum / max(1, n)),
            "train_rec": float(rec_sum / max(1, n)),
            "train_kl": float(kl_sum / max(1, n)),
            "val_score_mean": float(np.mean(val_scores)) if val_scores.size else 0.0,
            "val_score_p95": float(np.quantile(val_scores, 0.95)) if val_scores.size else 0.0,
        }
        history.append(row)

    val_scores = _score(model, val_z, beta_kl=cfg.beta_kl, device=device)
    threshold = float(np.quantile(val_scores, float(cfg.threshold_quantile))) if val_scores.size else 1.0

    out_dir = cfg.output_dir / cfg.model_version
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "l4_vae.pt"
    scaler_path = out_dir / "l4_scaler.npz"
    meta_path = out_dir / "l4_vae_meta.json"
    history_path = out_dir / "l4_vae_history.json"

    torch.save(model.state_dict(), model_path)
    np.savez(
        scaler_path,
        mean_=mean.astype(np.float64),
        scale_=std.astype(np.float64),
        var_=np.square(std.astype(np.float64)),
    )

    meta = {
        "format": "samurai_vae_dense_v1",
        "model_version": cfg.model_version,
        "feature_names": feats,
        "window_size": int(vae_cfg.window_size),
        "step_size": int(vae_cfg.step_size),
        "input_dim": int(vae_cfg.input_dim),
        "hidden_dim": int(cfg.hidden_dim),
        "latent_dim": int(cfg.latent_dim),
        "beta_kl": float(cfg.beta_kl),
        "threshold": float(threshold),
        "threshold_quantile": float(cfg.threshold_quantile),
        "label_col": str(cfg.label_col),
        "normal_label": str(cfg.normal_label),
        "train_windows": int(train_w.shape[0]),
        "val_windows": int(val_w.shape[0]),
        "seed": int(cfg.seed),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")

    return {
        "model_path": str(model_path),
        "scaler_path": str(scaler_path),
        "meta_path": str(meta_path),
        "history_path": str(history_path),
        "threshold": float(threshold),
        "train_windows": int(train_w.shape[0]),
        "val_windows": int(val_w.shape[0]),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("samurai-vae-train")
    p.add_argument("--input-glob", required=True, help="CSV glob pattern. Example: data/vae/*.csv")
    p.add_argument("--output-dir", default="samurai/models/vae/artifacts", help="Base artifacts directory")
    p.add_argument("--model-version", default="vae-loadtest-v1")
    p.add_argument("--label-col", default="Label")
    p.add_argument("--normal-label", default="BENIGN")
    p.add_argument("--hidden-dim", type=int, default=128)
    p.add_argument("--latent-dim", type=int, default=16)
    p.add_argument("--batch-size", type=int, default=1024)
    p.add_argument("--epochs", type=int, default=20)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--beta-kl", type=float, default=0.1)
    p.add_argument("--threshold-quantile", type=float, default=0.95)
    p.add_argument("--seed", type=int, default=1337)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg = TrainConfig(
        input_glob=str(args.input_glob),
        output_dir=Path(str(args.output_dir)),
        model_version=str(args.model_version),
        label_col=str(args.label_col),
        normal_label=str(args.normal_label),
        hidden_dim=int(args.hidden_dim),
        latent_dim=int(args.latent_dim),
        batch_size=int(args.batch_size),
        epochs=int(args.epochs),
        lr=float(args.lr),
        beta_kl=float(args.beta_kl),
        threshold_quantile=float(args.threshold_quantile),
        seed=int(args.seed),
    )
    out = run_train(cfg)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
