from __future__ import annotations

try:
    import torch
    from torch import nn
except ImportError:  # pragma: no cover - optional runtime dependency
    torch = None
    nn = None


if nn is None:
    class DenseVAE:  # pragma: no cover - torch-less fallback
        def __init__(self, in_dim: int, hidden_dim: int, latent_dim: int):
            raise RuntimeError("PyTorch is required for DenseVAE. Install with: pip install -r requirements-ml.txt")
else:
    class DenseVAE(nn.Module):
        def __init__(self, in_dim: int, hidden_dim: int, latent_dim: int):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(in_dim, hidden_dim),
                nn.ReLU(inplace=True),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(inplace=True),
            )
            self.mu = nn.Linear(hidden_dim, latent_dim)
            self.logvar = nn.Linear(hidden_dim, latent_dim)
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.ReLU(inplace=True),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(inplace=True),
                nn.Linear(hidden_dim, in_dim),
            )

        def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
            h = self.encoder(x)
            mu = self.mu(h)
            logvar = self.logvar(h)
            z = self._reparameterize(mu, logvar)
            xr = self.decoder(z)
            return xr, mu, logvar

        @staticmethod
        def _reparameterize(mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std
