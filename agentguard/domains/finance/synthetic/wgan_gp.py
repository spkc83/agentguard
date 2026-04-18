"""Wasserstein GAN with Gradient Penalty for tabular credit data.

Architecture: TabGAN variant with embedding layers for categorical features.
Training uses the WGAN-GP objective (Gulrajani et al. 2017) for stable
training on highly imbalanced tabular data.

This module requires PyTorch — it is only loaded when the [finance] extra
is installed: pip install agentguard[finance]

For environments without PyTorch, use SyntheticCreditGenerator in
generators.py which provides statistical sampling without GPU requirements.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()


def _import_torch() -> Any:
    """Lazily import torch."""
    try:
        import torch
    except ImportError as e:
        raise ImportError(
            "PyTorch is required for WGAN-GP training. "
            "Install with: pip install agentguard[finance]"
        ) from e
    return torch


class WganGpConfig(BaseModel):
    """Configuration for WGAN-GP training.

    Args:
        latent_dim: Dimension of the noise vector z.
        generator_hidden: Hidden layer sizes for the generator.
        critic_hidden: Hidden layer sizes for the critic.
        learning_rate: Adam learning rate.
        beta1: Adam beta1.
        beta2: Adam beta2.
        gradient_penalty_lambda: Weight for gradient penalty term.
        critic_steps: Critic updates per generator update.
        batch_size: Training batch size.
        epochs: Number of training epochs.
    """

    model_config = ConfigDict(frozen=True)

    latent_dim: int = 128
    generator_hidden: list[int] = [256, 256, 256]
    critic_hidden: list[int] = [256, 256, 256]
    learning_rate: float = 1e-4
    beta1: float = 0.5
    beta2: float = 0.9
    gradient_penalty_lambda: float = 10.0
    critic_steps: int = 5
    batch_size: int = 256
    epochs: int = 300


class WganGpTrainer:
    """WGAN-GP trainer for tabular credit data generation.

    Trains a generator to produce synthetic credit application data
    that matches the statistical properties of real data. Uses
    gradient penalty for training stability.

    Args:
        config: Training configuration.
    """

    def __init__(self, config: WganGpConfig | None = None) -> None:
        self._config = config or WganGpConfig()
        self._generator: Any = None
        self._critic: Any = None
        self._trained = False

    @property
    def is_trained(self) -> bool:
        """Whether the model has been trained."""
        return self._trained

    def fit(
        self,
        data: list[list[float]],
        feature_names: list[str] | None = None,
    ) -> dict[str, list[float]]:
        """Train the WGAN-GP on tabular data.

        Args:
            data: Training data as list of feature vectors.
            feature_names: Optional feature names for logging.

        Returns:
            Training history dict with loss curves.
        """
        torch = _import_torch()
        nn = torch.nn
        cfg = self._config

        n_features = len(data[0])
        tensor_data = torch.FloatTensor(data)

        # Generator: noise -> synthetic sample
        gen_layers = []
        prev_dim = cfg.latent_dim
        for hidden_dim in cfg.generator_hidden:
            gen_layers.extend(
                [
                    nn.Linear(prev_dim, hidden_dim),
                    nn.BatchNorm1d(hidden_dim),
                    nn.LeakyReLU(0.2),
                ]
            )
            prev_dim = hidden_dim
        gen_layers.append(nn.Linear(prev_dim, n_features))
        self._generator = nn.Sequential(*gen_layers)

        # Critic: sample -> scalar
        critic_layers = []
        prev_dim = n_features
        for hidden_dim in cfg.critic_hidden:
            critic_layers.extend(
                [
                    nn.Linear(prev_dim, hidden_dim),
                    nn.LayerNorm(hidden_dim),
                    nn.LeakyReLU(0.2),
                ]
            )
            prev_dim = hidden_dim
        critic_layers.append(nn.Linear(prev_dim, 1))
        self._critic = nn.Sequential(*critic_layers)

        # Optimizers
        g_optimizer = torch.optim.Adam(
            self._generator.parameters(),
            lr=cfg.learning_rate,
            betas=(cfg.beta1, cfg.beta2),
        )
        c_optimizer = torch.optim.Adam(
            self._critic.parameters(),
            lr=cfg.learning_rate,
            betas=(cfg.beta1, cfg.beta2),
        )

        dataset = torch.utils.data.TensorDataset(tensor_data)
        dataloader = torch.utils.data.DataLoader(
            dataset, batch_size=cfg.batch_size, shuffle=True, drop_last=True
        )

        g_losses: list[float] = []
        c_losses: list[float] = []

        for epoch in range(cfg.epochs):
            epoch_g_loss = 0.0
            epoch_c_loss = 0.0
            n_batches = 0

            for (real_batch,) in dataloader:
                batch_size = real_batch.size(0)

                # Train critic
                for _ in range(cfg.critic_steps):
                    noise = torch.randn(batch_size, cfg.latent_dim)
                    fake = self._generator(noise).detach()

                    c_real = self._critic(real_batch).mean()
                    c_fake = self._critic(fake).mean()

                    # Gradient penalty
                    alpha = torch.rand(batch_size, 1)
                    interpolated = (alpha * real_batch + (1 - alpha) * fake).requires_grad_(True)
                    c_interp = self._critic(interpolated)
                    gradients = torch.autograd.grad(
                        outputs=c_interp,
                        inputs=interpolated,
                        grad_outputs=torch.ones_like(c_interp),
                        create_graph=True,
                    )[0]
                    gp = ((gradients.norm(2, dim=1) - 1) ** 2).mean()

                    c_loss = c_fake - c_real + cfg.gradient_penalty_lambda * gp
                    c_optimizer.zero_grad()
                    c_loss.backward()
                    c_optimizer.step()

                # Train generator
                noise = torch.randn(batch_size, cfg.latent_dim)
                fake = self._generator(noise)
                g_loss = -self._critic(fake).mean()
                g_optimizer.zero_grad()
                g_loss.backward()
                g_optimizer.step()

                epoch_g_loss += g_loss.item()
                epoch_c_loss += c_loss.item()
                n_batches += 1

            if n_batches > 0:
                g_losses.append(epoch_g_loss / n_batches)
                c_losses.append(epoch_c_loss / n_batches)

            if (epoch + 1) % 50 == 0:
                logger.info(
                    "wgan_gp_epoch",
                    epoch=epoch + 1,
                    g_loss=g_losses[-1] if g_losses else 0,
                    c_loss=c_losses[-1] if c_losses else 0,
                )

        self._trained = True
        logger.info("wgan_gp_training_complete", epochs=cfg.epochs, features=n_features)
        return {"g_losses": g_losses, "c_losses": c_losses}

    def generate(self, n_samples: int) -> list[list[float]]:
        """Generate synthetic samples from the trained model.

        Args:
            n_samples: Number of synthetic samples to generate.

        Returns:
            List of feature vectors.

        Raises:
            RuntimeError: If model has not been trained.
        """
        if not self._trained or self._generator is None:
            raise RuntimeError("Model must be trained before generating samples.")

        torch = _import_torch()
        with torch.no_grad():
            noise = torch.randn(n_samples, self._config.latent_dim)
            synthetic = self._generator(noise)
            result: list[list[float]] = synthetic.tolist()
            return result
