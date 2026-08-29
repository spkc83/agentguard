"""Optional, deterministic WGAN-GP support for synthetic benchmark data."""

from __future__ import annotations

import math
from numbers import Real
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from collections.abc import Sequence

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

logger = structlog.get_logger()

_FEATURE_BOUNDS: dict[str, tuple[float, float]] = {
    "fico_score": (300.0, 850.0),
    "dti_ratio": (0.0, 1.0),
    "ltv_ratio": (0.0, 2.0),
}
_TORCH_SEED_MAX = 2**63 - 1


def _import_torch() -> Any:
    """Import PyTorch only when training or generation is requested."""
    try:
        import torch
    except ImportError as exc:
        raise ImportError(
            "PyTorch is required for WGAN-GP training. "
            "Install with: pip install agentguard[finance]"
        ) from exc
    return torch


def _numeric_matrix(data: Sequence[Sequence[float]]) -> tuple[tuple[float, ...], ...]:
    if not data:
        raise ValueError("data must contain at least one row")

    rows: list[tuple[float, ...]] = []
    width: int | None = None
    for row in data:
        if not row:
            raise ValueError("data rows must contain at least one value")
        if width is None:
            width = len(row)
        elif len(row) != width:
            raise ValueError("data must be rectangular")

        values: list[float] = []
        for value in row:
            if isinstance(value, bool) or not isinstance(value, Real):
                raise ValueError("data must contain only numeric values")
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("data must contain only finite values")
            values.append(number)
        rows.append(tuple(values))
    return tuple(rows)


def _feature_order(
    feature_names: Sequence[str] | None,
    width: int,
) -> tuple[str, ...]:
    if feature_names is None:
        return tuple(f"feature_{index}" for index in range(width))
    names = tuple(feature_names)
    if len(names) != width:
        raise ValueError("feature_names length must match the data width")
    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise ValueError("feature_names must contain non-empty strings")
    if len(set(names)) != len(names):
        raise ValueError("feature_names must be unique")
    return names


class StandardScaler(BaseModel):
    """Immutable fitted population standard scaler for rectangular rows."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    feature_names: tuple[str, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]

    @model_validator(mode="after")
    def _valid_fitted_state(self) -> Self:
        width = len(self.feature_names)
        if width == 0 or len(self.means) != width or len(self.scales) != width:
            raise ValueError("scaler state must contain one value per feature")
        if any(not name.strip() for name in self.feature_names):
            raise ValueError("feature_names must contain non-empty strings")
        if len(set(self.feature_names)) != width:
            raise ValueError("feature_names must be unique")
        if any(not math.isfinite(value) for value in (*self.means, *self.scales)):
            raise ValueError("scaler state must be finite")
        if any(scale <= 0 for scale in self.scales):
            raise ValueError("scaler scales must be positive")
        return self

    @classmethod
    def fit(
        cls,
        data: Sequence[Sequence[float]],
        feature_names: Sequence[str] | None = None,
    ) -> Self:
        """Fit a scaler without retaining caller-owned mutable values."""
        rows = _numeric_matrix(data)
        names = _feature_order(feature_names, len(rows[0]))
        count = len(rows)
        means = tuple(math.fsum(row[index] for row in rows) / count for index in range(len(names)))
        scales = tuple(
            math.sqrt(math.fsum((row[index] - means[index]) ** 2 for row in rows) / count) or 1.0
            for index in range(len(names))
        )
        return cls(feature_names=names, means=means, scales=scales)

    def transform(self, data: Sequence[Sequence[float]]) -> tuple[tuple[float, ...], ...]:
        """Standardize finite rectangular rows in fitted feature order."""
        rows = self._validate_width(data)
        return tuple(
            tuple(
                (value - mean) / scale
                for value, mean, scale in zip(row, self.means, self.scales, strict=True)
            )
            for row in rows
        )

    def inverse_transform(
        self,
        data: Sequence[Sequence[float]],
    ) -> tuple[tuple[float, ...], ...]:
        """Restore standardized rows to their original scale."""
        rows = self._validate_width(data)
        return tuple(
            tuple(
                value * scale + mean
                for value, mean, scale in zip(row, self.means, self.scales, strict=True)
            )
            for row in rows
        )

    def _validate_width(
        self,
        data: Sequence[Sequence[float]],
    ) -> tuple[tuple[float, ...], ...]:
        rows = _numeric_matrix(data)
        if len(rows[0]) != len(self.feature_names):
            raise ValueError("data width must match the fitted scaler")
        return rows


class WganGpConfig(BaseModel):
    """Strict, deeply immutable WGAN-GP training configuration."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    latent_dim: int = Field(default=128, gt=0)
    generator_hidden: tuple[int, ...] = (256, 256, 256)
    critic_hidden: tuple[int, ...] = (256, 256, 256)
    learning_rate: float = Field(default=1e-4, gt=0)
    beta1: float = Field(default=0.5, ge=0, lt=1)
    beta2: float = Field(default=0.9, ge=0, lt=1)
    gradient_penalty_lambda: float = Field(default=10.0, gt=0)
    critic_steps: int = Field(default=5, gt=0)
    batch_size: int = Field(default=256, gt=0)
    epochs: int = Field(default=300, gt=0)
    seed: int = Field(default=0, ge=0, le=_TORCH_SEED_MAX)

    @field_validator("generator_hidden", "critic_hidden")
    @classmethod
    def _positive_hidden_dimensions(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or any(dimension <= 0 for dimension in value):
            raise ValueError("hidden layer dimensions must be positive and non-empty")
        return value

    @field_validator(
        "learning_rate",
        "beta1",
        "beta2",
        "gradient_penalty_lambda",
    )
    @classmethod
    def _finite_float(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("floating-point configuration values must be finite")
        return value


class WganGpTrainer:
    """Seeded WGAN-GP trainer for synthetic tabular benchmark data."""

    def __init__(self, config: WganGpConfig | None = None) -> None:
        self._config = config or WganGpConfig()
        self._generator: Any = None
        self._critic: Any = None
        self._generation_rng: Any = None
        self._scaler: StandardScaler | None = None
        self._trained = False

    @property
    def is_trained(self) -> bool:
        """Whether training has completed."""
        return self._trained

    @property
    def scaler(self) -> StandardScaler | None:
        """Return the immutable fitted scaler, if available."""
        return self._scaler

    @property
    def feature_names(self) -> tuple[str, ...]:
        """Return fitted feature order as an immutable value."""
        return self._scaler.feature_names if self._scaler is not None else ()

    def fit(
        self,
        data: Sequence[Sequence[float]],
        feature_names: Sequence[str] | None = None,
    ) -> dict[str, list[float]]:
        """Validate, standardize, and train on a finite rectangular matrix."""
        rows = _numeric_matrix(data)
        names = _feature_order(feature_names, len(rows[0]))
        scaler = StandardScaler.fit(rows, names)
        scaled_rows = scaler.transform(rows)
        torch = _import_torch()
        nn = torch.nn
        cfg = self._config

        self._trained = False
        self._scaler = scaler
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(cfg.seed)
            self._generator = self._network(
                nn,
                cfg.latent_dim,
                cfg.generator_hidden,
                len(names),
                batch_normalize=True,
            )
            self._critic = self._network(
                nn,
                len(names),
                cfg.critic_hidden,
                1,
                batch_normalize=False,
            )

        tensor_data = torch.tensor(scaled_rows, dtype=torch.float32)
        dataset = torch.utils.data.TensorDataset(tensor_data)
        shuffle_rng = torch.Generator().manual_seed(cfg.seed)
        training_rng = torch.Generator().manual_seed((cfg.seed + 1) % _TORCH_SEED_MAX)
        self._generation_rng = torch.Generator().manual_seed((cfg.seed + 2) % _TORCH_SEED_MAX)
        dataloader = torch.utils.data.DataLoader(
            dataset,
            batch_size=min(cfg.batch_size, len(dataset)),
            shuffle=True,
            generator=shuffle_rng,
        )
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

        g_losses: list[float] = []
        c_losses: list[float] = []
        for _epoch in range(cfg.epochs):
            epoch_g_loss = 0.0
            epoch_c_loss = 0.0
            n_batches = 0
            for (real_batch,) in dataloader:
                if real_batch.size(0) == 1:
                    real_batch = real_batch.repeat(2, 1)
                batch_size = real_batch.size(0)

                for _ in range(cfg.critic_steps):
                    noise = torch.randn(batch_size, cfg.latent_dim, generator=training_rng)
                    fake = self._generator(noise).detach()
                    c_real = self._critic(real_batch).mean()
                    c_fake = self._critic(fake).mean()
                    alpha = torch.rand(batch_size, 1, generator=training_rng)
                    interpolated = (alpha * real_batch + (1 - alpha) * fake).requires_grad_(True)
                    c_interp = self._critic(interpolated)
                    gradients = torch.autograd.grad(
                        outputs=c_interp,
                        inputs=interpolated,
                        grad_outputs=torch.ones_like(c_interp),
                        create_graph=True,
                    )[0]
                    penalty = ((gradients.norm(2, dim=1) - 1) ** 2).mean()
                    c_loss = c_fake - c_real + cfg.gradient_penalty_lambda * penalty
                    c_optimizer.zero_grad()
                    c_loss.backward()
                    c_optimizer.step()

                noise = torch.randn(batch_size, cfg.latent_dim, generator=training_rng)
                fake = self._generator(noise)
                g_loss = -self._critic(fake).mean()
                g_optimizer.zero_grad()
                g_loss.backward()
                g_optimizer.step()
                epoch_g_loss += float(g_loss.item())
                epoch_c_loss += float(c_loss.item())
                n_batches += 1

            g_losses.append(epoch_g_loss / n_batches)
            c_losses.append(epoch_c_loss / n_batches)

        self._trained = True
        logger.info("wgan_gp_training_complete", epochs=cfg.epochs, features=len(names))
        return {"g_losses": g_losses, "c_losses": c_losses}

    def generate(self, n_samples: int) -> list[list[float]]:
        """Generate inverse-scaled, finite synthetic rows in fitted feature order."""
        if isinstance(n_samples, bool) or not isinstance(n_samples, int) or n_samples < 1:
            raise ValueError("n_samples must be a positive integer")
        if (
            not self._trained
            or self._generator is None
            or self._generation_rng is None
            or self._scaler is None
        ):
            raise RuntimeError("Model must be trained before generating samples.")

        torch = _import_torch()
        self._generator.eval()
        with torch.no_grad():
            noise = torch.randn(
                n_samples,
                self._config.latent_dim,
                generator=self._generation_rng,
            )
            scaled_rows: list[list[float]] = self._generator(noise).tolist()

        rows = self._scaler.inverse_transform(scaled_rows)
        result: list[list[float]] = []
        for row in rows:
            bounded = list(row)
            for index, name in enumerate(self.feature_names):
                bounds = _FEATURE_BOUNDS.get(name.casefold())
                if bounds is not None:
                    bounded[index] = min(max(bounded[index], bounds[0]), bounds[1])
            if not all(math.isfinite(value) for value in bounded):
                raise RuntimeError("generator produced a non-finite value")
            result.append(bounded)
        return result

    @staticmethod
    def _network(
        nn: Any,
        input_dim: int,
        hidden_dims: tuple[int, ...],
        output_dim: int,
        *,
        batch_normalize: bool,
    ) -> Any:
        layers: list[Any] = []
        previous = input_dim
        for hidden in hidden_dims:
            layers.append(nn.Linear(previous, hidden))
            layers.append(nn.BatchNorm1d(hidden) if batch_normalize else nn.LayerNorm(hidden))
            layers.append(nn.LeakyReLU(0.2))
            previous = hidden
        layers.append(nn.Linear(previous, output_dim))
        return nn.Sequential(*layers)


__all__ = ["StandardScaler", "WganGpConfig", "WganGpTrainer"]
