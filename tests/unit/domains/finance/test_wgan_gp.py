from __future__ import annotations

import math
from typing import Any

import pytest
from pydantic import ValidationError

from agentguard.testing.wgan_gp import StandardScaler, WganGpConfig, WganGpTrainer


def _tiny_config(*, seed: int = 17) -> WganGpConfig:
    return WganGpConfig(
        latent_dim=3,
        generator_hidden=(4,),
        critic_hidden=(4,),
        learning_rate=0.001,
        beta1=0.5,
        beta2=0.9,
        gradient_penalty_lambda=1.0,
        critic_steps=1,
        batch_size=2,
        epochs=1,
        seed=seed,
    )


def _torch() -> Any:
    return pytest.importorskip("torch")


def test_scaler_is_immutable_and_round_trips_constant_columns() -> None:
    data = ((300.0, 7.0), (850.0, 7.0), (575.0, 7.0))
    scaler = StandardScaler.fit(data, ("fico_score", "constant"))

    assert scaler.feature_names == ("fico_score", "constant")
    assert scaler.scales[1] == 1.0
    transformed = scaler.transform(data)
    restored = scaler.inverse_transform(transformed)
    for actual, expected in zip(restored, data, strict=True):
        assert actual == pytest.approx(expected)
    with pytest.raises(ValidationError):
        scaler.means = (0.0, 0.0)  # type: ignore[misc]


@pytest.mark.parametrize(
    ("data", "names"),
    [
        ([], None),
        ([[]], None),
        ([[1.0], [1.0, 2.0]], None),
        ([[math.nan]], None),
        ([[math.inf]], None),
        ([[True]], None),
        ([[1.0]], []),
        ([[1.0, 2.0]], ["same", "same"]),
        ([[1.0]], [""]),
    ],
)
def test_scaler_rejects_invalid_inputs(
    data: list[list[float]],
    names: list[str] | None,
) -> None:
    with pytest.raises(ValueError):
        StandardScaler.fit(data, names)


def test_config_is_strict_deeply_immutable_and_validated() -> None:
    config = _tiny_config()
    assert config.generator_hidden == (4,)
    with pytest.raises(ValidationError):
        config.generator_hidden = (8,)  # type: ignore[misc]
    with pytest.raises(ValidationError):
        WganGpConfig(generator_hidden=())
    with pytest.raises(ValidationError):
        WganGpConfig(seed=-1)
    with pytest.raises(ValidationError):
        WganGpConfig(learning_rate=math.inf)
    with pytest.raises(ValidationError):
        WganGpConfig(latent_dim="3")  # type: ignore[arg-type]


def test_scaler_rejects_invalid_direct_state() -> None:
    with pytest.raises(ValidationError):
        StandardScaler(feature_names=("x",), means=(0.0,), scales=(0.0,))
    with pytest.raises(ValidationError):
        StandardScaler(feature_names=("x",), means=(0.0, 1.0), scales=(1.0,))


def test_trainer_rejects_invalid_generation_requests() -> None:
    trainer = WganGpTrainer(_tiny_config())
    with pytest.raises(ValueError):
        trainer.generate(0)
    with pytest.raises(ValueError):
        trainer.generate(True)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError):
        trainer.generate(1)


def test_fit_validates_before_optional_torch_import(monkeypatch: pytest.MonkeyPatch) -> None:
    import agentguard.testing.wgan_gp as module

    monkeypatch.setattr(module, "_import_torch", lambda: pytest.fail("torch imported"))
    with pytest.raises(ValueError, match="rectangular"):
        WganGpTrainer(_tiny_config()).fit([[1.0], [1.0, 2.0]])


def test_generate_one_is_finite_inverse_scaled_and_domain_bounded() -> None:
    _torch()
    trainer = WganGpTrainer(_tiny_config())
    trainer.fit(
        [[300.0, 0.1, 0.5], [850.0, 0.9, 1.5], [600.0, 0.4, 0.8]],
        ["fico_score", "dti_ratio", "ltv_ratio"],
    )

    generated = trainer.generate(1)

    assert len(generated) == 1
    assert all(math.isfinite(value) for value in generated[0])
    assert 300.0 <= generated[0][0] <= 850.0
    assert 0.0 <= generated[0][1] <= 1.0
    assert 0.0 <= generated[0][2] <= 2.0
    assert trainer.feature_names == ("fico_score", "dti_ratio", "ltv_ratio")
    assert trainer.scaler is not None


def test_equal_seed_is_reproducible_despite_ambient_rng_changes() -> None:
    torch = _torch()
    data = [[350.0, 0.2], [700.0, 0.6], [800.0, 0.3]]
    names = ["fico_score", "dti_ratio"]

    torch.manual_seed(999)
    first = WganGpTrainer(_tiny_config(seed=41))
    first.fit(data, names)
    first_output = first.generate(2)

    torch.manual_seed(2)
    second = WganGpTrainer(_tiny_config(seed=41))
    second.fit(data, names)
    second_output = second.generate(2)

    assert second_output == first_output


def test_legacy_namespace_reexports_canonical_types() -> None:
    from agentguard.domains.finance.synthetic.wgan_gp import StandardScaler as LegacyScaler
    from agentguard.domains.finance.synthetic.wgan_gp import WganGpConfig as LegacyConfig
    from agentguard.domains.finance.synthetic.wgan_gp import WganGpTrainer as LegacyTrainer

    assert LegacyScaler is StandardScaler
    assert LegacyConfig is WganGpConfig
    assert LegacyTrainer is WganGpTrainer
