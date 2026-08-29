"""Acceptance tests for atomic, versioned policy-bundle reloads."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentguard.compliance.engine import PolicyEngine, PolicyReloadResult, PolicyRule
from agentguard.exceptions import PolicyLoadError
from tests.unit.compliance.test_engine import _make_event


def _policy_document(*, rule_id: str, pattern: str, name: str = "Reload") -> str:
    return f"""\
schema_version: 2
name: {name}
version: "1"
rules:
  - id: {rule_id}
    name: Block selected action
    severity: high
    description: Reload acceptance rule
    stage: pre_tool
    applies_to: all
    on_fail: deny
    check:
      type: action_blocklist
      patterns: ["{pattern}"]
    remediation: Use an approved action.
"""


def _write_policy(
    directory: Path,
    *,
    filename: str = "policy.yaml",
    rule_id: str = "RELOAD-01",
    pattern: str = "tool:blocked",
) -> Path:
    path = directory / filename
    path.write_text(_policy_document(rule_id=rule_id, pattern=pattern))
    return path


def test_current_bundle_is_an_immutable_public_snapshot(tmp_path: Path) -> None:
    _write_policy(tmp_path)
    engine = PolicyEngine(policy_dirs=[tmp_path])

    bundle = engine.current_bundle

    assert engine.snapshot() == bundle
    assert isinstance(bundle.policy_sets, tuple)
    assert isinstance(bundle.all_rules, tuple)
    assert isinstance(bundle.rule_ids, tuple | frozenset)
    patterns = bundle.all_rules[0].check["patterns"]
    assert isinstance(patterns, tuple)
    with pytest.raises((AttributeError, TypeError)):
        bundle.version = "sha256:forged"
    with pytest.raises(TypeError):
        patterns[0] = "tool:forged"
    with pytest.raises(TypeError):
        bundle.all_rules[0].check["patterns"] = ("tool:forged",)


async def test_reload_changes_enforcement_without_restarting_engine(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path, pattern="tool:old_block")
    engine = PolicyEngine(policy_dirs=[tmp_path])
    before = await engine.evaluate_stage(_make_event(action="tool:new_block"), "pre_tool")

    policy.write_text(_policy_document(rule_id="RELOAD-01", pattern="tool:new_block"))
    result = await engine.reload()
    after = await engine.evaluate_stage(_make_event(action="tool:new_block"), "pre_tool")

    assert isinstance(result, PolicyReloadResult)
    assert result.changed is True
    assert before[0].passed is True
    assert after[0].passed is False


async def test_semantic_policy_change_bumps_bundle_version(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path, pattern="tool:old_block")
    engine = PolicyEngine(policy_dirs=[tmp_path])
    previous_version = engine.current_bundle.version

    policy.write_text(_policy_document(rule_id="RELOAD-01", pattern="tool:new_block"))
    result = await engine.reload()

    assert result.previous_version == previous_version
    assert result.current_version == engine.current_bundle.version
    assert result.current_version != previous_version


async def test_nonsemantic_file_change_preserves_bundle_version(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path)
    engine = PolicyEngine(policy_dirs=[tmp_path])
    previous_version = engine.current_bundle.version

    policy.write_text("# deployment comment\n\n" + policy.read_text() + "\n")
    result = await engine.reload()

    assert result.changed is False
    assert result.previous_version == previous_version
    assert result.current_version == previous_version


def test_bundle_version_is_independent_of_policy_file_path(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    _write_policy(first_dir, filename="original.yaml")
    _write_policy(second_dir, filename="renamed.yml")

    first = PolicyEngine(policy_dirs=[first_dir])
    second = PolicyEngine(policy_dirs=[second_dir])

    assert first.current_bundle.version == second.current_bundle.version


def test_bundle_version_is_independent_of_multi_file_rename_order(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    (first_dir / "a.yaml").write_text(
        _policy_document(rule_id="ORDER-01", pattern="tool:first", name="Zulu")
    )
    (first_dir / "z.yaml").write_text(
        _policy_document(rule_id="ORDER-02", pattern="tool:second", name="Alpha")
    )
    (second_dir / "a.yaml").write_text((first_dir / "z.yaml").read_text())
    (second_dir / "z.yaml").write_text((first_dir / "a.yaml").read_text())

    first = PolicyEngine(policy_dirs=[first_dir])
    second = PolicyEngine(policy_dirs=[second_dir])

    assert first.current_bundle.version == second.current_bundle.version
    assert [rule.id for rule in first.all_rules] == [rule.id for rule in second.all_rules]


def test_policy_check_rejects_mutable_set_values() -> None:
    with pytest.raises(ValidationError, match="sets are unsupported"):
        PolicyRule(
            id="IMMUTABLE-01",
            name="Immutable",
            severity="low",
            description="test",
            check={"type": "content_scan", "patterns": {"safe"}},
            remediation="use a list",
        )


async def test_invalid_reload_raises_and_leaves_previous_bundle_active(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path)
    engine = PolicyEngine(policy_dirs=[tmp_path])
    previous = engine.current_bundle
    before = await engine.evaluate_stage(_make_event(action="tool:blocked"), "pre_tool")

    policy.write_text("rules: [")
    with pytest.raises(PolicyLoadError):
        await engine.reload()
    after = await engine.evaluate_stage(_make_event(action="tool:blocked"), "pre_tool")

    assert engine.current_bundle == previous
    assert before[0].passed is False
    assert after[0].passed is False


def test_duplicate_disabled_rule_ids_fail_bundle_load(tmp_path: Path) -> None:
    first = _write_policy(tmp_path, filename="first.yaml", rule_id="DUPLICATE-01")
    second = _write_policy(tmp_path, filename="second.yaml", rule_id="DUPLICATE-02")
    second.write_text(
        _policy_document(rule_id="DUPLICATE-01", pattern="tool:other").replace(
            "    remediation: Use an approved action.",
            "    enabled: false\n    remediation: Use an approved action.",
        )
    )

    with pytest.raises(PolicyLoadError, match="duplicate rule ID"):
        PolicyEngine(policy_dirs=[tmp_path])

    assert first.exists()


async def test_concurrent_snapshot_and_reload_never_exposes_partial_bundle(
    tmp_path: Path,
) -> None:
    first = _write_policy(
        tmp_path,
        filename="first.yaml",
        rule_id="OLD-01",
        pattern="tool:old_one",
    )
    second = _write_policy(
        tmp_path,
        filename="second.yaml",
        rule_id="OLD-02",
        pattern="tool:old_two",
    )
    engine = PolicyEngine(policy_dirs=[tmp_path])
    old_bundle = engine.snapshot()
    first.write_text(_policy_document(rule_id="NEW-01", pattern="tool:new_one"))
    second.write_text(_policy_document(rule_id="NEW-02", pattern="tool:new_two"))

    observed_rule_sets: set[frozenset[str]] = {frozenset(old_bundle.rule_ids)}
    reload_task = asyncio.create_task(engine.reload())
    while not reload_task.done():
        observed_rule_sets.add(frozenset(engine.snapshot().rule_ids))
        await asyncio.sleep(0)
    await reload_task
    observed_rule_sets.add(frozenset(engine.snapshot().rule_ids))

    assert observed_rule_sets <= {
        frozenset({"OLD-01", "OLD-02"}),
        frozenset({"NEW-01", "NEW-02"}),
    }
    assert frozenset({"NEW-01", "NEW-02"}) in observed_rule_sets


async def test_historical_bundles_remain_resolvable_after_reload(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path, pattern="tool:old_block")
    engine = PolicyEngine(policy_dirs=[tmp_path])
    previous = engine.snapshot()

    policy.write_text(_policy_document(rule_id="RELOAD-02", pattern="tool:new_block"))
    await engine.reload()
    current = engine.snapshot()

    assert engine.resolve_bundle(previous.version) == previous
    assert engine.resolve_bundle(current.version) == current


async def test_overlapping_reloads_cannot_publish_an_older_request_last(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _write_policy(tmp_path, pattern="tool:initial")
    engine = PolicyEngine(policy_dirs=[tmp_path])
    build = engine._build_bundle
    first_built = threading.Event()
    release_first = threading.Event()
    build_count = 0

    def controlled_build():  # type: ignore[no-untyped-def]
        nonlocal build_count
        build_count += 1
        candidate = build()
        if build_count == 1:
            first_built.set()
            assert release_first.wait(timeout=1)
        return candidate

    monkeypatch.setattr(engine, "_build_bundle", controlled_build)
    policy.write_text(_policy_document(rule_id="RELOAD-01", pattern="tool:first"))
    first_reload = asyncio.create_task(engine.reload())
    assert await asyncio.to_thread(first_built.wait, 1)
    policy.write_text(_policy_document(rule_id="RELOAD-01", pattern="tool:second"))
    second_reload = asyncio.create_task(engine.reload())
    release_first.set()

    await asyncio.gather(first_reload, second_reload)
    first_result = await engine.evaluate_stage(_make_event(action="tool:first"), "pre_tool")
    second_result = await engine.evaluate_stage(_make_event(action="tool:second"), "pre_tool")

    assert first_result[0].passed is True
    assert second_result[0].passed is False
