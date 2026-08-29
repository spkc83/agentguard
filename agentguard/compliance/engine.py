"""Policy-as-code compliance engine.

Loads YAML policy files at startup and evaluates audit events against them.
Each policy rule defines a check type and conditions; the engine dispatches
to typed check handlers. Plugin architecture allows custom check types.

Policy files live in agentguard/compliance/policies/ and follow the schema
documented in ARCHITECTURE.md.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

import structlog
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

from agentguard.exceptions import PolicyLoadError
from agentguard.models import AuditEvent, PolicyResult

Severity = Literal["critical", "high", "medium", "low"]
PolicyStage = Literal["pre_tool", "post_tool", "pre_message", "post_message", "attestation"]
FailureEffect = Literal["deny", "escalate", "warn"]

#: Signature every policy check handler must implement.
CheckHandler = Callable[["PolicyRule", AuditEvent], PolicyResult]

logger = structlog.get_logger()

# Default policies directory (shipped with the package)
_DEFAULT_POLICIES_DIR = Path(__file__).parent / "policies"
_DEFAULT_RUNTIME_TIMEOUT_SECONDS = 1.0


def _freeze_policy_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("policy check keys must be strings")
        return MappingProxyType({key: _freeze_policy_value(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze_policy_value(item) for item in value)
    if isinstance(value, set | frozenset):
        raise ValueError("policy check sets are unsupported; use a list")
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("policy check numbers must be finite")
        return value
    raise ValueError(f"unsupported policy check value: {type(value).__name__}")


def _thaw_policy_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_policy_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_policy_value(item) for item in value]
    return value


class _PolicyHandlerExecutor:
    """Bound blocking policy work and retain capacity until timed-out work exits."""

    def __init__(self, max_workers: int = 4, max_pending: int = 8) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="agentguard-policy",
        )
        self._capacity = threading.BoundedSemaphore(max_workers + max_pending)

    async def call(
        self,
        handler: Callable[[], PolicyResult],
        *,
        timeout: float,
    ) -> PolicyResult:
        if not self._capacity.acquire(blocking=False):
            raise TimeoutError("policy handler capacity exhausted")
        try:
            future = self._pool.submit(handler)
        except BaseException:
            self._capacity.release()
            raise
        future.add_done_callback(lambda _future: self._capacity.release())
        return await asyncio.wait_for(
            asyncio.shield(asyncio.wrap_future(future)),
            timeout=timeout,
        )


_POLICY_HANDLER_EXECUTOR = _PolicyHandlerExecutor()


class PolicyApplicability(BaseModel):
    """Action/resource glob filters for a runtime policy rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: tuple[str, ...] | None = Field(default=None, min_length=1)
    resource: tuple[str, ...] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _require_filter(self) -> PolicyApplicability:
        if self.action is None and self.resource is None:
            raise ValueError("at least one action or resource filter is required")
        for patterns in (self.action, self.resource):
            if patterns is not None and any(not pattern for pattern in patterns):
                raise ValueError("applicability patterns must not be empty")
        return self


class PolicyRule(BaseModel):
    """A single compliance policy rule loaded from YAML.

    Args:
        id: Unique rule identifier (e.g. "OWASP-AGENT-01").
        name: Human-readable rule name.
        severity: Rule severity level.
        description: What this rule checks for.
        check: Check configuration — type and parameters.
        remediation: Recommended fix if the rule fails.
        references: Links to external standards/docs.
        enabled: Whether this rule is active.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9._-]{0,63}$")
    name: str
    severity: Severity
    description: str
    check: Mapping[str, Any]
    remediation: str
    references: tuple[str, ...] = ()
    enabled: bool = True
    stage: PolicyStage = "attestation"
    applies_to: Literal["all"] | PolicyApplicability = "all"
    on_fail: FailureEffect = "warn"

    @field_validator("check", mode="after")
    @classmethod
    def _freeze_check(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast("Mapping[str, Any]", _freeze_policy_value(value))

    @field_serializer("check")
    def _serialize_check(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return cast("dict[str, Any]", _thaw_policy_value(value))

    @model_validator(mode="before")
    @classmethod
    def _accept_deprecated_effect(cls, data: Any) -> Any:
        if not isinstance(data, Mapping) or "effect" not in data:
            return data
        normalized = dict(data)
        effect = normalized.pop("effect")
        if "on_fail" in normalized and normalized["on_fail"] != effect:
            raise ValueError("effect and on_fail must match when both are provided")
        normalized.setdefault("on_fail", effect)
        return normalized


class PolicySet(BaseModel):
    """A named collection of policy rules loaded from a single YAML file.

    Args:
        name: Policy set name (e.g. "OWASP Agentic AI Top 10").
        version: Version of the policy set.
        source_file: Path to the YAML file this was loaded from.
        rules: The policy rules in this set.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str
    schema_version: Literal[1, 2] = 1
    source_file: str = ""
    rules: tuple[PolicyRule, ...]


class PolicyBundleSnapshot(BaseModel):
    """Portable, immutable definition of one content-addressed policy bundle."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_sets: tuple[PolicySet, ...]


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """One immutable, content-addressed policy generation."""

    version: str
    policy_sets: tuple[PolicySet, ...]
    all_rules: tuple[PolicyRule, ...]
    rule_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class PolicyReloadResult:
    """Outcome of atomically rebuilding and activating a policy bundle."""

    changed: bool
    previous_version: str
    current_version: str


class PolicyEngine:
    """Evaluates audit events against loaded policy rule sets.

    The engine loads YAML policy files from a directory and evaluates
    each rule against incoming audit events. Check types supported:

    - action_blocklist: Deny specific action patterns.
    - resource_pattern: Flag access to sensitive resource patterns.
    - content_scan: Scan tool args/action for suspicious patterns.
    - permission_required: Require specific permission grants.
    - result_required: Require the event result to be in an allowed set.
    - metadata_required: Require specific metadata fields on the agent.

    Unknown check types are rejected at load time (ADR-022): a misspelled
    ``check.type`` would otherwise silently turn a control into a rule that
    always passes, which violates the fail-safe-over-fail-open principle.

    Args:
        policy_dirs: Directories to load policy YAML files from.
            Defaults to the built-in policies directory.
        extra_check_handlers: Additional check types, mapping a
            ``check.type`` string to a callable taking ``(rule, event)``
            and returning a PolicyResult. Registered before any policy
            file is read, so custom types load like built-in ones.

    Raises:
        PolicyLoadError: If a rule declares a check type with no handler.
    """

    def __init__(
        self,
        policy_dirs: list[Path] | None = None,
        extra_check_handlers: Mapping[str, CheckHandler] | None = None,
        runtime_timeout_seconds: float = _DEFAULT_RUNTIME_TIMEOUT_SECONDS,
    ) -> None:
        if not math.isfinite(runtime_timeout_seconds) or runtime_timeout_seconds <= 0:
            raise ValueError("runtime_timeout_seconds must be finite and greater than zero")
        self._runtime_timeout_seconds = runtime_timeout_seconds
        self._policy_dirs = tuple(policy_dirs or [_DEFAULT_POLICIES_DIR])
        self._bundle_lock = threading.Lock()
        self._reload_lock = asyncio.Lock()
        # Built-in handlers are bound here so they share the (rule, event)
        # signature that custom handlers use.
        self._check_handlers: dict[str, CheckHandler] = {
            "action_blocklist": self._check_action_blocklist,
            "resource_pattern": self._check_resource_pattern,
            "content_scan": self._check_content_scan,
            "permission_required": self._check_permission_required,
            "result_required": self._check_result_required,
            "metadata_required": self._check_metadata_required,
        }
        if extra_check_handlers:
            self._check_handlers.update(extra_check_handlers)
        self._check_handlers = dict(self._check_handlers)

        initial_bundle = self._build_bundle()
        self._current_bundle = initial_bundle
        self._bundle_history: dict[str, PolicyBundle] = {initial_bundle.version: initial_bundle}
        logger.info(
            "policy_engine_initialized",
            policy_sets=len(initial_bundle.policy_sets),
            total_rules=len(initial_bundle.all_rules),
            bundle_version=initial_bundle.version,
        )

    @property
    def check_types(self) -> list[str]:
        """Return the check types this engine can evaluate, sorted."""
        return sorted(self._check_handlers)

    def _load_directory(self, directory: Path) -> list[PolicySet]:
        """Load all YAML policy files from a directory."""
        if not directory.exists():
            logger.warning("policy_directory_not_found", directory=str(directory))
            return []
        yaml_files = [*directory.glob("*.yaml"), *directory.glob("*.yml")]
        policy_sets: list[PolicySet] = []
        for yaml_file in sorted(yaml_files):
            policy_set = self._load_file(yaml_file)
            if policy_set is not None:
                policy_sets.append(policy_set)
        return policy_sets

    def _load_file(self, path: Path) -> PolicySet | None:
        """Load and validate a single policy YAML file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise PolicyLoadError(
                file=str(path), rule_id="<file>", detail=f"YAML syntax error: {exc}"
            ) from exc

        if not data:
            logger.warning("policy_file_empty", file=str(path))
            return None
        if not isinstance(data, dict):
            raise PolicyLoadError(
                file=str(path),
                rule_id="<file>",
                detail="validation error: policy document must be a mapping",
            )

        schema_version = data.get("schema_version", 1)
        if schema_version not in {1, 2}:
            raise PolicyLoadError(
                file=str(path),
                rule_id="<file>",
                detail=f"unsupported policy schema_version {schema_version!r}",
            )

        rule_data_items = data.get("rules", [])
        if not isinstance(rule_data_items, list):
            raise PolicyLoadError(
                file=str(path),
                rule_id="<file>",
                detail="validation error: rules must be a list",
            )

        rules: list[PolicyRule] = []
        for index, rule_data in enumerate(rule_data_items):
            rule_id = (
                str(rule_data.get("id", f"<rule {index}>"))
                if isinstance(rule_data, Mapping)
                else f"<rule {index}>"
            )
            if schema_version == 2 and isinstance(rule_data, Mapping):
                missing = [
                    field for field in ("stage", "applies_to", "on_fail") if field not in rule_data
                ]
                if missing:
                    raise PolicyLoadError(
                        file=str(path),
                        rule_id=rule_id,
                        detail=("schema v2 rules require explicit fields: " + ", ".join(missing)),
                    )
            try:
                rule = PolicyRule.model_validate(rule_data)
            except ValidationError as exc:
                raise PolicyLoadError(
                    file=str(path),
                    rule_id=rule_id,
                    detail=f"validation error: {exc}",
                ) from exc
            check_type = rule.check.get("type")
            if check_type not in self._check_handlers:
                raise PolicyLoadError(
                    file=str(path),
                    rule_id=rule.id,
                    detail=(f"unknown check type {check_type!r}; known: {self.check_types}"),
                )
            rules.append(rule)

        try:
            ps = PolicySet(
                name=data.get("name", path.stem),
                version=data.get("version", "1.0"),
                schema_version=schema_version,
                source_file=str(path),
                rules=tuple(rules),
            )
        except ValidationError as exc:
            raise PolicyLoadError(
                file=str(path), rule_id="<file>", detail=f"validation error: {exc}"
            ) from exc
        logger.debug(
            "policy_set_loaded",
            name=ps.name,
            rules=len(ps.rules),
            file=str(path),
        )
        return ps

    def _build_bundle(self) -> PolicyBundle:
        loaded_policy_sets = tuple(
            policy_set
            for directory in self._policy_dirs
            for policy_set in self._load_directory(directory)
        )
        return self._bundle_from_policy_sets(loaded_policy_sets)

    @classmethod
    def _canonical_policy_sets(
        cls,
        policy_sets: tuple[PolicySet, ...],
    ) -> tuple[PolicySet, ...]:
        return tuple(
            sorted(
                policy_sets,
                key=lambda policy_set: json.dumps(
                    cls._policy_set_payload(policy_set),
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        )

    def _bundle_from_policy_sets(
        self,
        policy_sets: tuple[PolicySet, ...],
    ) -> PolicyBundle:
        """Validate policy-set relationships and build an immutable bundle."""

        policy_sets = self._canonical_policy_sets(policy_sets)
        declared_rules = tuple(rule for policy_set in policy_sets for rule in policy_set.rules)
        declared_rule_ids = frozenset(rule.id for rule in declared_rules)
        if len(declared_rule_ids) != len(declared_rules):
            duplicate_ids = sorted(
                rule_id
                for rule_id in declared_rule_ids
                if sum(rule.id == rule_id for rule in declared_rules) > 1
            )
            raise PolicyLoadError(
                file="<bundle>",
                rule_id=duplicate_ids[0],
                detail="duplicate rule ID across policy files",
            )
        for policy_set in policy_sets:
            for rule in policy_set.rules:
                check_type = rule.check.get("type")
                if check_type not in self._check_handlers:
                    raise PolicyLoadError(
                        file=policy_set.source_file or "<snapshot>",
                        rule_id=rule.id,
                        detail=(f"unknown check type {check_type!r}; known: {self.check_types}"),
                    )
        all_rules = tuple(rule for rule in declared_rules if rule.enabled)
        rule_ids = frozenset(rule.id for rule in all_rules)
        version = self._bundle_digest(policy_sets)
        return PolicyBundle(
            version=version,
            policy_sets=policy_sets,
            all_rules=all_rules,
            rule_ids=rule_ids,
        )

    @staticmethod
    def _policy_set_payload(policy_set: PolicySet) -> dict[str, Any]:
        return {
            "name": policy_set.name,
            "version": policy_set.version,
            "schema_version": policy_set.schema_version,
            "rules": [rule.model_dump(mode="json") for rule in policy_set.rules],
        }

    @classmethod
    def _bundle_digest(cls, policy_sets: tuple[PolicySet, ...]) -> str:
        payload = [cls._policy_set_payload(policy_set) for policy_set in policy_sets]
        canonical = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"

    @property
    def current_bundle(self) -> PolicyBundle:
        """Return the active immutable policy generation."""

        return self.snapshot()

    def snapshot(self) -> PolicyBundle:
        """Pin the active bundle for a complete governed invocation."""

        with self._bundle_lock:
            return self._current_bundle

    def export_bundle(self, bundle: PolicyBundle) -> PolicyBundleSnapshot:
        """Export a canonical, path-independent snapshot for restart-safe restore.

        The snapshot binds policy definitions and check-type names. It cannot bind
        custom handler implementation semantics because handlers currently have no
        declared semantic version; callers must register the same implementation
        when restoring a bundle that uses a custom check type.
        """

        policy_sets = self._canonical_policy_sets(
            tuple(
                PolicySet.model_validate(
                    {
                        **policy_set.model_dump(mode="json", exclude={"source_file"}),
                        "source_file": "",
                    }
                )
                for policy_set in bundle.policy_sets
            )
        )
        canonical_version = self._bundle_digest(policy_sets)
        if canonical_version != bundle.version:
            raise PolicyLoadError(
                file="<bundle>",
                rule_id="<bundle>",
                detail="bundle version does not match canonical policy definitions",
            )
        return PolicyBundleSnapshot(version=bundle.version, policy_sets=policy_sets)

    def restore_bundle(self, snapshot: PolicyBundleSnapshot) -> PolicyBundle:
        """Validate and retain an exact bundle snapshot without activating it.

        Restore fails closed if the digest is invalid or any declared check type
        lacks a registered handler. As with :meth:`export_bundle`, custom handler
        semantic equivalence cannot be verified until handlers expose versions.
        The active bundle is never substituted for the requested generation.
        """

        candidate = self._bundle_from_policy_sets(snapshot.policy_sets)
        if candidate.version != snapshot.version:
            raise PolicyLoadError(
                file="<snapshot>",
                rule_id="<bundle>",
                detail="snapshot version does not match canonical policy definitions",
            )
        with self._bundle_lock:
            self._bundle_history[candidate.version] = candidate
        return candidate

    async def reload(self) -> PolicyReloadResult:
        """Build, validate, and atomically activate the configured policy files."""

        async with self._reload_lock:
            candidate = await asyncio.to_thread(self._build_bundle)
            with self._bundle_lock:
                previous = self._current_bundle
                self._bundle_history.setdefault(candidate.version, candidate)
                if candidate.version != previous.version:
                    self._current_bundle = candidate
                current = self._current_bundle
        logger.info(
            "policy_bundle_reloaded",
            changed=current.version != previous.version,
            previous_version=previous.version,
            current_version=current.version,
        )
        return PolicyReloadResult(
            changed=current.version != previous.version,
            previous_version=previous.version,
            current_version=current.version,
        )

    def resolve_bundle(self, version: str) -> PolicyBundle | None:
        """Resolve a bundle generation retained by this engine instance."""

        with self._bundle_lock:
            return self._bundle_history.get(version)

    @property
    def policy_sets(self) -> list[PolicySet]:
        """Return all loaded policy sets."""
        return list(self.snapshot().policy_sets)

    @property
    def all_rules(self) -> list[PolicyRule]:
        """Return all rules from all policy sets."""
        return list(self.snapshot().all_rules)

    @property
    def bundle_version(self) -> str:
        """Return a path-independent canonical digest of the loaded policy bundle."""

        return self.snapshot().version

    async def evaluate(
        self,
        event: AuditEvent,
        *,
        bundle: PolicyBundle | None = None,
    ) -> list[PolicyResult]:
        """Evaluate all enabled policy rules against an audit event.

        Args:
            event: The audit event to evaluate.

        Returns:
            List of PolicyResult for each rule evaluated.
        """
        results: list[PolicyResult] = []
        active_bundle = bundle or self.snapshot()
        for rule in active_bundle.all_rules:
            result = await _POLICY_HANDLER_EXECUTOR.call(
                partial(self._evaluate_rule, rule, event),
                timeout=self._runtime_timeout_seconds,
            )
            results.append(result)
        return results

    async def evaluate_stage(
        self,
        event: AuditEvent,
        stage: PolicyStage,
        *,
        bundle: PolicyBundle | None = None,
    ) -> list[PolicyResult]:
        """Evaluate applicable rules for one runtime stage.

        Handler exceptions intentionally propagate so the governance pipeline can
        convert them into its fail-closed denial path.
        """
        results: list[PolicyResult] = []
        active_bundle = bundle or self.snapshot()
        for rule in active_bundle.all_rules:
            if rule.stage != stage or not self._rule_applies(rule, event):
                continue
            result = await _POLICY_HANDLER_EXECUTOR.call(
                partial(self._evaluate_rule, rule, event),
                timeout=self._runtime_timeout_seconds,
            )
            effect = "allow" if result.passed else rule.on_fail
            results.append(result.model_copy(update={"effect": effect}))
        return results

    @staticmethod
    def _rule_applies(rule: PolicyRule, event: AuditEvent) -> bool:
        """Return whether an event matches every configured applicability field."""
        if rule.applies_to == "all":
            return True
        values = {"action": event.action, "resource": event.resource}
        return all(
            patterns is None
            or any(
                fnmatchcase(values[field].casefold(), pattern.casefold()) for pattern in patterns
            )
            for field, patterns in (
                ("action", rule.applies_to.action),
                ("resource", rule.applies_to.resource),
            )
        )

    def _evaluate_rule(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Evaluate a single rule against an event.

        Raises:
            PolicyLoadError: Defensive guard — unknown check types are
                rejected at load time, so reaching this branch means a rule
                was injected after construction.
        """
        check_type = rule.check.get("type", "")
        handler = self._check_handlers.get(check_type)

        if handler is None:  # pragma: no cover - blocked at load time
            raise PolicyLoadError(
                file="<runtime>",
                rule_id=rule.id,
                detail=f"unknown check type {check_type!r}; known: {self.check_types}",
            )

        return handler(rule, event)

    def _check_action_blocklist(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Check if the action matches any blocked pattern."""
        patterns = rule.check.get("patterns", [])
        for pattern in patterns:
            if re.search(pattern, event.action):
                return PolicyResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    passed=False,
                    severity=rule.severity,
                    evidence={"matched_pattern": pattern, "action": event.action},
                    remediation=rule.remediation,
                )
        return PolicyResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=True,
            severity=rule.severity,
            evidence={"action": event.action},
            remediation=rule.remediation,
        )

    def _check_resource_pattern(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Check if resource access matches a sensitive pattern."""
        patterns = rule.check.get("patterns", [])
        for pattern in patterns:
            if re.search(pattern, event.resource):
                return PolicyResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    passed=False,
                    severity=rule.severity,
                    evidence={"matched_pattern": pattern, "resource": event.resource},
                    remediation=rule.remediation,
                )
        return PolicyResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=True,
            severity=rule.severity,
            evidence={"resource": event.resource},
            remediation=rule.remediation,
        )

    def _check_content_scan(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Scan action and resource for suspicious content patterns."""
        patterns = rule.check.get("patterns", [])
        targets = rule.check.get("targets", ["action", "resource"])
        scan_text = ""
        if "action" in targets:
            scan_text += event.action + " "
        if "resource" in targets:
            scan_text += event.resource + " "
        context = event.permission_context.context
        if "tool_args" in targets:
            scan_text += str(context.get("tool_args", "")) + " "
        if "tool_result" in targets:
            scan_text += str(context.get("tool_result", "")) + " "

        scan_text = scan_text.lower()
        for pattern in patterns:
            if pattern.lower() in scan_text:
                return PolicyResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    passed=False,
                    severity=rule.severity,
                    evidence={"matched_pattern": pattern, "target_text": scan_text[:200]},
                    remediation=rule.remediation,
                )
        return PolicyResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=True,
            severity=rule.severity,
            evidence={"scanned_targets": targets},
            remediation=rule.remediation,
        )

    def _check_permission_required(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Check that the event has proper permission grants."""
        if event.result == "denied":
            return PolicyResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=True,
                severity=rule.severity,
                evidence={"note": "Action was denied by RBAC"},
                remediation=rule.remediation,
            )
        require_granted = rule.check.get("require_granted", True)
        passed = event.permission_context.granted == require_granted
        return PolicyResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=passed,
            severity=rule.severity,
            evidence={
                "granted": event.permission_context.granted,
                "required": require_granted,
            },
            remediation=rule.remediation,
        )

    def _check_result_required(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Check that the event result matches expected values."""
        allowed_results = rule.check.get("allowed_results", ["allowed", "denied"])
        passed = event.result in allowed_results
        return PolicyResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=passed,
            severity=rule.severity,
            evidence={
                "actual_result": event.result,
                "allowed_results": allowed_results,
            },
            remediation=rule.remediation,
        )

    def _check_metadata_required(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Check that the agent's identity has required metadata fields."""
        required_fields = rule.check.get("required_fields", [])
        agent_metadata = event.permission_context.agent.metadata
        missing = [f for f in required_fields if f not in agent_metadata]
        return PolicyResult(
            rule_id=rule.id,
            rule_name=rule.name,
            passed=len(missing) == 0,
            severity=rule.severity,
            evidence={
                "required_fields": required_fields,
                "missing_fields": missing,
            },
            remediation=rule.remediation,
        )
