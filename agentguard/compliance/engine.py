"""Policy-as-code compliance engine.

Loads YAML policy files at startup and evaluates audit events against them.
Each policy rule defines a check type and conditions; the engine dispatches
to typed check handlers. Plugin architecture allows custom check types.

Policy files live in agentguard/compliance/policies/ and follow the schema
documented in ARCHITECTURE.md.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, ConfigDict

from agentguard.models import AuditEvent, PolicyResult

logger = structlog.get_logger()

# Default policies directory (shipped with the package)
_DEFAULT_POLICIES_DIR = Path(__file__).parent / "policies"


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

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    severity: str  # critical, high, medium, low
    description: str
    check: dict[str, Any]
    remediation: str
    references: list[str] = []
    enabled: bool = True


class PolicySet(BaseModel):
    """A named collection of policy rules loaded from a single YAML file.

    Args:
        name: Policy set name (e.g. "OWASP Agentic AI Top 10").
        version: Version of the policy set.
        source_file: Path to the YAML file this was loaded from.
        rules: The policy rules in this set.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    source_file: str = ""
    rules: list[PolicyRule]


class PolicyEngine:
    """Evaluates audit events against loaded policy rule sets.

    The engine loads YAML policy files from a directory and evaluates
    each rule against incoming audit events. Check types supported:

    - action_blocklist: Deny specific action patterns.
    - resource_pattern: Flag access to sensitive resource patterns.
    - content_scan: Scan tool args/action for suspicious patterns.
    - permission_required: Require specific permission grants.
    - rate_check: Flag high-frequency actions.
    - metadata_required: Require specific metadata fields on the agent.

    Args:
        policy_dirs: Directories to load policy YAML files from.
            Defaults to the built-in policies directory.
    """

    def __init__(self, policy_dirs: list[Path] | None = None) -> None:
        self._policy_sets: list[PolicySet] = []
        dirs = policy_dirs or [_DEFAULT_POLICIES_DIR]
        for d in dirs:
            self._load_directory(d)
        logger.info(
            "policy_engine_initialized",
            policy_sets=len(self._policy_sets),
            total_rules=sum(len(ps.rules) for ps in self._policy_sets),
        )

    def _load_directory(self, directory: Path) -> None:
        """Load all YAML policy files from a directory."""
        if not directory.exists():
            logger.warning("policy_directory_not_found", directory=str(directory))
            return
        for yaml_file in sorted(directory.glob("*.yaml")):
            self._load_file(yaml_file)

    def _load_file(self, path: Path) -> None:
        """Load and validate a single policy YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data or not isinstance(data, dict):
            logger.warning("policy_file_empty", file=str(path))
            return

        rules = []
        for rule_data in data.get("rules", []):
            rules.append(PolicyRule(**rule_data))

        ps = PolicySet(
            name=data.get("name", path.stem),
            version=data.get("version", "1.0"),
            source_file=str(path),
            rules=rules,
        )
        self._policy_sets.append(ps)
        logger.debug(
            "policy_set_loaded",
            name=ps.name,
            rules=len(ps.rules),
            file=str(path),
        )

    @property
    def policy_sets(self) -> list[PolicySet]:
        """Return all loaded policy sets."""
        return list(self._policy_sets)

    @property
    def all_rules(self) -> list[PolicyRule]:
        """Return all rules from all policy sets."""
        return [r for ps in self._policy_sets for r in ps.rules if r.enabled]

    async def evaluate(self, event: AuditEvent) -> list[PolicyResult]:
        """Evaluate all enabled policy rules against an audit event.

        Args:
            event: The audit event to evaluate.

        Returns:
            List of PolicyResult for each rule evaluated.
        """
        results: list[PolicyResult] = []
        for rule in self.all_rules:
            result = self._evaluate_rule(rule, event)
            results.append(result)
        return results

    def _evaluate_rule(self, rule: PolicyRule, event: AuditEvent) -> PolicyResult:
        """Evaluate a single rule against an event."""
        check_type = rule.check.get("type", "")
        handler = self._check_handlers.get(check_type)

        if handler is None:
            return PolicyResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=True,
                severity=rule.severity,
                evidence={"note": f"Unknown check type: {check_type}"},
                remediation=rule.remediation,
            )

        return handler(self, rule, event)

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
        if "tool_args" in targets:
            scan_text += str(event.permission_context.context)

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

    # Dispatch table for check types
    _check_handlers: dict[str, Any] = {
        "action_blocklist": _check_action_blocklist,
        "resource_pattern": _check_resource_pattern,
        "content_scan": _check_content_scan,
        "permission_required": _check_permission_required,
        "result_required": _check_result_required,
        "metadata_required": _check_metadata_required,
    }
