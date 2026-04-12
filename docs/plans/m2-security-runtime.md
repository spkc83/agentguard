# M2: Full Security Runtime + MCP Middleware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Complete Layer 1 of AgentGuard — circuit breaker with rate limiting, sandboxed tool execution (Docker + NoOp backends), file-backed agent registry, MCP middleware that governs tool calls end-to-end, and CLI audit replay.

**Architecture:** The circuit breaker and sandbox are standalone core components that plug into the existing identity - RBAC - audit pipeline. The MCP middleware orchestrates the full flow: resolve identity - check RBAC - circuit breaker - audit log - sandbox run. The file-backed registry upgrades the in-memory AgentRegistry to persist agents as a JSON file with atomic writes.

**Tech Stack:** Python 3.11+, Pydantic v2, asyncio, Docker SDK (docker package), structlog, Typer/Rich CLI, mcp SDK for MCP middleware.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | agentguard/core/circuit_breaker.py | Circuit breaker (CLOSED/OPEN/HALF_OPEN) + token bucket rate limiter |
| Create | agentguard/core/sandbox.py | SandboxBackend protocol, DockerSandboxBackend, NoOpSandboxBackend |
| Modify | agentguard/core/identity.py | Add FileBackedRegistry alongside existing AgentRegistry |
| Modify | agentguard/core/__init__.py | Re-export new public classes |
| Create | agentguard/integrations/mcp_middleware.py | GovernedMcpClient wrapping MCP ClientSession |
| Modify | agentguard/cli.py | Add audit replay subcommand |
| Modify | agentguard/exceptions.py | Add RateLimitExceededError |
| Create | tests/unit/core/test_circuit_breaker.py | Circuit breaker + rate limiter unit tests |
| Create | tests/unit/core/test_sandbox.py | Sandbox unit tests (NoOp backend, Docker mocked) |
| Create | tests/unit/core/test_file_registry.py | File-backed registry unit tests |
| Create | tests/unit/test_mcp_middleware.py | MCP middleware unit tests (mocked MCP session) |
| Create | tests/unit/test_cli_replay.py | CLI replay command tests |
| Create | tests/integration/test_sandbox_docker.py | Real Docker sandbox integration test |
| Create | tests/red_team/test_sandbox_escape.py | Red team sandbox escape attempts |

---

## Task 1: Circuit Breaker

**Files:**
- Create: agentguard/core/circuit_breaker.py
- Modify: agentguard/exceptions.py (add RateLimitExceededError)
- Create: tests/unit/core/test_circuit_breaker.py

### Circuit Breaker Design

Three states: CLOSED (normal), OPEN (rejecting), HALF_OPEN (testing recovery).
- CLOSED: passes calls through. Tracks consecutive failures.
- When failures >= failure_threshold, transitions to OPEN.
- OPEN: rejects all calls with CircuitOpenError. After recovery_timeout seconds, transitions to HALF_OPEN.
- HALF_OPEN: allows one call through. If it succeeds, moves to CLOSED. If it fails, moves to OPEN.

Rate limiter: token bucket algorithm per agent identity. Configurable max_tokens and refill_rate (tokens/second).

- [ ] Step 1: Add RateLimitExceededError to exceptions.py
- [ ] Step 2: Write failing tests for circuit breaker and rate limiter (11 tests)
- [ ] Step 3: Run tests to verify they fail (ImportError expected)
- [ ] Step 4: Implement CircuitBreaker with CircuitState enum and TokenBucketRateLimiter
- [ ] Step 5: Run tests to verify they pass
- [ ] Step 6: Commit

Key implementation details:
- CircuitBreaker.state property checks if recovery_timeout has elapsed to return HALF_OPEN
- CircuitBreaker.call(fn, *args, **kwargs) is the main entry point
- TokenBucketRateLimiter uses per-agent buckets stored as dict of (tokens, last_time) tuples
- Both use asyncio.Lock for thread safety

---

## Task 2: Sandbox

**Files:**
- Create: agentguard/core/sandbox.py
- Create: tests/unit/core/test_sandbox.py
- Create: tests/integration/test_sandbox_docker.py
- Create: tests/red_team/__init__.py
- Create: tests/red_team/test_sandbox_escape.py

### Sandbox Design

SandboxBackend is a Protocol with: async def run(command, config) -> SandboxResult
- SandboxConfig: Pydantic model with timeout_seconds (30.0), network_enabled (False), memory_limit_mb (256)
- NoOpSandboxBackend: runs commands via asyncio.create_subprocess_exec with timeout enforcement
- DockerSandboxBackend: runs commands in ephemeral Docker containers with resource limits
- SandboxResult model already exists in agentguard/models.py

- [ ] Step 1: Write failing tests for NoOpSandboxBackend (4 tests) and SandboxConfig (2 tests)
- [ ] Step 2: Run tests to verify they fail
- [ ] Step 3: Implement sandbox module with SandboxConfig, NoOpSandboxBackend, DockerSandboxBackend
- [ ] Step 4: Run tests to verify they pass
- [ ] Step 5: Create red team test stubs (marked @pytest.mark.integration @pytest.mark.red_team)
- [ ] Step 6: Create Docker integration test (marked @pytest.mark.integration)
- [ ] Step 7: Commit

Key implementation details:
- NoOpSandboxBackend uses asyncio.create_subprocess_exec (not shell=True)
- Timeout via asyncio.wait_for, returns exit_code=137 on timeout
- DockerSandboxBackend lazy-imports docker SDK, raises SandboxError if not installed
- Docker containers run with network_disabled, mem_limit, detach=True, remove after

---

## Task 3: File-Backed Agent Registry

**Files:**
- Modify: agentguard/core/identity.py
- Create: tests/unit/core/test_file_registry.py

### Design

FileBackedRegistry wraps AgentRegistry and persists to a JSON file. Uses atomic writes (write to temp file, then os.replace) to prevent corruption. Loads existing agents from file on construction.

- [ ] Step 1: Write failing tests for FileBackedRegistry (6 tests: persist, survive restart, list after restart, duplicate raises, not found raises, empty init)
- [ ] Step 2: Run tests to verify they fail
- [ ] Step 3: Implement FileBackedRegistry in identity.py
- [ ] Step 4: Run tests to verify they pass
- [ ] Step 5: Commit

Key implementation details:
- Constructor takes Path, loads existing agents via _load_sync()
- _persist() writes JSON atomically via .tmp + os.replace
- Delegates to internal AgentRegistry for in-memory operations
- Uses asyncio.Lock for write serialization

---

## Task 4: MCP Middleware

**Files:**
- Create: agentguard/integrations/mcp_middleware.py
- Create: tests/unit/test_mcp_middleware.py

### Design

GovernedMcpClient wraps an MCP ClientSession and intercepts call_tool with the full governance pipeline: identity resolve, RBAC check, circuit breaker, audit log (before), tool call, audit log (after). All dependencies injected via constructor. Tests mock the MCP session interface.

- [ ] Step 1: Write failing tests (4 tests: allowed call, denied call, audit events written, denied audit event)
- [ ] Step 2: Run tests to verify they fail
- [ ] Step 3: Implement GovernedMcpClient
- [ ] Step 4: Run tests to verify they pass
- [ ] Step 5: Commit

Key implementation details:
- McpSession Protocol: just needs async call_tool(tool_name, arguments)
- call_tool flow: resolve identity, check RBAC, if denied: audit + raise PermissionDeniedError, if allowed: audit (pre), call through circuit breaker, return result
- Resource parameter defaults to "*" but caller should provide specific resource pattern
- Audit events use log-first-act-second pattern

---

## Task 5: CLI Audit Replay

**Files:**
- Modify: agentguard/cli.py
- Create: tests/unit/test_cli_replay.py

### Design

`agentguard audit replay --log-dir <dir>` reads all audit events and displays them sequentially with Rich formatting. Shows each event's action, result, permission context, and timing.

- [ ] Step 1: Write failing tests (3 tests: replay with events, empty log, JSON output)
- [ ] Step 2: Run tests to verify they fail
- [ ] Step 3: Add replay command to CLI
- [ ] Step 4: Run tests to verify they pass
- [ ] Step 5: Commit

---

## Task 6: Update Exports and Polish

**Files:**
- Modify: agentguard/core/__init__.py
- Modify: agentguard/integrations/__init__.py

- [ ] Step 1: Update core __init__.py with CircuitBreaker, CircuitState, TokenBucketRateLimiter, FileBackedRegistry, sandbox classes
- [ ] Step 2: Update integrations __init__.py with GovernedMcpClient
- [ ] Step 3: Run full test suite with coverage
- [ ] Step 4: Run linter
- [ ] Step 5: Commit

---

## Task 7: Version Bump and Final Verification

**Files:**
- Modify: agentguard/__init__.py (version bump)
- Modify: pyproject.toml (version bump)

- [ ] Step 1: Bump version to 0.2.0 in pyproject.toml and __init__.py
- [ ] Step 2: Run full test suite with coverage (target: 85%+ on core/)
- [ ] Step 3: Run linter and type checker
- [ ] Step 4: Run quickstart example to verify backward compatibility
- [ ] Step 5: Commit and tag v0.2.0
