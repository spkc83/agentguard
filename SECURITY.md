# Security Policy

AgentGuard is a security and governance runtime; vulnerabilities in it can have
outsized impact on the agents and services it protects. We take reports seriously
and appreciate responsible disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | Yes       |
| < 0.9   | No        |

AgentGuard is currently in **Alpha** (see [README.md](README.md#current-status-v090-alpha)).
Only the latest `0.9.x` release receives security fixes until a stable 1.0 line exists.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Instead, open a private security advisory on GitHub:
https://github.com/spkc83/agentguard/security/advisories/new

Include as much detail as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code, if available)
- The affected version(s) or commit
- Any suggested remediation, if known

## Scope

The following are explicitly in scope for security reports:

- **Sandbox escapes** — any way to break out of or bypass the tool execution
  sandbox (`agentguard/core/sandbox.py`)
- **Audit-chain forgery** — any way to tamper with, truncate, or forge entries
  in the append-only audit log without detection (`agentguard/core/audit.py`)
- **RBAC bypass** — any way to obtain a permission grant that the configured
  roles should not allow (`agentguard/core/rbac.py`)
- **Circuit breaker / rate limiter bypass** — any way to exceed configured
  limits undetected (`agentguard/core/circuit_breaker.py`)

Issues in third-party dependencies should be reported upstream, but we would
still like to know if they affect AgentGuard's default configuration.

## Disclosure Timeline

- We aim to acknowledge new reports within **5 business days**.
- We will work with you to understand and validate the issue, and to agree on
  a disclosure timeline once a fix is available.
- Credit will be given to reporters in the release notes, unless anonymity is
  requested.
