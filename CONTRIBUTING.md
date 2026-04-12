# Contributing to AgentGuard

Thanks for your interest in contributing! AgentGuard is an open-source agent governance runtime and we welcome contributions of all kinds.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/spkc83/agentguard.git
cd agentguard

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Set the audit key for tests
export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

## Running Tests

```bash
# Unit tests (fast)
pytest tests/unit/ -v

# All tests with coverage
pytest --cov=agentguard --cov-report=term-missing

# Integration tests (requires Docker)
pytest tests/integration/ -v
```

## Code Quality

We use `ruff` for linting and formatting, and `mypy` for type checking. Run these before submitting a PR:

```bash
ruff check . --fix && ruff format .
mypy agentguard/
```

## Submitting Changes

1. Fork the repository and create a feature branch (`feat/your-feature`, `fix/your-fix`)
2. Write tests for your changes — target 80%+ coverage on modified modules
3. Ensure `ruff check .`, `ruff format --check .`, and `mypy agentguard/` pass
4. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
5. Open a pull request against `main`

## Security

- Never commit secrets, API keys, or real PII data
- No dynamic code evaluation in library code
- Report security vulnerabilities privately via GitHub Security Advisories

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
