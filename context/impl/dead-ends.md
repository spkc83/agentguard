---
created: "2026-04-22"
last_edited: "2026-04-22"
---

# Dead Ends

Build site: context/plans/build-site.md.

## T-019, T-020, T-021 — Docker red-team sandbox escape tests

**Blocker:** `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock` in the current non-privileged session. Current user is not in the `docker` group.

**Tests exist and are correct** (`tests/red_team/test_sandbox_escape.py`, 3 test methods, marked `@pytest.mark.integration` + `@pytest.mark.red_team`). Source code in `agentguard/core/sandbox.py` configures `network_disabled`, `mem_limit`, and ephemeral containers per ADR-006.

**Remediation:** Re-run these in CI where the runner has Docker socket access, or run locally after `sudo usermod -aG docker $USER && newgrp docker`. The code path is not in doubt — only the adversarial validation cannot be executed here.
