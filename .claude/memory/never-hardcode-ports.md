---
name: never-hardcode-ports
description: Host ports come from config/stack.env (override in .env) and bind to 127.0.0.1 unless exposure is required
metadata:
  type: feedback
---

Never write a literal host port in `deploy/compose.yaml`, nginx configs or scripts. Use
`"127.0.0.1:${DASHBOARDS_PORT}:5601"` and define the value in `config/stack.env`
(committed, non-secret); a developer may override it in a local `.env` (git-ignored).
`tests/test_compose_policy.py` fails on any other binding.

**Why:** A hardcoded `5601:5601` binds on every interface and silently widens exposure (R-07).
**How to apply:** Review every `ports:` entry for a `${VAR}` and an explicit bind address.
Non-secret settings never go in a `.env.*` file: the agent's deny rules cover that pattern.
