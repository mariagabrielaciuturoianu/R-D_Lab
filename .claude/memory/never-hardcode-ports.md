---
name: never-hardcode-ports
description: Host ports are read from .env and bound to 127.0.0.1 unless exposure is required
metadata:
  type: feedback
---

Never write a literal host port in `compose.yaml`, nginx configs or scripts. Use
`"127.0.0.1:${DASHBOARDS_PORT}:5601"` and define the value in `.env` (ignored by git;
document defaults in `.env.example`).

**Why:** A hardcoded `5601:5601` binds on every interface and silently widens exposure.
**How to apply:** Review every `ports:` entry for a `${VAR}` and an explicit bind address.
