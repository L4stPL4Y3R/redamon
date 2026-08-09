---
name: project-settings-cascade
description: >
  Changing or adding a project setting / default value in RedAmon. A single
  setting is duplicated across Prisma, two separate Python settings modules, the
  orchestrator defaults endpoint, and the frontend fallback; miss a layer and the
  UI shows one value while the backend uses another, and existing projects keep
  the old value forever.
  Trigger: editing a @default in webapp/prisma/schema.prisma; editing
  DEFAULT_AGENT_SETTINGS or fetch_agent_settings in agentic/project_settings.py,
  or DEFAULT_SETTINGS or fetch_project_settings in recon/project_settings.py;
  editing the /defaults endpoint or RUNTIME_ONLY_KEYS in recon_orchestrator/api.py;
  changing a default toggle/number/string in a ProjectForm section.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [webapp, agentic, recon]
  auto_invoke:
    - "Changing or adding a project setting or default value"
    - "Editing a Prisma @default, a Python settings default, or the /defaults endpoint"
---

## When to Use

- Adding a new project setting, or changing the default value of an existing one.

This skill is the settings sub-pattern the tool/skill skills depend on; they link
here rather than restating it. For the surrounding tool wiring, see
`agentic-tool-integration`,
`recon-tool-integration`, or
`builtin-agent-skill`.

---

## Critical Rules

- **NEVER change a default in one layer only.** A setting is synchronized across
  every layer in the table below. Update them in one commit or the UI and backend
  drift silently.
- **NEVER assume existing projects pick up a new/changed default.** A Prisma
  `@default` applies to **new** projects only. Existing rows keep their stored
  value; changing behaviour for them needs an explicit SQL `UPDATE` (ask before
  running it - it mutates every project).
- **NEVER share settings code between agent and recon.** `agentic/project_settings.py`
  and `recon/project_settings.py` are **separate** modules with their own default
  dicts (`DEFAULT_AGENT_SETTINGS` vs `DEFAULT_SETTINGS`). A setting used by both
  is declared in both.
- **NEVER use `prisma migrate`.** This project is push-based:
  `docker compose exec webapp npx prisma db push`.
- **ALWAYS keep the name triad aligned**: DB column `snake_case` (via `@map()`),
  Prisma field + frontend + API `camelCase`, Python key `SCREAMING_SNAKE_CASE`.
  A mismatch means `fetch_*_settings` reads `None` and silently falls back to the default.
- **ALWAYS give the frontend `onChange` a fallback** equal to the Python/Prisma
  default, so a project saved before the field existed does not write `undefined`.

---

## The layers (recon example: `katanaTimeout`)

| Layer | File | Form |
| --- | --- | --- |
| DB / schema | [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma) | `katanaTimeout Int @default(3600) @map("katana_timeout")` |
| Python default | [recon/project_settings.py:21](../../recon/project_settings.py#L21) `DEFAULT_SETTINGS` (or [agentic/project_settings.py](../../agentic/project_settings.py) `DEFAULT_AGENT_SETTINGS`) | `'KATANA_TIMEOUT': 3600` |
| Fetch mapping | [recon/project_settings.py:863](../../recon/project_settings.py#L863) `fetch_project_settings` (or `fetch_agent_settings` in the agent module) | `settings['KATANA_TIMEOUT'] = project.get('katanaTimeout', DEFAULT_SETTINGS['KATANA_TIMEOUT'])` |
| Served defaults | [recon_orchestrator/api.py:576](../../recon_orchestrator/api.py#L576) `/defaults` + `RUNTIME_ONLY_KEYS` | include it, unless it is runtime-only (then add to `RUNTIME_ONLY_KEYS`) |
| Frontend | the tool's `ProjectForm` section component | control with an `onChange` fallback equal to the default |

Agent-only settings use `DEFAULT_AGENT_SETTINGS` + `fetch_agent_settings`; recon-only
use `DEFAULT_SETTINGS` + `fetch_project_settings`. There is no shared module.

## Commands

```bash
docker compose exec webapp npx prisma db push                 # apply schema; NEVER prisma migrate
docker compose build agent && docker compose up -d agent      # only if you changed agentic/ defaults
docker compose restart recon-orchestrator                     # if you changed the /defaults endpoint
# existing projects (ask first - mutates every row):
docker compose exec postgres psql -U redamon -d redamon -c "UPDATE projects SET katana_timeout = 3600 WHERE katana_timeout IS NULL;"
```

## Resources

- Naming + servement details in [readmes/coding_agent_prompts/PROMPT.ADD_RECON_TOOL.md](../../readmes/coding_agent_prompts/PROMPT.ADD_RECON_TOOL.md) (settings multi-layer flow)
- Related skills: `agentic-tool-integration`, `recon-tool-integration`, `recon-ai-enrichment`
