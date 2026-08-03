---
id: TASK-18
title: 'Docs: fix doc-claim drift detected on 2026-08-03'
status: To Do
assignee: []
created_date: '2026-08-03 00:00'
updated_date: '2026-08-03 00:00'
labels:
  - docs
dependencies: []
priority: Low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated doc-drift scan run on 2026-08-03 against the 12-file audit set. Twelve concrete claim discrepancies found across 9 files. Findings are grouped by severity and then by file. Note: TASK-17 (referenced in `docs/vulnerability-inventory.md`) is a separate ongoing vulnerability-reconciliation task and is NOT this task.

### P1 — Dev-doc errors (affects correctness, likely to mislead developers)

#### docs/architecture.md

- `docs/architecture.md:165` — `| DEMO_MODE | true | ...` — Default value `true` is not a valid DEMO_MODE option (valid: `full`, `strict`). Actual code default: `'full'` (see `app/config.py:32`: `os.environ.get('DEMO_MODE', 'full')`). Proposed fix: change default column from `true` to `full`.

- `docs/architecture.md` (directory listing lines 88–116) — `education/` blueprint is missing from the `app/blueprints/` directory listing. The blueprint directory `apps/vuln-api/app/blueprints/education/` exists and is imported at `apps/vuln-api/app/asgi.py:185` (`from app.blueprints.education import education_router`). Proposed fix: add `├── education/            # Education (N routes)` to the listing.

#### docs/developer-guide.md

- `docs/developer-guide.md:148` — `"hatchling, with \`force-include\` ensuring \`web_dist/\` makes it into the wheel despite being gitignored"` — `apps/vuln-api/pyproject.toml` `[tool.hatch.build.targets.wheel]` block contains only `packages = ["app"]`; there is no `force-include` directive. Proposed fix: either add the `force-include` directive to pyproject.toml or remove the claim from the doc.

- `docs/developer-guide.md:333` — `# Output: apps/vuln-api/dist/chimera_api-0.1.0-py3-none-any.whl` — Version `0.1.0` is stale; `apps/vuln-api/pyproject.toml:8` shows `version = "0.1.5"`. Proposed fix: update to `0.1.5` (or use a glob pattern to avoid re-drifting).

#### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:14` and `:599` — Same document claims **469 unique endpoints** (lines 4, 14, 590) and **243 Total Routes** (line 599: "✅ 243 Total Routes: Comprehensive coverage…"). These two counts are internally inconsistent by 226 routes. Proposed fix: reconcile both numbers or remove the "243 Total Routes" implementation-status callout.

#### README.md

- `README.md:47` — `| DEMO_MODE | strict | ... |` — The general "Environment Variables" table (not Docker-specific) claims the default is `strict`. The application code default (`app/config.py:32`) is `full`. The production Docker image (`Dockerfile.prod:39`) sets `DEMO_MODE=strict` as an env override, but that is a Docker-layer default, not the application default for pip installs. Proposed fix: change Default column to `full` (matching config.py) and add a note that `Dockerfile.prod` overrides to `strict`.

#### AGENTS.md (root)

- `AGENTS.md:116` — `"In production (Docker), nginx handles the proxy."` — No nginx is present in any of the three Dockerfiles (`Dockerfile`, `Dockerfile.prod`, `Dockerfile.fargate`). All use uvicorn directly. `Dockerfile.prod` runs `uvicorn app.asgi:app --workers 4` and the Starlette app serves both the API and SPA from a single process. Proposed fix: replace the nginx claim with "In production (Docker), uvicorn serves both the API and bundled SPA from a single process."

#### apps/vuln-api/README.md

- `apps/vuln-api/README.md:7` — `**[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)**` — Broken link: `apps/vuln-api/docs/` contains only `archive/` and `openapi.yaml`; there is no `API-DOCUMENTATION.md` at that path. The actual file is `apps/vuln-api/API-DOCUMENTATION.md` (root of vuln-api). Proposed fix: change link target to `API-DOCUMENTATION.md` (remove `docs/` prefix).

#### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:102` — `| **GenAI** | ~1 | ... |` — The Router Organization table claims ~1 GenAI endpoint, but the GenAI section of the same document (lines 347–352) lists 4 endpoints (`/api/v1/genai/chat`, `/api/v1/genai/knowledge/upload`, `/api/v1/genai/agent/browse`, `GET /api/v1/genai/models/config`), matching `docs/api-reference.md` which also states "GenAI (4 routes)". Proposed fix: change `~1` to `~4`.

#### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:212` — `"Coverage Requirements: Minimum overall: 90%"` — The enforced gate is 80%. See `apps/vuln-api/justfile:48`: `--cov-fail-under=80`. `apps/vuln-api/AGENTS.md:29` and `apps/vuln-api/API-DOCUMENTATION.md` both state 80%. Proposed fix: change to 80%.

---

### P2 — Minor staleness (low risk, cosmetic or confusing but not incorrect at runtime)

#### apps/vuln-api/AGENTS.md

- `apps/vuln-api/AGENTS.md:29` — `"Coverage target: 80% minimum (\`make test-coverage\`)"` — There is no `Makefile` in `apps/vuln-api/`; the task runner is `justfile`. The correct command is `just test-coverage`. Proposed fix: replace `make test-coverage` with `just test-coverage`.

#### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:1014` — `"Total Endpoints: 450+"` at document footer contradicts the opening section claim of "469 Vulnerable Endpoints" (line 20) within the same document. Proposed fix: align both to 469 (or whichever reflects the current live route count from `scripts/check_openapi_drift.py`).

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md` DEMO_MODE default column changed from `true` to `full`
- [ ] #2 `docs/architecture.md` `education/` blueprint added to `app/blueprints/` directory listing
- [ ] #3 `docs/developer-guide.md` `force-include` claim reconciled against pyproject.toml (add directive or remove claim)
- [ ] #4 `docs/developer-guide.md` wheel filename version updated from `0.1.0` to `0.1.5`
- [ ] #5 `docs/endpoints-catalog.md` endpoint count inconsistency resolved (469 vs 243 in same doc)
- [ ] #6 `README.md` DEMO_MODE default updated to `full` with note about Dockerfile.prod override
- [ ] #7 `AGENTS.md` nginx claim replaced with accurate uvicorn description
- [ ] #8 `apps/vuln-api/README.md` broken `docs/API-DOCUMENTATION.md` link fixed
- [ ] #9 `apps/vuln-api/API-DOCUMENTATION.md` GenAI row changed from `~1` to `~4`
- [ ] #10 `apps/vuln-api/tests/README.md` coverage requirement changed from 90% to 80%
- [ ] #11 `apps/vuln-api/AGENTS.md` `make test-coverage` replaced with `just test-coverage`
- [ ] #12 `apps/vuln-api/API-DOCUMENTATION.md` footer endpoint count aligned with header (450+ vs 469)
- [ ] #13 All linked claims verified against current code after fixes are applied
<!-- AC:END -->
