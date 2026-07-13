---
id: TASK-18
title: 'Docs: fix doc-claim drift detected on 2026-07-13'
status: To Do
assignee: []
created_date: '2026-07-13 00:00'
updated_date: '2026-07-13 00:00'
labels:
  - docs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated drift audit on 2026-07-13 validated every concrete, verifiable claim in the 12-file active doc set against the current codebase. **18 drift findings** were identified (10 P1 dev-doc errors, 8 P2 minor staleness). No P0 user-facing factual errors were found.

Findings are grouped by file. Proposed fixes are marked inline.

### docs/architecture.md

- `docs/architecture.md:165` — `| DEMO_MODE | true | ...` — **P1**: default listed as `true` but `app/config.py:31` reads `os.environ.get('DEMO_MODE', 'full')`, making the actual default `full`. Proposed fix: change `true` → `full` in the table.
- `docs/architecture.md:88-116` — **P2**: Blueprint directory listing omits the `education/` domain. `apps/vuln-api/app/blueprints/education/` exists and `app/asgi.py` imports `from app.blueprints.education import education_router`. Proposed fix: add `├── education/            # Education/training routes` to the listing.

### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:15` — `"verified against the live route table via \`just docs-drift\`"` — **P1**: recipe `docs-drift` does not exist in either the root or apps/vuln-api justfile. The actual recipe is `docs-check` in `apps/vuln-api/justfile`. Proposed fix: change `just docs-drift` → `just docs-check`.
- `docs/endpoints-catalog.md:14` vs `docs/endpoints-catalog.md:601` — `"469 unique endpoints"` (header) vs `"243 Total Routes"` (Implementation Status footer) — **P1**: internally inconsistent numbers within the same file. Proposed fix: reconcile to a single authoritative count and remove or explain the discrepancy between the two figures.

### README.md

- `README.md:243-247` — `make -C apps/vuln-api test-unit`, `make -C apps/vuln-api test-quick`, `make -C apps/vuln-api test-vulnerability`, `make -C apps/vuln-api test-smoke` — **P1**: `apps/vuln-api` has a `justfile`, not a `Makefile`. The root `justfile` recipe `api-test-unit` itself calls `make -C apps/vuln-api test-unit` (also broken). Proposed fix: replace `make -C apps/vuln-api <target>` with `just -f apps/vuln-api/justfile <target>`.

### AGENTS.md (root)

- `AGENTS.md:94-99` — `"Vulnerability gating (\`security.py\`): DEMO_MODE env var: full (vulns active) vs strict (safe mode, default), @require_full_demo decorator blocks dangerous endpoints in strict mode, is_full_mode() / get_demo_mode() helpers"` — **P1**: `apps/vuln-api/security.py` is a legacy Flask module (`from flask import jsonify, request`) left over from before the Flask→Starlette migration. It is not imported or used anywhere in the current Starlette app. Actual demo-mode gating is via `app/config.py:app_config.demo_mode`. Proposed fix: update to describe the current `app_config` pattern and remove the `security.py` reference.
- `AGENTS.md:115-116` — `"In production (Docker), nginx handles the proxy."` — **P1**: no nginx in production. `Dockerfile.prod` and `Dockerfile.fargate` run uvicorn directly; `app/asgi.py` serves the SPA via Starlette `StaticFiles` and a catch-all route. Proposed fix: remove the nginx sentence; replace with explanation that uvicorn + Starlette serve both API and SPA in a single process.
- `AGENTS.md:127` — `"Coverage target: 80% minimum (\`make test-coverage\`)"` — **P2**: should be `just test-coverage` (or `just -f apps/vuln-api/justfile test-coverage`); no Makefile exists. Proposed fix: change `make test-coverage` → `just -f apps/vuln-api/justfile test-coverage`.

### docs/developer-guide.md

- `docs/developer-guide.md:151` — `"force-include ensuring \`web_dist/\` makes it into the wheel despite being gitignored"` — **P2**: `apps/vuln-api/pyproject.toml` has no `force-include` directive in `[tool.hatch.build.targets.wheel]`. Proposed fix: remove the `force-include` claim or update pyproject.toml to add it.
- `docs/developer-guide.md:335` — `"Output: apps/vuln-api/dist/chimera_api-0.1.0-py3-none-any.whl"` — **P2**: pyproject.toml has `version = "0.1.5"`. Proposed fix: update the example wheel name to `chimera_api-0.1.5-py3-none-any.whl` or use a glob pattern.

### apps/vuln-api/README.md

- `apps/vuln-api/README.md:7` — `"[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)"` — **P2**: the linked path `docs/API-DOCUMENTATION.md` (relative to `apps/vuln-api/`) does not exist. The actual file is `apps/vuln-api/API-DOCUMENTATION.md`. Proposed fix: change link to `[API-DOCUMENTATION.md](API-DOCUMENTATION.md)`.

### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:20` — `"469 Vulnerable Endpoints"` vs `apps/vuln-api/API-DOCUMENTATION.md:1015` — `"Total Endpoints: 450+"` — **P1**: two different numbers in the same file. Proposed fix: reconcile to a single count that matches the live route table (run `just docs-check`).
- `apps/vuln-api/API-DOCUMENTATION.md:102` — `"| **GenAI** | ~1 | LLM-based chat interfaces and prompt injection targets."` — **P2**: `docs/api-reference.md` and `apps/vuln-api/README.md` both list 4 GenAI endpoints. The `~1` is incorrect. Proposed fix: change `~1` → `~4`.

### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:69` — `"tests/vulnerability/                  # Security validation"` — **P1**: `apps/vuln-api/tests/vulnerability/` does not exist. Only `tests/unit/` and `tests/integration/` exist. Proposed fix: remove the `vulnerability/` entry or create the directory.
- `apps/vuln-api/tests/README.md:74` — `"tests/smoke/                           # (implied)"` — **P1**: `apps/vuln-api/tests/smoke/` does not exist. The justfile's `test-smoke` recipe targets `tests/smoke/` (would fail). Proposed fix: remove the `smoke/` directory reference or create the directory.
- `apps/vuln-api/tests/README.md:36` — `"./run_tests.sh --quick"` — **P1**: the script resides at `apps/vuln-api/scripts/run_tests.sh`, not at `./run_tests.sh` relative to the `tests/` directory. The vuln-api `justfile` also calls `./run_tests.sh all` which would fail if run from the `apps/vuln-api/` directory (needs `./scripts/run_tests.sh`). Proposed fix: update all references from `./run_tests.sh` to `./scripts/run_tests.sh` (or `../scripts/run_tests.sh` from within tests/).
- `apps/vuln-api/tests/README.md:214` — `"Minimum overall: 90%, New code: 95%, Critical paths: 100%"` — **P2**: `apps/vuln-api/justfile` enforces `--cov-fail-under=80` and `docs/developer-guide.md` states "80% minimum". Proposed fix: align to 80% or update the justfile to reflect 90%.
- `apps/vuln-api/tests/README.md:73-75` — Directory tree shows `pytest.ini` and `justfile` as living inside `tests/`; neither exists there. `justfile` is at `apps/vuln-api/justfile`. No `pytest.ini` was found. — **P2**: Proposed fix: remove these entries from the tree or note their actual locations.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md` DEMO_MODE default corrected from `true` to `full`
- [ ] #2 `docs/architecture.md` blueprint listing includes the `education/` domain
- [ ] #3 `docs/endpoints-catalog.md` `just docs-drift` corrected to `just docs-check`
- [ ] #4 `docs/endpoints-catalog.md` "469" vs "243" inconsistency resolved
- [ ] #5 `README.md` `make -C apps/vuln-api test-*` commands replaced with `just -f apps/vuln-api/justfile *`
- [ ] #6 `AGENTS.md` `security.py` gating section updated to reflect `app/config.py` + `app_config.demo_mode`
- [ ] #7 `AGENTS.md` nginx production proxy claim removed; replaced with correct uvicorn+Starlette description
- [ ] #8 `AGENTS.md` `make test-coverage` corrected to `just -f apps/vuln-api/justfile test-coverage`
- [ ] #9 `docs/developer-guide.md` `force-include` claim removed or pyproject.toml updated
- [ ] #10 `docs/developer-guide.md` wheel filename version updated to match pyproject.toml
- [ ] #11 `apps/vuln-api/README.md` broken `docs/API-DOCUMENTATION.md` link fixed
- [ ] #12 `apps/vuln-api/API-DOCUMENTATION.md` "469" vs "450+" inconsistency resolved
- [ ] #13 `apps/vuln-api/API-DOCUMENTATION.md` GenAI endpoint count corrected from `~1` to `~4`
- [ ] #14 `apps/vuln-api/tests/README.md` non-existent `tests/vulnerability/` directory removed or created
- [ ] #15 `apps/vuln-api/tests/README.md` non-existent `tests/smoke/` directory removed or created
- [ ] #16 `apps/vuln-api/tests/README.md` `./run_tests.sh` path corrected to `./scripts/run_tests.sh`
- [ ] #17 `apps/vuln-api/tests/README.md` coverage floor aligned (80% or update justfile to 90%)
- [ ] #18 `apps/vuln-api/tests/README.md` phantom `pytest.ini` and `justfile` entries removed from directory tree
- [ ] #19 All linked claims verified against current code after fixes applied
<!-- AC:END -->
