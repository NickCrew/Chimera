---
id: TASK-17
title: 'Docs: Fix doc-claim drift detected 2026-06-29'
status: To Do
assignee: []
created_date: '2026-06-29 00:00'
updated_date: '2026-06-29 00:00'
labels:
  - docs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated doc-drift audit run on 2026-06-29 against 12 doc files. The audit
verified file paths, symbol names, just recipe names, env-var defaults, and
behavioral claims against the current codebase. 21 verifiable claim failures
were found: 1 P0 (user-facing factual error), 16 P1 (dev-doc errors), 4 P2
(minor staleness / internal inconsistencies).

Severity key:
- **P0** User-facing factual error (security-relevant or affects published docs)
- **P1** Dev-doc error (would mislead a contributor or break a workflow)
- **P2** Minor staleness or internal inconsistency

---

### docs/architecture.md

- **F-1 (P1)** `docs/architecture.md:165` — `| DEMO_MODE | true | ... |` — doc says default is `true`; `app/config.py:31` defaults to `'full'` via `os.environ.get('DEMO_MODE', 'full')`. — Fix: change default column to `full`.
- **F-2 (P1)** `docs/architecture.md:89-116` — blueprint architecture listing omits the `education` domain — `app/asgi.py:185` imports `from app.blueprints.education import education_router`; `app/blueprints/education/` directory exists on disk. — Fix: add `├── education/` entry to the router tree.

---

### docs/developer-guide.md

- **F-3 (P1)** `docs/developer-guide.md:47` — `| DEMO_MODE | strict | ... |` — doc says default is `strict`; `app/config.py:31` defaults to `'full'`. — Fix: change default column to `full`.

---

### docs/endpoints-catalog.md

- **F-4 (P1)** `docs/endpoints-catalog.md:15` — `"verified against the live route table via \`just docs-drift\`"` — no `docs-drift` recipe exists in any justfile; the correct recipe is `docs-check` in `apps/vuln-api/justfile`. — Fix: replace `just docs-drift` with `just -f apps/vuln-api/justfile docs-check`.
- **F-5 (P2)** `docs/endpoints-catalog.md:15,590,601` — internally inconsistent endpoint counts within the same file: lines 15 and 590 say "469 unique endpoints / API endpoints" while line 601 says "243 Total Routes". — Fix: reconcile to a single canonical count.

---

### docs/dockerhub-overview.md

- **F-6 (P2)** `docs/dockerhub-overview.md:21` — `| PORT | 8880 | Server port |` — Docker container exposes port 80 (`Dockerfile:21-23`: `EXPOSE 80`, `ENV PORT=80`, CMD uses `--port 80`). `README.md` correctly documents `80 (container) / 8880 (dev)`. — Fix: change default to `80`.

---

### README.md

- **F-7 (P0)** `README.md:47` — `| DEMO_MODE | strict | full enables all vulnerabilities ... |` — doc says default is `strict`; `app/config.py:31` defaults to `'full'`. Running without `DEMO_MODE` set activates all vulnerabilities contrary to what the published README states. — Fix: change default column to `full`.

---

### AGENTS.md (root)

- **F-8 (P1)** `AGENTS.md:116` — `"In production (Docker), nginx handles the proxy."` — no nginx is used. `app/asgi.py` serves the SPA directly via `StaticFiles` mount and `spa_catch_all`; no Dockerfile references nginx. — Fix: remove the nginx sentence; document that uvicorn/Starlette serves both API and SPA.

---

### apps/vuln-api/AGENTS.md

- **F-9 (P1)** `apps/vuln-api/AGENTS.md:95` — `"DEMO_MODE env var: full (vulns active) vs strict (safe mode, default)"` — doc says default is `strict`; `app/config.py:31` defaults to `'full'`. — Fix: change `default` label from `strict` to `full`.
- **F-10 (P1)** `apps/vuln-api/AGENTS.md:94-98` — `"Vulnerability gating (security.py)"` — `apps/vuln-api/security.py` is the Flask-era module (`from flask import jsonify, request` at line 8) and is not imported by the Starlette app. Starlette demo-mode gating is implemented via `app/config.py` (`AppConfig.demo_mode`) and inline `get_demo_mode()` calls within route handlers. — Fix: update to reference `app/config.py` and per-route gating pattern, not `security.py`.
- **F-11 (P1)** `apps/vuln-api/AGENTS.md:116` — `"In production (Docker), nginx handles the proxy."` — same as F-8; no nginx involved. — Fix: remove nginx sentence.

---

### apps/vuln-api/README.md

- **F-12 (P1)** `apps/vuln-api/README.md:8` — `**[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)**` — relative to `apps/vuln-api/`, this resolves to `apps/vuln-api/docs/API-DOCUMENTATION.md` which does not exist. The actual file is `apps/vuln-api/API-DOCUMENTATION.md` (not inside `docs/`). — Fix: change link to `API-DOCUMENTATION.md`.
- **F-13 (P1)** `apps/vuln-api/README.md:9` — `**[../DOCUMENTATION.md](../DOCUMENTATION.md)**` — resolves to `apps/DOCUMENTATION.md`; this file does not exist (`ls apps/` shows only directories). — Fix: remove or update to a valid path.

---

### apps/vuln-api/API-DOCUMENTATION.md

- **F-14 (P2)** `apps/vuln-api/API-DOCUMENTATION.md:17` vs `:1016` — internal inconsistency: overview says "469 Vulnerable Endpoints"; footer says "Total Endpoints: 450+". — Fix: unify to a single count.
- **F-15 (P2)** `apps/vuln-api/API-DOCUMENTATION.md:102` vs `:345` — internal inconsistency in GenAI route count: router table (line 102) says `~1`; section header (line 345) says "GenAI Domain (4 endpoints)" and lists 4 routes. All other docs consistently say 4. — Fix: correct router table entry to `~4`.

---

### apps/vuln-api/tests/README.md

- **F-16 (P1)** `apps/vuln-api/tests/README.md:67-73` — lists `tests/vulnerability/` as an existing directory with `test_sql_injection.py`, `test_xss.py`, `test_command_injection.py`, `test_auth_bypass.py` — no such directory exists; `ls apps/vuln-api/tests/` shows only `unit/`, `integration/`, `conftest.py`, `README.md`, `__init__.py`, `verify_vaas.py`. — Fix: remove or mark as planned.
- **F-17 (P1)** `apps/vuln-api/tests/README.md:73` — claims `tests/run_tests.sh` exists — file not present in `apps/vuln-api/tests/` or `apps/vuln-api/`. — Fix: remove reference.
- **F-18 (P1)** `apps/vuln-api/tests/README.md:73` — claims `tests/pytest.ini` exists — file not present in `apps/vuln-api/tests/` or `apps/vuln-api/`. — Fix: remove reference.
- **F-19 (P1)** `apps/vuln-api/tests/README.md:214` — states "Minimum overall: 90%" and "New code: 95%" — `apps/vuln-api/justfile` `test-coverage` recipe enforces `--cov-fail-under=80`. — Fix: align to 80%.
- **F-20 (P1)** `apps/vuln-api/tests/README.md:135` — `pytest -m "security"` — `apps/vuln-api/justfile:40` uses `-m vulnerability`; the project pytest marker is `vulnerability`, not `security`. — Fix: update example to `pytest -m vulnerability`.
- **F-21 (P1)** `apps/vuln-api/tests/README.md:231-234` — conftest fixture list claims `auth_headers`, `sample_data`, `mock_services` — actual `conftest.py` provides `admin_headers`, `user_headers`, `unauthorized_headers`, `set_session`, `read_session`, `mock_users`, `mock_medical_records`, `sample_user`, `mfa_user`, and attack-payload fixtures; `auth_headers`, `sample_data`, and `mock_services` do not exist. — Fix: update fixture list to match actual conftest.

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md:165` DEMO_MODE default corrected from `true` to `full`.
- [ ] #2 `docs/architecture.md` router architecture listing includes the `education` blueprint.
- [ ] #3 `docs/developer-guide.md:47` DEMO_MODE default corrected from `strict` to `full`.
- [ ] #4 `docs/endpoints-catalog.md:15` `just docs-drift` replaced with the correct recipe (`just -f apps/vuln-api/justfile docs-check`).
- [ ] #5 `docs/endpoints-catalog.md` endpoint count inconsistency (469 vs 243) resolved to a single value.
- [ ] #6 `docs/dockerhub-overview.md:21` PORT default corrected from `8880` to `80`.
- [ ] #7 `README.md:47` DEMO_MODE default corrected from `strict` to `full`.
- [ ] #8 `AGENTS.md:116` (root) nginx proxy claim removed; uvicorn/Starlette SPA serving documented.
- [ ] #9 `apps/vuln-api/AGENTS.md:95` DEMO_MODE default corrected from `strict` to `full`.
- [ ] #10 `apps/vuln-api/AGENTS.md:94-98` `security.py` gating reference updated to reflect Starlette implementation (`app/config.py` + per-route checks).
- [ ] #11 `apps/vuln-api/AGENTS.md:116` nginx proxy claim removed.
- [ ] #12 `apps/vuln-api/README.md:8` link corrected from `docs/API-DOCUMENTATION.md` to `API-DOCUMENTATION.md`.
- [ ] #13 `apps/vuln-api/README.md:9` broken `../DOCUMENTATION.md` link removed or updated.
- [ ] #14 `apps/vuln-api/API-DOCUMENTATION.md` endpoint count inconsistency (469 vs 450+) resolved.
- [ ] #15 `apps/vuln-api/API-DOCUMENTATION.md` GenAI route count in router table corrected from `~1` to `~4`.
- [ ] #16 `apps/vuln-api/tests/README.md:67-73` `tests/vulnerability/` directory reference removed or marked as planned.
- [ ] #17 `apps/vuln-api/tests/README.md:73` `tests/run_tests.sh` reference removed.
- [ ] #18 `apps/vuln-api/tests/README.md:73` `tests/pytest.ini` reference removed.
- [ ] #19 `apps/vuln-api/tests/README.md:214` coverage minimum corrected from 90%/95% to 80%.
- [ ] #20 `apps/vuln-api/tests/README.md:135` pytest marker corrected from `security` to `vulnerability`.
- [ ] #21 `apps/vuln-api/tests/README.md:231-234` conftest fixture list updated to reflect actual fixtures in `conftest.py`.
- [ ] #22 All linked claims verified against current code after fixes are applied.
<!-- AC:END -->
