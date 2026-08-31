---
id: TASK-17
title: 'Docs: doc-claim drift detected on 2026-08-31'
status: To Do
assignee: []
created_date: '2026-08-31 00:00'
updated_date: '2026-08-31 00:00'
labels:
  - docs
dependencies: []
priority: Low
---

## Description

Automated drift scan run on 2026-08-31 detected 11 verified findings across 12 audited doc files.
Findings are grouped by file below in the shape `path:line — \`exact quote\` — claim — proposed fix` with severity.

Severity scale: **P0** user-facing factual error / **P1** dev-doc error / **P2** minor staleness.

---

### docs/architecture.md

- `docs/architecture.md:165` — `| DEMO_MODE | true | ...` — **P1** The "Default" column says `true` for DEMO_MODE; the actual in-code default (app/config.py:31) is the string `'full'`. Proposed fix: change default cell to `full`.
- `docs/architecture.md:168` — `| DATABASE_PATH | demo.db | ...` — **P1** DATABASE_PATH default is claimed as `demo.db`, but `app/database.py:72` uses `os.getenv("DATABASE_PATH", "/tmp/api-demo.db")`. Proposed fix: update default to `/tmp/api-demo.db`.
- `docs/architecture.md:169` — `| DEMO_THROUGHPUT_PATHS | \`\` | Comma-separated paths to short-circuit |` — **P1** `DEMO_THROUGHPUT_PATHS` does not exist in `app/config.py` (only `DEMO_THROUGHPUT_MODE`, `DEMO_THROUGHPUT_PAYLOAD_BYTES`, `DEMO_THROUGHPUT_MAX_BYTES`). Proposed fix: remove this row or replace with the correct env vars.
- `docs/architecture.md:170` — `| PORT | 80 | Server port (container), CLI defaults to \`8880\` |` — **P1** `Dockerfile.prod` sets `PORT=8880` and exposes/binds to 8880. The container default is 8880, not 80 (80 is used only in the dev Dockerfile). Proposed fix: change default cell to `8880 (Dockerfile.prod) / 80 (Dockerfile dev)` or simply `8880`.
- `docs/architecture.md:88-116` — blueprint directory tree — **P2** The `education/` blueprint is present on disk (`apps/vuln-api/app/blueprints/education/`) and has a test file (`tests/unit/test_education_routes.py`), but is not listed in the blueprint directory. Proposed fix: add `education/` entry to the table.

### docs/developer-guide.md

- `docs/developer-guide.md:47` — `| DEMO_MODE | strict | full enables all vulnerabilities...` — **P1** Claims the default is `strict`; the in-code default (`app/config.py:31`) is `full` (the string `'full'`). `Dockerfile.prod` does set `DEMO_MODE=strict`, but the code default itself is `full`. Proposed fix: distinguish code default (`full`) from Dockerfile.prod override (`strict`), e.g. `full (code) / strict (Docker image)`.
- `docs/developer-guide.md:49` — `| DATABASE_PATH | demo.db | ...` — **P1** Same as architecture.md above; actual default is `/tmp/api-demo.db`. Proposed fix: update default.
- `docs/developer-guide.md:50` — `| PORT | 80 (container) / 8880 (dev) | ...` — **P1** `Dockerfile.prod` uses 8880 for container; the published image runs on 8880, not 80. Proposed fix: update to `8880 (Dockerfile.prod) / 80 (Dockerfile dev)`.

### README.md

- `README.md:48` — `| DEMO_MODE | strict | full enables all vulnerabilities...` — **P1** Same as developer-guide.md; code default is `full`. Proposed fix: same distinction.
- `README.md:50` — `| DATABASE_PATH | demo.db | ...` — **P1** Actual default is `/tmp/api-demo.db`. Proposed fix: update.
- `README.md:51` — `| PORT | 80 (container) / 8880 (dev) | ...` — **P1** Dockerfile.prod uses 8880. Proposed fix: update.

### AGENTS.md

- `AGENTS.md:116` — `"In production (Docker), nginx handles the proxy."` — **P1** `Dockerfile.prod` runs `uvicorn app.asgi:app` directly; there is no nginx in any Dockerfile. Starlette itself handles routing and SPA serving in production. Proposed fix: replace with "In production (Docker), uvicorn + Starlette serve both the API and the bundled SPA directly."

### docs/dockerhub-overview.md

- `docs/dockerhub-overview.md:24` — `| DATABASE_PATH | demo.db | ...` — **P1** Actual default in `app/database.py:72` is `/tmp/api-demo.db`. Proposed fix: update default.

### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:599` — `✅ **243 Total Routes**: Comprehensive coverage...` — **P2** The same document states "469 unique endpoints" in the header (line 5) and conclusion (line 590), but "243 Total Routes" in the implementation status. Internally inconsistent. Proposed fix: reconcile the route count using the live route table (`just docs-drift` or `just docs-check`).

### apps/vuln-api/README.md

- `apps/vuln-api/README.md:7` — `**[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)**` — **P1** The relative link resolves to `apps/vuln-api/docs/API-DOCUMENTATION.md`, which does not exist. The actual file is `apps/vuln-api/API-DOCUMENTATION.md`. Proposed fix: change link to `API-DOCUMENTATION.md`.

### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:54-76` — directory tree listing — **P1** Lists several paths that do not exist on disk:
  - `tests/vulnerability/` directory and its files — DOES NOT EXIST (only `unit/` and `integration/`)
  - `tests/pytest.ini` — DOES NOT EXIST
  - `tests/run_tests.sh` — DOES NOT EXIST
  - `tests/justfile` — DOES NOT EXIST
  - `tests/unit/test_validators.py` — DOES NOT EXIST
  - `tests/unit/test_responses.py` — DOES NOT EXIST
  Proposed fix: rewrite the directory tree to reflect the actual structure.
- `apps/vuln-api/tests/README.md` (conftest section) — `client`, `auth_headers`, `sample_data`, `mock_services` — **P1** These four fixtures are listed as the ones provided by `conftest.py`, but the actual conftest.py exposes a different set: `client`, `app`, `remote_client`, `set_session`, `read_session`, `mock_users`, `mock_medical_records`, `sample_user`, `mfa_user`, `demo_mode_full`, `demo_mode_strict`, `sql_injection_payloads`, `command_injection_payloads`, and `reset_databases`. Proposed fix: update the fixture table.
- `apps/vuln-api/tests/README.md` (markers section) — `slow`, `security`, `critical` — **P1** Listed markers don't match the actual registered markers (`vulnerability`, `integration`, `smoke`) documented in `AGENTS.md` and `docs/developer-guide.md`. Proposed fix: update the marker list.

---

## Severity Summary

| Severity | Count |
|----------|------:|
| P0 user-facing factual error | 0 |
| P1 dev-doc error | 17 |
| P2 minor staleness | 3 |
| **Total** | **20** |

---

## Acceptance Criteria

- [ ] `docs/architecture.md`: DEMO_MODE default corrected from `true` to `full`
- [ ] `docs/architecture.md`: DATABASE_PATH default corrected from `demo.db` to `/tmp/api-demo.db`
- [ ] `docs/architecture.md`: `DEMO_THROUGHPUT_PATHS` row removed or replaced with correct env vars
- [ ] `docs/architecture.md`: PORT container default corrected from `80` to `8880`
- [ ] `docs/architecture.md`: `education/` blueprint added to blueprint directory listing
- [ ] `docs/developer-guide.md`: DEMO_MODE default corrected (`full` code default / `strict` Docker override)
- [ ] `docs/developer-guide.md`: DATABASE_PATH default corrected to `/tmp/api-demo.db`
- [ ] `docs/developer-guide.md`: PORT container default corrected to `8880`
- [ ] `README.md`: DEMO_MODE default corrected
- [ ] `README.md`: DATABASE_PATH default corrected to `/tmp/api-demo.db`
- [ ] `README.md`: PORT container default corrected to `8880`
- [ ] `AGENTS.md`: nginx proxy claim replaced with accurate uvicorn/Starlette description
- [ ] `docs/dockerhub-overview.md`: DATABASE_PATH default corrected to `/tmp/api-demo.db`
- [ ] `docs/endpoints-catalog.md`: "243 Total Routes" inconsistency resolved with correct count
- [ ] `apps/vuln-api/README.md`: `docs/API-DOCUMENTATION.md` link corrected to `API-DOCUMENTATION.md`
- [ ] `apps/vuln-api/tests/README.md`: Non-existent directory/file paths removed from directory tree
- [ ] `apps/vuln-api/tests/README.md`: Fixture list updated to match actual `conftest.py` exports
- [ ] `apps/vuln-api/tests/README.md`: Marker list updated to `vulnerability`, `integration`, `smoke`
- [ ] All linked claims verified against current code after corrections are applied
