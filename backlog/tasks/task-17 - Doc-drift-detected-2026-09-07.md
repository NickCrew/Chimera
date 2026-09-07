---
id: TASK-17
title: Doc drift detected — 2026-09-07 audit
status: To Do
assignee: []
created_date: '2026-09-07 00:00'
updated_date: '2026-09-07 00:00'
labels:
  - docs
dependencies: []
priority: Low
---

## Description

Automated claim-validator audit run on 2026-09-07 against the 12-file active doc set. 21 drift findings discovered across 4 severity levels. The detector does **not** modify docs; all fixes should be applied in a follow-up PR.

**Findings by file** (`path:line — exact quote / claim — proposed fix`):

---

### docs/architecture.md

- `docs/architecture.md:165` — `| \`DEMO_MODE\` | \`true\` |` — default listed as `true`, which is not a valid DEMO_MODE value; actual default in `app/config.py:31` is `'full'`. **(P0)** Fix: change column to `full`.

---

### docs/developer-guide.md

- `docs/developer-guide.md:47` — `| \`DEMO_MODE\` | \`strict\` |` — default listed as `strict`; actual default in `app/config.py:31` is `'full'`. **(P0)** Fix: change column to `full`.

---

### README.md

- `README.md:48` — `| \`DEMO_MODE\` | \`strict\` |` — default listed as `strict`; actual default is `'full'`. **(P0)** Fix: change column to `full`.

- `README.md:242-247` — `make -C apps/vuln-api test-unit` / `test-quick` / `test-vulnerability` / `test-smoke` — no `Makefile` exists at `apps/vuln-api/` (removed during Flask→Starlette migration); commands will fail. **(P1)** Fix: replace each line with its `just -f apps/vuln-api/justfile test-*` equivalent.

---

### AGENTS.md

- `AGENTS.md:116` — `"In production (Docker), nginx handles the proxy"` — the main Chimera production image (`apps/vuln-api/Dockerfile.prod`) uses uvicorn only; nginx appears solely in the `apps/vuln-web/Dockerfile` standalone web container. Statement is misleading for the primary production deployment. **(P2)** Fix: clarify scope to the standalone vuln-web container.

- `AGENTS.md:126` — `Coverage target: 80% minimum (\`make test-coverage\`)` — `make test-coverage` fails (no Makefile). **(P1)** Fix: replace with `just -f apps/vuln-api/justfile test-coverage`.

---

### docs/dockerhub-overview.md

- `docs/dockerhub-overview.md:22` — `| \`DEMO_MODE\` | \`strict\` |` — default listed as `strict`; actual default is `'full'`. **(P0)** Fix: change column to `full`.

---

### apps/vuln-api/README.md

- `apps/vuln-api/README.md:7` — `**[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)**` — resolves to `apps/vuln-api/docs/API-DOCUMENTATION.md` which does not exist; actual file is `apps/vuln-api/API-DOCUMENTATION.md`. **(P1)** Fix: update link to `API-DOCUMENTATION.md`.

- `apps/vuln-api/README.md:9` — `**[../DOCUMENTATION.md](../DOCUMENTATION.md)**` — `DOCUMENTATION.md` does not exist at the Chimera repo root. **(P1)** Fix: remove or replace with the correct root-level doc reference.

---

### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:17` vs `apps/vuln-api/API-DOCUMENTATION.md:1015` — line 17 states "469 Vulnerable Endpoints across 28 router packages"; line 1015 states "Total Endpoints: 450+" — internal inconsistency in the same file. **(P1)** Fix: align both to a single consistent count.

- `apps/vuln-api/API-DOCUMENTATION.md:294-307` — test template uses Flask API: `self.app = create_app('testing')` / `self.client = self.app.test_client()` — project migrated to Starlette; `create_app()` takes no positional config arg and Starlette uses `TestClient(app)`, not `app.test_client()`. **(P1)** Fix: replace template with Starlette pattern (`from starlette.testclient import TestClient; return TestClient(create_app())`).

---

### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:34` — `./run_tests.sh --quick` — `run_tests.sh` does not exist at `apps/vuln-api/` or `apps/vuln-api/tests/`. **(P1)** Fix: replace with `just test-quick` (or `just -f apps/vuln-api/justfile test-quick`).

- `apps/vuln-api/tests/README.md:68-72` — directory tree shows `tests/vulnerability/` with `test_sql_injection.py`, `test_xss.py`, `test_command_injection.py`, `test_auth_bypass.py` — this directory does not exist; vulnerability tests live in `tests/unit/` and are selected via `@pytest.mark.vulnerability`. **(P1)** Fix: correct directory tree to reflect actual layout.

- `apps/vuln-api/tests/README.md:74-76` — shows `tests/smoke/` directory entry — this directory does not exist. **(P1)** Fix: remove from directory tree.

- `apps/vuln-api/tests/README.md:211-214` — coverage requirements: "Minimum overall: 90%, New code: 95%, Critical paths: 100%" — actual enforced threshold in `justfile` (`--cov-fail-under=80`) is 80%. **(P2)** Fix: correct to 80% minimum.

- `apps/vuln-api/tests/README.md:218-229` — shows `pytest.ini` config file located in `tests/` — no such file exists there; pytest configuration is in `apps/vuln-api/pyproject.toml` under `[tool.pytest.ini_options]`. **(P1)** Fix: remove `pytest.ini` block; point readers to `pyproject.toml`.

- `apps/vuln-api/tests/README.md:252-256` — GitHub Actions CI snippet uses `pip install -r requirements.txt` — no `requirements.txt` exists; project uses `uv sync --extra dev --frozen`. **(P2)** Fix: replace `pip install` line with `uv sync --extra dev --frozen`.

- `apps/vuln-api/tests/README.md:294-307` — test template uses `create_app('testing')` and `self.app.test_client()` — same Flask-API drift as API-DOCUMENTATION.md finding above. **(P1)** Fix: update template to Starlette pattern.

---

### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:601` — `"243 Total Routes: Comprehensive coverage across offensive and defensive scenarios"` — contradicts "469 unique endpoints" stated at lines 4, 14, and 590 of the same document. **(P1)** Fix: reconcile to a single accurate count.

---

### docs/vulnerability-inventory.md

- `docs/vulnerability-inventory.md:524` — `[API Documentation](../api-demo/API-DOCUMENTATION.md)` — resolves to `api-demo/API-DOCUMENTATION.md` which doesn't exist (no `api-demo/` directory). **(P2)** Fix: update to `../apps/vuln-api/API-DOCUMENTATION.md`.

- `docs/vulnerability-inventory.md:526` — `[Attack Simulation](./attack-simulation.md)` — `docs/attack-simulation.md` does not exist. **(P2)** Fix: remove or replace with a valid doc reference.

- `docs/vulnerability-inventory.md:527` — `[Getting Started](./getting-started.md)` — `docs/getting-started.md` does not exist. **(P2)** Fix: replace with `developer-guide.md`.

---

## Acceptance Criteria

- [ ] **F01** `docs/architecture.md:165` — `DEMO_MODE` default corrected from `true` to `full`
- [ ] **F02** `docs/developer-guide.md:47` — `DEMO_MODE` default corrected from `strict` to `full`
- [ ] **F03** `README.md:48` — `DEMO_MODE` default corrected from `strict` to `full`
- [ ] **F04** `docs/dockerhub-overview.md:22` — `DEMO_MODE` default corrected from `strict` to `full`
- [ ] **F05** `README.md:242-247` — `make -C apps/vuln-api test-*` commands replaced with `just` equivalents
- [ ] **F06** `AGENTS.md:126` — `make test-coverage` replaced with `just -f apps/vuln-api/justfile test-coverage`
- [ ] **F07** `apps/vuln-api/README.md:7` — broken `docs/API-DOCUMENTATION.md` link fixed
- [ ] **F08** `apps/vuln-api/README.md:9` — nonexistent `../DOCUMENTATION.md` link removed or updated
- [ ] **F09** `apps/vuln-api/API-DOCUMENTATION.md:17,1015` — "469" vs "450+" count inconsistency resolved
- [ ] **F10** `apps/vuln-api/API-DOCUMENTATION.md:294-307` — Flask test template replaced with Starlette pattern
- [ ] **F11** `apps/vuln-api/tests/README.md:68-72` — nonexistent `tests/vulnerability/` directory removed from tree
- [ ] **F12** `apps/vuln-api/tests/README.md:34` — `./run_tests.sh --quick` replaced with `just test-quick`
- [ ] **F13** `apps/vuln-api/tests/README.md:294-307` — Flask test template replaced with Starlette pattern
- [ ] **F14** `apps/vuln-api/tests/README.md:218-229` — `tests/pytest.ini` reference removed; readers directed to `pyproject.toml`
- [ ] **F15** `docs/endpoints-catalog.md:601` — "243 Total Routes" reconciled with "469 unique endpoints"
- [ ] **F16** `apps/vuln-api/tests/README.md:252-256` — CI snippet `pip install -r requirements.txt` replaced with `uv sync`
- [ ] **F17** `apps/vuln-api/tests/README.md:211-214` — coverage minimum corrected from 90% to 80%
- [ ] **F18** `AGENTS.md:116` — nginx proxy claim scoped to the standalone vuln-web container
- [ ] **F19** `docs/vulnerability-inventory.md:524` — `../api-demo/API-DOCUMENTATION.md` link corrected
- [ ] **F20** `docs/vulnerability-inventory.md:526` — nonexistent `attack-simulation.md` link removed or replaced
- [ ] **F21** `docs/vulnerability-inventory.md:527` — nonexistent `getting-started.md` link replaced with `developer-guide.md`
- [ ] All linked claims verified against current code after fixes are applied
