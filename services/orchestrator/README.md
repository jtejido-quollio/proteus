# Orchestrator (Temporal Worker)

Temporal workflow worker for case lifecycle orchestration. This is not a domain service.

## Boundaries
- Import only API clients (e.g., `proteus/api/clients`) and shared libraries.
- Do not import `services/case-service/internal/...` packages.

## Local Temporal
Start Temporal via:

```sh
podman compose -f services/orchestrator/docker-compose.yml up -d
```

## Environment
- `TEMPORAL_ADDRESS` (default: `localhost:7233`)
- `TEMPORAL_NAMESPACE` (default: `default`)
- `TEMPORAL_TASK_QUEUE` (default: `case-orchestrator`)
- `CASE_SERVICE_BASE_URL` (default: `http://localhost:8080`)
- `ORCHESTRATOR_SUBJECT` (default: `orchestrator`)
- `ORCHESTRATOR_SCOPES` (default: `case:event`)
- `HEALTH_ADDR` (default: `:8090`)
