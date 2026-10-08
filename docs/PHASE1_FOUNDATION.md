# Phase 1: Project Foundation Verification & Guide

## Objective
Establish the monorepo structure, environment configuration, database & Redis wiring, structured logging, health checks (`GET /health`, `GET /ready`), and single-command local boot without implementing scanning logic yet.

---

## 1. Single Command Stack Boot

The entire stack (PostgreSQL, Redis, Go API, Playwright Worker, Next.js Web) boots with a single command:

```bash
docker compose -f infrastructure/docker/docker-compose.yml up --build
```

To run in detached background mode:
```bash
docker compose -f infrastructure/docker/docker-compose.yml up --build -d
```

To inspect running containers:
```bash
docker compose -f infrastructure/docker/docker-compose.yml ps
```

To terminate the stack:
```bash
docker compose -f infrastructure/docker/docker-compose.yml down
```

---

## 2. Port Mapping & Endpoints

| Service | Container Port | Host Port | Verification URL |
|---|---|---|---|
| **Web UI** | 3000 | 3000 | `http://localhost:3000` |
| **API Server** | 8080 | 8080 | `http://localhost:8080/health` |
| **Browser Worker** | 3001 | 3001 | `http://localhost:3001/health` |
| **PostgreSQL** | 5432 | 5432 | `pg_isready -U expose -d expose` |
| **Redis** | 6379 | 6379 | `redis-cli -p 6379 ping` |

---

## 3. Verification Checklist

1. **Liveness Check**:
   ```bash
   curl -i http://localhost:8080/health
   # Expected: HTTP 200 OK, JSON with status: "healthy"
   ```

2. **Readiness Check**:
   ```bash
   curl -i http://localhost:8080/ready
   # Expected: HTTP 200 OK, JSON with status: "ready", postgres: UP, redis: UP
   ```

3. **Browser Worker Liveness**:
   ```bash
   curl -i http://localhost:3001/health
   # Expected: HTTP 200 OK, JSON with status: "healthy"
   ```

4. **Web Frontend**:
   Navigate to `http://localhost:3000` to view the live dashboard displaying infrastructure metrics, architecture pipeline, and safety boundaries.
