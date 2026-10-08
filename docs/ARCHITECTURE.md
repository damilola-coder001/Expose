# EXPOSE Architecture Documentation

## 1. System Overview

**EXPOSE** is a real-time website security posture intelligence platform designed around the principle:
> **Evidence first. Intelligence second.**

The platform produces externally observable, reproducible, and verifiable security assessments without destructive payload fuzzing or unauthenticated penetration.

---

## 2. High-Level Dataflow

```
                         USER
                          │
                          ▼
                    EXPOSE WEB APP (apps/web)
                          │
                          ▼
                     API SERVER (apps/api)
                          │
                          ▼
                  SCOPE VALIDATOR (SSRF Guard)
                          │
                          ▼
                    SCAN JOB (Scheduled Task)
                          │
                          ▼
                    REDIS QUEUE (Distributed FIFO)
                          │
                          ▼
                  SCAN ORCHESTRATOR (Concurrent Workers)
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
   HTTP/TLS           BROWSER          DISCOVERY
    ENGINE             ENGINE            ENGINE
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
                     NUCLEI (Component)
                          │
                          ▼
                  FINDING PIPELINE
                          │
                          ▼
                    VALIDATION (Evidence Verifier)
                          │
                          ▼
                    RISK ENGINE (Deterministic 0-100)
                          │
                          ▼
                  SECURITY INTELLIGENCE
                          │
                          ▼
                      EXPOSE AI (Explanation)
                          │
                          ▼
                       REPORT
```

---

## 3. Monorepo Structure

| Directory | Responsibilities |
|---|---|
| `apps/web/` | Next.js, React, Tailwind CSS user interface ("PageSpeed Insights for Security"). |
| `apps/api/` | Go native API Gateway with structured `slog` logging, CORS, recovery, `/health` and `/ready` probes. |
| `apps/browser-worker/` | Headless Playwright worker service for DOM execution and mixed-content auditing. |
| `services/scanner/` | Scanner interfaces and probe execution stubs. |
| `services/orchestrator/` | Scan lifecycle coordination and worker dispatch stubs. |
| `services/intelligence/` | Risk synthesis and threat narrative interfaces. |
| `packages/types/` | Shared domain TypeScript interfaces and data models. |
| `packages/config/` | Centralized runtime configurations and schema defaults. |
| `packages/security-rules/`| Canonical rules taxonomy, scoring weights, and out-of-scope boundaries. |
| `infrastructure/docker/` | Production Dockerfiles and `docker-compose.yml` for single-command boot. |
| `infrastructure/deployment/` | `.env.example`, `init-db.sql`, and `Caddyfile` reverse proxy configs. |
| `docs/` | Architecture, API conventions, safety model, and phase verification guides. |
