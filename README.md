# EXPOSE

> **See what your website exposes.**

Expose is a real production-oriented website security intelligence platform. It allows a user to enter a website URL and receive an externally observable, empirical security assessment.

The user experience is inspired by PageSpeed Insights:
```
Paste URL ──▶ Analyze ──▶ Discover ──▶ Validate ──▶ Score ──▶ Explain ──▶ Recommend ──▶ Verify
```

---

## Core Product Principle

> **Evidence first. Intelligence second.**

The scanner determines what can actually be observed on the wire.  
The intelligence layer explains what those observations mean.  
The AI is **never** the source of truth.

```
Scanner ──▶ Observation ──▶ Evidence ──▶ Validation ──▶ Finding ──▶ Risk Assessment ──▶ AI Interpretation ──▶ Recommendation
```

---

## High-Level Architecture

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

## Monorepo Layout

```
expose/
├── apps/
│   ├── web/                    # Next.js, React, Tailwind CSS dashboard
│   ├── api/                    # Go API Gateway (GET /health, GET /ready, slog JSON logging)
│   └── browser-worker/         # Playwright Chromium headless analysis worker
│
├── services/                   # Backend modular service stubs
│   ├── scanner/                # Modular scanner probe interfaces
│   ├── orchestrator/           # Scan lifecycle coordination interfaces
│   └── intelligence/           # Risk assessment & intelligence interfaces
│
├── packages/                   # Shared libraries
│   ├── types/                  # TypeScript & Go shared domain schemas
│   ├── config/                 # Default configs, timeouts, rate limits
│   └── security-rules/         # Taxonomy, scoring weights, out-of-scope boundaries
│
├── infrastructure/
│   ├── docker/                 # Production Dockerfiles & docker-compose.yml
│   └── deployment/             # .env.example, init-db.sql, Caddyfile
│
├── docs/                       # Architecture, API conventions, Safety model
├── Makefile                    # Single-command shortcuts
└── README.md
```

---

## Booting the Stack (Single Documented Command)

To build and boot the entire infrastructure locally (PostgreSQL, Redis, Go API, Browser Worker, Next.js Web):

```bash
docker compose -f infrastructure/docker/docker-compose.yml up --build
```

Or using the Makefile:
```bash
make dev
```

### Active Service Ports

| Service | Host Port | Verification |
|---|---|---|
| **Web UI** | `http://localhost:3000` | Browser dashboard |
| **API Server** | `http://localhost:8080` | `curl http://localhost:8080/health` |
| **Browser Worker** | `http://localhost:3001` | `curl http://localhost:3001/health` |
| **PostgreSQL 16** | `localhost:5432` | `pg_isready -U expose -d expose` |
| **Redis 7** | `localhost:6379` | `redis-cli -p 6379 ping` |

---

## Health & Readiness Probes

### Liveness (`GET /health`)
```bash
curl -i http://localhost:8080/health
```
```json
{
  "status": "healthy",
  "service": "expose-api",
  "version": "0.1.0",
  "uptime_seconds": 12.4,
  "timestamp": "2026-09-09T14:30:00Z"
}
```

### Readiness (`GET /ready`)
Actively verifies downstream PostgreSQL socket connectivity and Redis wire RESP `PING`/`+PONG`:
```bash
curl -i http://localhost:8080/ready
```
```json
{
  "status": "ready",
  "service": "expose-api",
  "version": "0.1.0",
  "timestamp": "2026-09-09T14:30:00Z",
  "dependencies": {
    "postgres": {
      "status": "UP",
      "latency_ms": 1.2
    },
    "redis": {
      "status": "UP",
      "latency_ms": 0.8
    }
  }
}
```

---

## Authorization & Safety Model

Expose enforces strict safety rules and enterprise guarantees:
1. **Notice**: *"Only scan websites you own or are authorized to test."*
2. **Safe by default**: All baseline checks are strictly passive, non-destructive, and externally observable.
3. **SSRF Guard & Anti-DNS-Rebinding**: 
   - Pre-flight checks block RFC 1918 private subnets, loopbacks, and cloud metadata IPs.
   - Socket-level connection interception (`SSRFSafeAsyncTransport`) inspects peer IPs at TCP connect time, preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
4. **Domain Ownership Verification (Proof-of-Control)**:
   - Cryptographic challenge tokens via DNS TXT (`_expose-challenge.<domain>`) and HTTP well-known endpoint (`/.well-known/expose-challenge.txt`).
   - Confirms domain authority to award authoritative "Verified Owner" badges on scan scorecards.
5. **Explicit Boundaries**: The following domains are out of scope:
   - Authentication & session flows (no credential brute-forcing)
   - Active code injection (no SQLi/RCE fuzzing payloads)
   - Business logic workflows
   - Internal cloud topologies
   - Proprietary source code trees

---

## Standards Compliance & Enterprise Guarantees

- **OWASP Top 10:2025 & ASVS 5.0**: Authoritative mapping across all observation rules and findings.
- **OASIS SARIF v2.1.0 & Self-Contained Executive HTML**: Standardized security telemetry for CI/CD and zero-dependency offline C-suite reporting.
- **Multi-Region Vantage Point Egress**: Distributed observation from US, EU, and AP vantage points with GeoDNS divergence detection and latency differential analysis.
- **Distributed Queue Orchestration**: Worker task queue supporting Redis and high-throughput in-memory backends with lease renewal, heartbeats, automatic retries, and dead-letter queues.
- **Live CISA KEV Threat Intelligence**: Synchronized Catalog of Known Exploited Vulnerabilities with zero-latency offline caching and automatic technology banner correlation.
- **Expose Shield Inline WAF & Active Defense**: Reverse proxy and ASGI security middleware featuring deterministic client device fingerprinting, real-time regex attack inspection (SQLi, XSS, Path Traversal, Scanners, RCE), sliding window threat accumulation, and automatic adaptive banning.
- **Automated Test Coverage**: **133 / 133 unit and integration tests passing across 28 test suites** (100% pass rate).

---

## CLI Reference

Expose provides a comprehensive, production-grade CLI:

```bash
# 1. Run a comprehensive security scan with Executive HTML, SARIF, and JSON export
expose scan https://example.com --html-out report.html --sarif results.sarif -o report.json --min-score 80

# 2. Multi-Region distributed vantage point evaluation
expose scan https://example.com --multi-region

# 3. Synchronize or query live CISA KEV Threat Intelligence
expose threat-intel sync
expose threat-intel search "Log4j"

# 4. Launch Expose Shield Inline WAF Reverse Proxy
expose shield start --upstream http://localhost:8000 --port 8080 --ban-threshold 80

# 5. Inspect or unban IP addresses and device fingerprints
expose shield bans
expose shield unban 203.0.113.50

# 6. Re-verify a specific finding to confirm remediation
expose verify-fix report.json EXP-SEC-01

# 7. Generate and verify Domain Ownership Challenge (Proof-of-Control)
expose domain challenge example.com
expose domain verify example.com --method dns-txt

# 8. Execute parallel multi-target portfolio batch scans
expose batch domains.txt --concurrency 5 --min-score 75

# 9. Run the continuous monitoring scheduler daemon
expose worker --poll-interval 30
```


