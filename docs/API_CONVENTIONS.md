# EXPOSE API Conventions & Standards

## 1. HTTP Headers & Identification
Every request processed by the EXPOSE API pipeline carries standard correlation metadata:
- `X-Request-ID`: Generated client-side or assigned by the API gateway (`req_<hex>`). Propagated across all logs.
- `Content-Type`: `application/json; charset=utf-8` for successes, `application/problem+json` for error envelopes.

---

## 2. Standard Responses

### Success Envelope
```json
{
  "status": "success",
  "data": {
    "key": "value"
  }
}
```

### Error Envelope (RFC 7807 Problem Details)
```json
{
  "status": "error",
  "error": {
    "code": "BAD_REQUEST",
    "message": "Human-readable explanation of why the operation failed.",
    "details": []
  }
}
```

### Error Codes
| Code | HTTP Status | Description |
|---|---|---|
| `BAD_REQUEST` | 400 | The request body or parameters are malformed. |
| `UNAUTHORIZED` | 401 | Missing authentication or unverified tenant credentials. |
| `FORBIDDEN` | 403 | Target domain outside allowable scope or private IP detected. |
| `NOT_FOUND` | 404 | The requested resource does not exist. |
| `RATE_LIMITED` | 429 | Request threshold exceeded (5 req/s token bucket). |
| `INTERNAL_SERVER_ERROR` | 500 | Panic or unexpected unhandled exception. |
| `SERVICE_UNAVAILABLE` | 503 | Downstream dependency (Postgres, Redis) unreachable. |

---

## 3. Phase 1 Health & Readiness Endpoints

### Liveness Probe: `GET /health`
- **Method**: `GET`
- **Status**: `200 OK`
- **Purpose**: Verifies the API server process is running and accepting sockets.
- **Payload**:
  ```json
  {
    "status": "healthy",
    "service": "expose-api",
    "version": "0.1.0",
    "uptime_seconds": 45.2,
    "timestamp": "2026-09-09T14:30:00Z"
  }
  ```

### Readiness Probe: `GET /ready`
- **Method**: `GET`
- **Status**: `200 OK` (when all dependencies are UP) or `503 Service Unavailable` (when any dependency is DOWN)
- **Purpose**: Probes downstream PostgreSQL socket and Redis wire RESP `PING`/`+PONG`.
- **Payload (Healthy)**:
  ```json
  {
    "status": "ready",
    "service": "expose-api",
    "version": "0.1.0",
    "timestamp": "2026-09-09T14:30:00Z",
    "dependencies": {
      "postgres": {
        "status": "UP",
        "latency_ms": 1.4
      },
      "redis": {
        "status": "UP",
        "latency_ms": 0.6
      }
    }
  }
  ```
- **Payload (Degraded)**:
  ```json
  {
    "status": "not_ready",
    "service": "expose-api",
    "version": "0.1.0",
    "timestamp": "2026-09-09T14:30:00Z",
    "dependencies": {
      "postgres": {
        "status": "DOWN",
        "error": "dial tcp 127.0.0.1:5432: connect: connection refused"
      },
      "redis": {
        "status": "UP",
        "latency_ms": 0.8
      }
    }
  }
  ```
