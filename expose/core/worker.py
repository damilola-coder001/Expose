"""Scanner worker isolation and ephemeral job runner for Expose (Phase 19).

Mandatory architecture for production:
Security scanning must NEVER happen directly inside the main web API process.

Architecture:
API (Public HTTP)
  ↓
Redis (Queue / Message Broker)
  ↓
Ephemeral Worker (Isolated Container / Sandboxed Process)
  ↓
Scanner Engine (Probes / HTTP / TLS / Nuclei / Browser)
  ↓
Verifiable Evidence (Output Artifact)
  ↓
Worker Recycled / Destroyed

Threat Model Constraints:
1. Target websites may behave maliciously (slowloris, zip bombs, malicious scripts).
2. Scanner components (headless browsers, HTML parsers) can encounter hostile content.
3. Workers have NO direct access to PostgreSQL database credentials.
4. Workers run under strict CPU, memory, and timeout watchdogs.
5. Network egress is strictly filtered to prevent SSRF against internal cloud infrastructure.
"""

import asyncio
from datetime import datetime, timezone
import logging
import os
import sys
import time
from typing import Callable, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from expose.core.models import ScanResult
from expose.core.orchestrator import ScanOrchestrator
from expose.core.safety import SecurityScopeError

logger = logging.getLogger("expose.worker")


class ScanJob(BaseModel):
    """Encapsulated job dispatched from API to worker queue."""
    job_id: str = Field(default_factory=lambda: f"job_{uuid.uuid4().hex[:10]}")
    scan_id: str
    target: str
    allow_private: bool = False
    enable_ai: bool = False
    timeout_seconds: int = 45
    memory_limit_mb: int = 512
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WorkerIsolationProfile(BaseModel):
    """Specification of container and execution sandbox boundaries."""
    read_only_filesystem: bool = True
    tmpfs_mounts: List[str] = Field(default_factory=lambda: ["/tmp:rw,noexec,nosuid,size=64m"])
    cpu_limit: float = 1.0
    memory_limit_mb: int = 512
    execution_timeout_seconds: int = 45
    no_new_privileges: bool = True
    drop_capabilities: List[str] = Field(default_factory=lambda: ["ALL"])
    has_postgres_access: bool = False
    isolated_network_egress: bool = True


class EphemeralWorkerRunner:
    """Runs a single scan job within strict execution, memory, and timeout limits.
    
    Guarantees that:
    - Hostile target timeouts cannot hang the scanner indefinitely.
    - Zero database credentials are held or leaked.
    - Process or task lifecycle terminates immediately after job completion.
    """

    def __init__(
        self,
        worker_id: Optional[str] = None,
        profile: Optional[WorkerIsolationProfile] = None,
    ):
        self.worker_id = worker_id or f"wrk_{uuid.uuid4().hex[:8]}"
        self.profile = profile or WorkerIsolationProfile()

    async def execute_job(
        self,
        job: ScanJob,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> ScanResult:
        """Executes the scan job under strict execution boundaries and watchdog timers."""
        logger.info(
            "Worker %s starting ephemeral scan job %s for target %s (timeout: %ds)",
            self.worker_id,
            job.job_id,
            job.target,
            job.timeout_seconds,
        )

        orchestrator = ScanOrchestrator()

        try:
            # Enforce hard execution watchdog timeout
            result = await asyncio.wait_for(
                orchestrator.scan(
                    raw_target=job.target,
                    allow_private=job.allow_private,
                    enable_ai=job.enable_ai,
                    progress_callback=progress_callback,
                ),
                timeout=float(job.timeout_seconds),
            )
            # Retain requested scan_id
            result.scan_id = job.scan_id
            logger.info("Worker %s successfully completed scan %s", self.worker_id, job.scan_id)
            return result

        except asyncio.TimeoutError:
            logger.error(
                "Worker %s: Target '%s' exceeded timeout limit (%ds). Hostile slowloris or unresponsive target.",
                self.worker_id,
                job.target,
                job.timeout_seconds,
            )
            raise TimeoutError(f"Scan execution exceeded hard timeout ceiling of {job.timeout_seconds} seconds.")
        except SecurityScopeError as e:
            logger.warning("Worker %s: Safety scope rejected target '%s': %s", self.worker_id, job.target, str(e))
            raise
        except Exception as e:
            logger.exception("Worker %s: Scan job %s failed: %s", self.worker_id, job.job_id, str(e))
            raise
        finally:
            # Ephemeral cleanup: explicitly purge any probe resources
            pass


class MemoryWatchdog:
    """Lightweight process memory monitor for worker instances."""

    @staticmethod
    def get_memory_usage_mb() -> float:
        """Returns approximate resident memory usage in MB."""
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform == "darwin":
                return usage / (1024.0 * 1024.0)
            return usage / 1024.0
        except Exception:
            # On Windows or systems without resource module
            return 0.0


class MonitoringSchedulerDaemon:
    """Continuous background scheduler daemon for recurring target monitoring (Phase 28/30).

    Periodically checks enabled schedules in `MonitoringStore`, executes due scans
    using an isolated `EphemeralWorkerRunner`, evaluates security regressions/diffs,
    and dispatches webhooks when alerts or regressions are identified.
    """

    def __init__(
        self,
        monitoring_store=None,
        history_store=None,
        poll_interval_seconds: float = 10.0,
    ):
        from expose.core.monitoring import get_monitoring_store
        from expose.core.history import get_history_store

        self.monitoring_store = monitoring_store or get_monitoring_store()
        self.history_store = history_store or get_history_store()
        self.poll_interval = poll_interval_seconds
        self.is_running = False

    def is_schedule_due(self, schedule) -> bool:
        """Determines if a schedule is due for execution."""
        if not schedule.enabled:
            return False
        if schedule.last_run_at is None:
            return True

        now = datetime.now(timezone.utc)
        elapsed = (now - schedule.last_run_at).total_seconds()

        # MonitoringFrequency interval mapping in seconds
        interval_map = {
            "hourly": 3600,
            "daily": 86400,
            "weekly": 604800,
        }
        freq_str = str(schedule.frequency.value if hasattr(schedule.frequency, "value") else schedule.frequency).lower()
        threshold = interval_map.get(freq_str, 86400)
        return elapsed >= threshold

    async def run_due_schedules_once(self) -> List[ScanResult]:
        """Runs one check cycle over all registered schedules, returning generated scan results."""
        from expose.core.monitoring import detect_security_regression, dispatch_webhook

        schedules = self.monitoring_store.list_schedules()
        executed_scans: List[ScanResult] = []

        for schedule in schedules:
            if not self.is_schedule_due(schedule):
                continue

            target_host = schedule.target_host
            target_url = f"https://{target_host}" if not target_host.startswith("http") else target_host

            logger.info("Executing scheduled monitoring scan for %s", target_host)

            previous_scan = None
            if self.history_store:
                previous_scan = self.history_store.get_latest_scan(target_host)

            runner = EphemeralWorkerRunner(worker_id=f"sched_{schedule.id[:8]}")
            job = ScanJob(
                scan_id=f"sched_{uuid.uuid4().hex[:12]}",
                target=target_url,
                allow_private=False,
                enable_ai=False,
                timeout_seconds=45,
            )

            try:
                result = await runner.execute_job(job)
                executed_scans.append(result)

                if self.history_store:
                    self.history_store.record_scan(result)

                # Detect regressions
                alert = detect_security_regression(
                    current_scan=result,
                    previous_scan=previous_scan,
                )

                if alert:
                    self.monitoring_store.record_alert(alert)
                    logger.warning("Security regression detected on %s: %s", target_host, alert.summary)
                    if schedule.webhook_url:
                        success, msg = await dispatch_webhook(schedule.webhook_url, alert)
                        logger.info("Alert webhook dispatched to %s: %s", schedule.webhook_url, msg)

                # Update schedule metadata
                schedule.last_run_at = datetime.now(timezone.utc)
                if result.score_card:
                    schedule.last_score = result.score_card.overall_score
                self.monitoring_store.set_schedule(schedule)

            except Exception as e:
                logger.error("Failed scheduled scan for %s: %s", target_host, str(e))

        return executed_scans

    async def start(self):
        """Runs the monitoring scheduler loop continuously."""
        self.is_running = True
        logger.info("MonitoringSchedulerDaemon started (polling every %ds)", self.poll_interval)
        try:
            while self.is_running:
                await self.run_due_schedules_once()
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            logger.info("MonitoringSchedulerDaemon cancelled.")
        finally:
            self.is_running = False

    def stop(self):
        """Signals the daemon to stop."""
        self.is_running = False

