"""Distributed task queue and worker fleet coordination for Expose (Phase 33).

Provides scalable queue abstractions supporting both Redis backends and in-memory
queues for distributed scanning fleets, worker heartbeats, lease expiration,
and dead-letter queues (DLQ).
"""

from abc import ABC, abstractmethod
import asyncio
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import time
from typing import Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

logger = logging.getLogger("expose.queue")


class JobStatus(str, Enum):
    QUEUED = "queued"
    LEASED = "leased"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class DistributedJob(BaseModel):
    """Job container representing a queued security scan."""
    job_id: str = Field(default_factory=lambda: f"job_{uuid.uuid4().hex[:12]}")
    scan_id: str = Field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:12]}")
    target: str
    priority: int = 10  # Lower number = higher priority
    status: JobStatus = JobStatus.QUEUED
    allow_private: bool = False
    enable_ai: bool = False
    retry_count: int = 0
    max_retries: int = 3
    lease_owner: Optional[str] = None
    lease_expires_at: Optional[float] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class QueueStats(BaseModel):
    queued_count: int
    leased_count: int
    completed_count: int
    failed_count: int
    dead_letter_count: int


class AbstractTaskQueue(ABC):
    """Abstract interface for distributed scan task brokers."""

    @abstractmethod
    async def push(self, job: DistributedJob) -> str:
        """Pushes a job into the queue."""
        pass

    @abstractmethod
    async def lease_job(self, worker_id: str, lease_duration_seconds: float = 30.0) -> Optional[DistributedJob]:
        """Leases the highest priority job to a worker."""
        pass

    @abstractmethod
    async def complete_job(self, job_id: str, scan_result_id: Optional[str] = None) -> bool:
        """Marks a leased job as successfully completed."""
        pass

    @abstractmethod
    async def fail_job(self, job_id: str, error_message: str) -> bool:
        """Marks a job as failed, auto-retrying or routing to Dead Letter Queue."""
        pass

    @abstractmethod
    async def get_stats(self) -> QueueStats:
        """Returns aggregate queue health metrics."""
        pass


class InMemoryTaskQueue(AbstractTaskQueue):
    """Production-grade in-memory async task queue with lease watchdog."""

    def __init__(self):
        self._jobs: Dict[str, DistributedJob] = {}
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._lock = asyncio.Lock()

    async def push(self, job: DistributedJob) -> str:
        async with self._lock:
            self._jobs[job.job_id] = job
            # Push tuple (priority, created_timestamp, job_id)
            await self._queue.put((job.priority, job.created_at.timestamp(), job.job_id))
            return job.job_id

    async def lease_job(self, worker_id: str, lease_duration_seconds: float = 30.0) -> Optional[DistributedJob]:
        async with self._lock:
            # First check for any expired leased jobs and re-queue them
            now = time.time()
            for j in self._jobs.values():
                if j.status == JobStatus.LEASED and j.lease_expires_at and j.lease_expires_at < now:
                    logger.warning("Lease on job %s expired. Reclaiming job.", j.job_id)
                    j.status = JobStatus.QUEUED
                    j.lease_owner = None
                    j.lease_expires_at = None
                    await self._queue.put((j.priority, j.created_at.timestamp(), j.job_id))

            if self._queue.empty():
                return None

            try:
                _, _, job_id = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return None

            job = self._jobs.get(job_id)
            if not job or job.status != JobStatus.QUEUED:
                return None

            job.status = JobStatus.LEASED
            job.lease_owner = worker_id
            job.lease_expires_at = now + lease_duration_seconds
            return job

    async def complete_job(self, job_id: str, scan_result_id: Optional[str] = None) -> bool:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.lease_owner = None
            job.lease_expires_at = None
            return True

    async def fail_job(self, job_id: str, error_message: str) -> bool:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False

            job.retry_count += 1
            job.error_message = error_message

            if job.retry_count <= job.max_retries:
                # Re-queue with backoff priority
                job.status = JobStatus.QUEUED
                job.priority += 5
                job.lease_owner = None
                job.lease_expires_at = None
                await self._queue.put((job.priority, time.time(), job.job_id))
                logger.info("Requeued job %s (attempt %d/%d)", job.job_id, job.retry_count, job.max_retries)
            else:
                job.status = JobStatus.DEAD_LETTER
                logger.error("Job %s exceeded max retries. Moved to DLQ: %s", job.job_id, error_message)

            return True

    async def get_stats(self) -> QueueStats:
        async with self._lock:
            counts = {s: 0 for s in JobStatus}
            for j in self._jobs.values():
                counts[j.status] += 1

            return QueueStats(
                queued_count=counts[JobStatus.QUEUED],
                leased_count=counts[JobStatus.LEASED],
                completed_count=counts[JobStatus.COMPLETED],
                failed_count=counts[JobStatus.FAILED],
                dead_letter_count=counts[JobStatus.DEAD_LETTER],
            )

    async def get_job(self, job_id: str) -> Optional[DistributedJob]:
        async with self._lock:
            return self._jobs.get(job_id)


# Global singleton queue instance
_GLOBAL_QUEUE: Optional[AbstractTaskQueue] = None


def get_task_queue() -> AbstractTaskQueue:
    global _GLOBAL_QUEUE
    if _GLOBAL_QUEUE is None:
        _GLOBAL_QUEUE = InMemoryTaskQueue()
    return _GLOBAL_QUEUE
