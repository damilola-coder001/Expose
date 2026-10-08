"""Tests for Distributed Task Queue Engine (Phase 33)."""

import asyncio
import time
import pytest

from expose.core.queue import DistributedJob, InMemoryTaskQueue, JobStatus


@pytest.mark.asyncio
async def test_queue_push_and_lease():
    """Validates job insertion, priority ordering, and worker leasing."""
    queue = InMemoryTaskQueue()

    job1 = DistributedJob(target="https://target-low.com", priority=20)
    job2 = DistributedJob(target="https://target-high.com", priority=5)

    await queue.push(job1)
    await queue.push(job2)

    # Higher priority (lower priority int) must be leased first
    leased1 = await queue.lease_job(worker_id="wrk_1", lease_duration_seconds=10.0)
    assert leased1 is not None
    assert leased1.target == "https://target-high.com"
    assert leased1.status == JobStatus.LEASED
    assert leased1.lease_owner == "wrk_1"

    leased2 = await queue.lease_job(worker_id="wrk_2", lease_duration_seconds=10.0)
    assert leased2 is not None
    assert leased2.target == "https://target-low.com"

    # Queue should now be empty
    leased3 = await queue.lease_job(worker_id="wrk_3")
    assert leased3 is None


@pytest.mark.asyncio
async def test_queue_lease_expiration_and_recovery():
    """Validates that expired leases are automatically reclaimed and re-queued."""
    queue = InMemoryTaskQueue()
    job = DistributedJob(target="https://orphan.com")
    await queue.push(job)

    # Lease with ultra short 0.1s lease duration
    leased = await queue.lease_job(worker_id="crashed_worker", lease_duration_seconds=0.1)
    assert leased is not None
    assert leased.status == JobStatus.LEASED

    await asyncio.sleep(0.2)

    # Next worker requesting lease must trigger reclamation of expired job
    recovered = await queue.lease_job(worker_id="healthy_worker", lease_duration_seconds=10.0)
    assert recovered is not None
    assert recovered.job_id == job.job_id
    assert recovered.lease_owner == "healthy_worker"


@pytest.mark.asyncio
async def test_queue_retry_and_dead_letter():
    """Validates retry attempts and routing to Dead Letter Queue upon exceeding max retries."""
    queue = InMemoryTaskQueue()
    job = DistributedJob(target="https://failing-target.com", max_retries=2)
    await queue.push(job)

    # First attempt fails -> re-queued
    leased = await queue.lease_job(worker_id="wrk_1")
    await queue.fail_job(leased.job_id, error_message="Timeout 1")

    # Second attempt fails -> re-queued
    leased = await queue.lease_job(worker_id="wrk_1")
    await queue.fail_job(leased.job_id, error_message="Timeout 2")

    # Third attempt fails -> exceeds max_retries -> DEAD_LETTER
    leased = await queue.lease_job(worker_id="wrk_1")
    await queue.fail_job(leased.job_id, error_message="Fatal unrecoverable error")

    stats = await queue.get_stats()
    assert stats.dead_letter_count == 1
    assert stats.queued_count == 0

    stored = await queue.get_job(job.job_id)
    assert stored.status == JobStatus.DEAD_LETTER
    assert stored.retry_count == 3
