#!/usr/bin/env python3
import asyncio
import json
import time
from collections.abc import Awaitable
from typing import Any

from aiohttp import ClientSession
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from .clamav import ClamAVResult, ClamAVScanner, Monitor
from .const import (
    CLAMD_HOSTS,
    DELAY,
    KAFKA_LOG_RETENTION_MS,
    KAFKA_TOPIC,
    KAFKA_TOPIC_RSLT,
    MAX_CONCURRENT_SCANS,
    RESULT_TO_KAFKA_TOPIC,
    RETRY,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
)
from .helpers import retry
from .logging import getLogger, logging
from .models import ScanResponse
from .storage import S3BucketKeyException, S3LockException, S3MoveException, S3Storage
from .utils import kafka_params

logger = getLogger("scanav")

# Limit max concurrent scans
scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


# ----------------- UTILITIES -----------------
def fire_and_forget(coro: Awaitable[None]):
    """Run an async task in background and log exceptions."""

    async def wrapper():
        try:
            await coro
        except Exception as e:
            logger.error("Background task failed: %s", e)

    asyncio.create_task(wrapper())


@retry(tries=RETRY, delay=DELAY, logger=logger)
async def async_call_webhook(key: str, url: str, payload: dict):
    """Call webhook asynchronously."""

    async with ClientSession(raise_for_status=True) as session:
        logger.info("Calling webhook %s", key)
        async with session.post(url, json=payload):
            logger.info(f"Webhook {url} successfully called for file {key}")


async def async_publish2kafka(result: ScanResponse) -> None:
    """Publish result to Kafka."""
    producer = AIOKafkaProducer(
        **kafka_params(), value_serializer=lambda v: v.encode("utf-8")
    )
    await producer.start()
    try:
        await producer.send_and_wait(KAFKA_TOPIC_RSLT, value=result.model_dump_json())
    finally:
        await producer.stop()


# ----------------- WORKER -----------------
@retry(
    exceptions=(S3BucketKeyException, S3LockException, S3MoveException),
    tries=RETRY,
    delay=DELAY,
    logger=logger,
)
async def worker(
    worker_id: str,
    storage: S3Storage,
    record: dict[str, Any],
    clamav: ClamAVScanner,
) -> None:
    """Worker that selects the best host adaptively, performs scan, updates stats and moves object."""

    async with scan_semaphore:
        logger.info(f"[worker-{worker_id}] Start scan.")
        start_time = time.monotonic()

        # Extract object key, bucket and metadata
        key, bucket = storage.get_bucket_key(record)

        # Set status to PENDING
        await storage.async_set_s3_tags(key, bucket, {"status": "PENDING"})

        try:
            scan = await storage.async_scan_s3_object(key, bucket, clamav)
        except Exception as e:
            logger.error(f"[worker-{worker_id}] {e}")
            scan = ClamAVResult(status="ERROR", infos=e.__class__.__name__)

        duration = time.monotonic() - start_time

        # Move object based on scan result
        target = (
            f"{S3_SCAN_RESULT}/{key}"
            if scan.status in ["CLEAN", "ERROR"]
            else f"{S3_SCAN_QUARANTINE}/{key}"
        )
        result = ScanResponse(
            key=key, bucket=bucket, duration=duration, **scan.model_dump()
        )
        await storage.async_move_s3_object(key, bucket, target, result)

        # Fire webhook if present
        if (
            (metadata := await storage.async_get_s3_metadata(target, bucket))
            and (url := metadata.get("webhook"))
            and scan is not None
        ):
            fire_and_forget(async_call_webhook(target, url, result.model_dump_json()))

        # Publish result to Kafka
        if RESULT_TO_KAFKA_TOPIC:
            await async_publish2kafka(result)

        logger.info(f"[worker-{worker_id}] Scanned {key} → {scan.status}")


# ----------------- CONSUMER -----------------
async def consume_loop(storage: S3Storage, clamav: ClamAVScanner) -> None:
    """Consume Kafka messages and schedule scans."""

    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC, **kafka_params(), value_deserializer=lambda v: v.decode("utf-8")
    )
    await consumer.start()
    try:
        async for msg in consumer:
            if not msg.value:
                continue
            payload = json.loads(msg.value)
            logger.debug("Kafka payload: %s", payload)
            for record in payload.get("Records", []):
                if record.get("eventName") == "s3:ObjectCreated:Put":
                    logger.debug("New S3 object to scan detected.")
                    object = record.get("s3", {}).get("object", {})
                    skip_file = (
                        object.get("userMetadata", {}).get("X-Amz-Meta-Lock-Id")
                        == "clamav-scan-ignore"
                    )

                    if key := object.get("key") and not skip_file:
                        logger.info(
                            f"[kafka-consumer] Scheduling scan for object key: {key}"
                        )
                        asyncio.create_task(worker(key, storage, record, clamav))
    finally:
        await consumer.stop()


# ----------------- CLEANUP TASK -----------------
async def periodic_cleanup_task(storage: S3Storage) -> None:
    """Run cleanup periodically."""
    while True:
        try:
            await storage.async_cleanup_s3_folder(
                S3_BUCKET, S3_SCAN_QUARANTINE, older_than_ms=KAFKA_LOG_RETENTION_MS
            )
            await storage.async_cleanup_s3_folder(
                S3_BUCKET, S3_SCAN_RESULT, older_than_ms=KAFKA_LOG_RETENTION_MS
            )
        except Exception as e:
            logger.exception(f"[task-cleanup] Cleanup task error: {e}")
        await asyncio.sleep(KAFKA_LOG_RETENTION_MS / 1000 / 2)


# ----------------- STATS TASK -----------------
async def periodic_stats_task(
    monitor: Monitor, clamav: ClamAVScanner, storage: S3Storage
) -> None:
    """Log statistics periodically."""

    async def _check():
        try:
            tags = await storage.async_get_s3_tags("stats/_last_stats", S3_BUCKET)
            return tags.get("status") == "ASKED"
        except Exception:
            return False

    while True:
        try:
            if await _check():
                metadata = {"lock-id": "clamav-scan-ignore"}
                if logger.isEnabledFor(logging.DEBUG):
                    r = await clamav.async_stats()
                    logger.info(f"[task-stats] ClamAV stats: {r}")

                await storage.astnc_create_s3_file(
                    "stats/monitor_stats.json",
                    S3_BUCKET,
                    metadata,
                    json.dumps(monitor.statistics).encode("utf-8"),
                )

                await storage.astnc_create_s3_file(
                    "stats/clamav_counters.json",
                    S3_BUCKET,
                    metadata,
                    json.dumps(clamav.statistics).encode("utf-8"),
                )
                await storage.async_set_s3_tags(
                    "stats/_last_stats", S3_BUCKET, {"status": "DONE"}
                )
        except Exception as e:
            logger.exception(f"[task-stats] Stats task error: {e}")
        await asyncio.sleep(0.5)


# ----------------- MAIN -----------------
async def main():
    """Main entrypoint."""
    monitor = Monitor(CLAMD_HOSTS)
    clamav = ClamAVScanner(monitor)
    storage = S3Storage(S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY)

    asyncio.create_task(monitor.reset_host_failures_periodically())
    asyncio.create_task(periodic_cleanup_task(storage))
    asyncio.create_task(periodic_stats_task(monitor, clamav, storage))

    consumer_task = asyncio.create_task(consume_loop(storage, clamav))

    await consumer_task


if __name__ == "__main__":
    asyncio.run(main())
