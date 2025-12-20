#!/usr/bin/env python3
import asyncio
import json
import time
from collections.abc import Awaitable
from typing import Any

from aiohttp import ClientSession
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from clamav import (
    ClamAVResult,
    ClamAVScanner,
)
from const import (
    CLAMD_HOSTS,
    DELAY,
    KAFKA_LOG_RETENTION_MS,
    KAFKA_TOPIC,
    KAFKAT_STATS,
    MAX_CONCURRENT_SCANS,
    RETRY,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
)
from helpers import retry
from models import ScanResponse
from monitor import Monitor
from mylogging import mylogging
from storage import S3BucketKeyException, S3LockException, S3MoveException, S3Storage
from utils import kafka_params

logger = mylogging.getLogger("scanav")

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
    monitor: Monitor,
    record: dict[str, Any],
    producer: AIOKafkaProducer,
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
            scan = ClamAVResult(
                key=key, bucket=bucket, status="ERROR", infos=e.__class__.__name__
            )

        # Move object based on scan result
        target = (
            f"{S3_SCAN_RESULT}/{key}"
            if scan.status in ["CLEAN", "ERROR"]
            else f"{S3_SCAN_QUARANTINE}/{key}"
        )

        duration = time.monotonic() - start_time
        result = ScanResponse(duration=duration, **scan.model_dump())
        await storage.async_move_s3_object(key, bucket, target, result)
        logger.info(f"[worker-{worker_id}] Scanned {key} → {scan.status}")

        await producer.send_and_wait(KAFKA_TOPIC, value=result.model_dump_json())
        await producer.send_and_wait(
            KAFKAT_STATS,
            value=json.dumps({**clamav.statistics, "monitor": monitor.statistics}),
        )

        # Fire webhook if present
        if (
            (metadata := await storage.async_get_s3_metadata(target, bucket))
            and (url := metadata.get("webhook"))
            and scan is not None
        ):
            fire_and_forget(async_call_webhook(target, url, result.model_dump()))


# ----------------- CONSUMER -----------------
async def consume_loop(
    producer: AIOKafkaProducer,
    storage: S3Storage,
    monitor: Monitor,
    clamav: ClamAVScanner,
):
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
                    if key := record.get("s3", {}).get("object", {}).get("key"):
                        logger.info(
                            f"[kafka-consumer] Scheduling scan for object key: {key}"
                        )
                        asyncio.create_task(
                            worker(key, storage, monitor, record, producer, clamav)
                        )
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


# ----------------- MAIN -----------------
async def main():
    """Main entrypoint."""
    monitor = Monitor(CLAMD_HOSTS)
    clamav = ClamAVScanner(monitor)
    storage = S3Storage(S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY)

    producer = AIOKafkaProducer(
        **kafka_params(), value_serializer=lambda v: v.encode("utf-8")
    )
    await producer.start()

    asyncio.create_task(monitor.reset_host_failures_periodically())
    asyncio.create_task(periodic_cleanup_task(storage))

    consumer_task = asyncio.create_task(
        consume_loop(producer, storage, monitor, clamav)
    )

    try:
        await consumer_task
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
