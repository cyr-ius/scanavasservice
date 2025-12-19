#!/usr/bin/env python3
import asyncio
import json
import ssl
import time
from collections.abc import Awaitable
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from const import (
    BASE_DELAY,
    CLAMD_CNX_TIMEOUT,
    CLAMD_HOSTS,
    KAFKA_LOG_RETENTION_MS,
    KAFKA_SASL_MECHANISM,
    KAFKA_SASL_PASSWORD,
    KAFKA_SASL_USERNAME,
    KAFKA_SECURITY_PROTOCOL,
    KAFKA_SERVERS,
    KAFKA_SSL_CHECK_HOSTNAME,
    KAFKA_SSL_VERIFY_MODE,
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
from models import ClamAVResult, ScanResult
from monitor import Monitor
from mylogging import mylogging
from storage import (
    ClamAVException,
    S3BucketKeyException,
    S3LockException,
    S3MoveException,
    S3Storage,
)

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


def _ssl_context():
    """Create SSL context for Kafka connections if needed."""

    context = ssl.create_default_context()
    context.check_hostname = KAFKA_SSL_CHECK_HOSTNAME
    context.verify_mode = ssl.CERT_REQUIRED if KAFKA_SSL_VERIFY_MODE else ssl.CERT_NONE
    return context


# ----------------- WORKER -----------------
@retry(
    exceptions=(S3BucketKeyException, S3LockException, S3MoveException),
    tries=RETRY,
    delay=BASE_DELAY,
)
async def worker(
    worker_id: str,
    storage: S3Storage,
    monitor: Monitor,
    record: dict[str, Any],
    producer: AIOKafkaProducer,
) -> None:
    """Worker that selects the best host adaptively, performs scan, updates stats and moves object."""
    async with scan_semaphore:
        logger.info(f"[worker-{worker_id}] Start scan.")
        start_time = time.monotonic()

        # Extract object key, bucket and metadata
        key, bucket = storage.get_bucket_key(record)

        # Set status to PENDING
        await storage.async_set_s3_tags(key, bucket, {"status": "PENDING"})

        attempt = 0
        last_exception = None

        while attempt < RETRY:
            attempt += 1
            host, port, host_key = await monitor.select_best_host()
            await monitor.mark_host_busy(host_key)
            scan_start = time.monotonic()

            try:
                scan = await storage.async_scan_s3_object(key, bucket, host, port)
            except ClamAVException as e:
                await monitor.mark_host_done(host_key, elapsed=None, success=False)
                last_exception = e
                logger.warning(
                    f"[worker-{worker_id}] ClamAV attempt failed on {host_key}: {e} (attempt {attempt})"
                )
                await asyncio.sleep(BASE_DELAY * (2 ** (attempt - 1)))
                continue
            else:
                elapsed = time.monotonic() - scan_start
                await monitor.mark_host_done(host_key, elapsed=elapsed, success=True)
                break
        else:
            logger.error(
                f"[worker-{worker_id}] All CLAMD attempts failed for {key}: {last_exception}"
            )
            scan = ClamAVResult(
                key=key,
                bucket=bucket,
                status="ERROR",
                infos="All CLAMD attempts failed",
                analyse=0,
            )

        # Move object based on scan result
        target = (
            f"{S3_SCAN_RESULT}/{key}"
            if scan.status in ["CLEAN", "ERROR"]
            else f"{S3_SCAN_QUARANTINE}/{key}"
        )

        duration = time.monotonic() - start_time
        result = ScanResult(worker=worker_id, duration=duration, **scan.model_dump())
        await storage.async_move_s3_object(key, bucket, target, result)
        logger.info(f"[worker-{worker_id}] Scanned {key} → {scan.status}")

        await producer.send_and_wait(
            KAFKA_TOPIC, value=result.model_dump_json().encode("utf-8")
        )
        await producer.send_and_wait(
            KAFKAT_STATS,
            value=json.dumps(
                {**storage.statistics, "monitor": monitor.statistics}
            ).encode("utf-8"),
        )

        # Fire webhook if present
        if (
            (metadata := await storage.async_get_s3_metadata(target, bucket))
            and (url := metadata.get("webhook"))
            and scan is not None
        ):
            fire_and_forget(
                storage.async_call_webhook(target, url, result.model_dump_json())
            )


# ----------------- CONSUMER -----------------
async def consume_loop(
    producer: AIOKafkaProducer, storage: S3Storage, monitor: Monitor
):
    if KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD:
        security_protocol = KAFKA_SECURITY_PROTOCOL
        sasl_mechanism = KAFKA_SASL_MECHANISM
        sasl_plain_username = KAFKA_SASL_USERNAME
        sasl_plain_password = KAFKA_SASL_PASSWORD
    else:
        security_protocol = "PLAINTEXT"
        sasl_mechanism = None
        sasl_plain_username = None
        sasl_plain_password = None

    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,  # type: ignore
        group_id="scanner-group",
        enable_auto_commit=True,
        security_protocol=security_protocol,
        sasl_mechanism=sasl_mechanism,  # type: ignore
        sasl_plain_username=sasl_plain_username,
        sasl_plain_password=sasl_plain_password,
        auto_offset_reset="latest",
        ssl_context=_ssl_context(),
    )
    await consumer.start()
    try:
        async for msg in consumer:
            if not msg.value:
                continue
            payload = json.loads(msg.value.decode("utf-8"))
            logger.debug("Kafka payload: %s", payload)
            for record in payload.get("Records", []):
                if record.get("eventName") == "s3:ObjectCreated:Put":
                    logger.debug("New S3 object to scan detected.")
                    if key := record.get("s3", {}).get("object", {}).get("key"):
                        logger.info(
                            f"[kafka-consumer] Scheduling scan for object key: {key}"
                        )
                        asyncio.create_task(
                            worker(key, storage, monitor, record, producer)
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
    monitor = Monitor(CLAMD_HOSTS)
    storage = S3Storage(
        S3_ENDPOINT,
        S3_ACCESS_KEY,
        S3_SECRET_KEY,
        CLAMD_CNX_TIMEOUT,
    )

    if KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD:
        security_protocol = KAFKA_SECURITY_PROTOCOL
        sasl_mechanism = KAFKA_SASL_MECHANISM
        sasl_plain_username = KAFKA_SASL_USERNAME
        sasl_plain_password = KAFKA_SASL_PASSWORD
    else:
        security_protocol = "PLAINTEXT"
        sasl_mechanism = None
        sasl_plain_username = None
        sasl_plain_password = None

    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,  # type: ignore
        security_protocol=security_protocol,
        sasl_mechanism=sasl_mechanism,  # type: ignore
        sasl_plain_username=sasl_plain_username,
        sasl_plain_password=sasl_plain_password,
        ssl_context=_ssl_context(),
    )
    await producer.start()

    asyncio.create_task(monitor.reset_host_failures_periodically())
    asyncio.create_task(periodic_cleanup_task(storage))

    consumer_task = asyncio.create_task(consume_loop(producer, storage, monitor))

    try:
        await consumer_task
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
