"""Class for managment S3 storage."""

import time
from typing import Any

from aiobotocore.session import ClientCreatorContext, get_session
from aiohttp import ClientSession
from clamav import ClamAVScanner, ClamAVSendException
from const import BASE_DELAY, RETRY
from helpers import retry
from models import ClamAVResult, ScanResult
from mylogging import mylogging

logger = mylogging.getLogger("storage")


class S3Storage:
    def __init__(
        self,
        endpoint,
        key,
        secret,
        clamd_timeout: float,
        region: str | None = None,
    ):
        self.endpoint = endpoint
        self.key = key
        self.secret = secret
        self._clamd_timeout = clamd_timeout

    async def _get_s3_client(self) -> ClientCreatorContext:
        session = get_session()
        return session.create_client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.key,
            aws_secret_access_key=self.secret,
        )

    async def async_move_s3_object(
        self, key: str, bucket: str, target: str, result: ScanResult
    ) -> None:
        """Move or copy an object within S3 bucket."""

        logger.debug("Moving %s/%s to %s", bucket, key, target)
        async with await self._get_s3_client() as s3_client:
            try:
                # Get headers and merge with new metada because copy_object
                # lost old metadata on file
                await s3_client.copy_object(
                    Bucket=bucket, Key=target, CopySource={"Bucket": bucket, "Key": key}
                )  # type: ignore
                await s3_client.delete_object(Bucket=bucket, Key=key)  # type: ignore
                # Set tags
                tags = {
                    "timestamp": str(result.timestamp),
                    "duration": round(result.duration, 3) if result.duration else 0.0,
                    "status": result.status,
                    "infos": result.infos or "",
                    "analyse": result.analyse,
                    "instance": result.instance,
                }
                await self.async_set_s3_tags(target, bucket, tags)

            except Exception as e:
                raise S3MoveException(f"s3-move-error:{e}") from e

    async def async_cleanup_s3_folder(
        self, bucket: str, prefix: str, older_than_ms: int
    ) -> None:
        """Delete S3 objects in `bucket/prefix` older than `older_than_ms`."""

        cutoff_ts = time.time() - (older_than_ms / 1000)

        async with await self._get_s3_client() as s3_client:
            paginator = s3_client.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=bucket, Prefix=prefix):  # type: ignore
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    last_modified = obj["LastModified"].timestamp()
                    if last_modified < cutoff_ts:
                        try:
                            await s3_client.delete_object(Bucket=bucket, Key=key)  # type: ignore
                            logger.info(f"Deleted old object {bucket}/{key}")
                        except Exception as e:
                            logger.exception(f"Failed to delete {bucket}/{key}: {e}")

    @retry(
        exceptions=(ClamAVSendException,), tries=RETRY, delay=BASE_DELAY, logger=logger
    )
    async def async_scan_s3_object(
        self, key: str, bucket: str, clamav: ClamAVScanner
    ) -> ClamAVResult:
        """Scan a single S3 file using a specific CLAMD host via INSTREAM."""

        # fetch S3 stream (fresh for each attempt)
        async with await self._get_s3_client() as s3_client:
            # connect to S3 and get object
            try:
                logger.debug("Fetching S3 object %s/%s", bucket, key)
                resp = await s3_client.get_object(Bucket=bucket, Key=key)  # type: ignore
                body = resp["Body"]
            except Exception as e:
                raise S3GetObjectException(f"s3-get-error:{e}") from e
            else:
                # scan with clamav
                return await clamav.async_scan(key, bucket, body)

    @retry(tries=RETRY, delay=BASE_DELAY, logger=logger)
    async def async_call_webhook(self, key: str, url: str, payload: dict):
        async with ClientSession(raise_for_status=True) as session:
            logger.info("Calling webhook %s", key)
            async with session.post(url, json=payload):
                logger.info(f"Webhook {url} successfully called for file {key}")

    async def async_get_s3_metadata(self, key: str, bucket: str) -> dict[str, Any]:
        """Retrieve metadata."""
        async with await self._get_s3_client() as s3_client:
            obj = await s3_client.head_object(Key=key, Bucket=bucket)  # type: ignore
            return obj.get("Metadata", {})

    async def async_get_s3_tags(self, key: str, bucket: str) -> dict[str, Any]:
        """Return tags."""
        async with await self._get_s3_client() as s3_client:
            result = await s3_client.get_object_tagging(Key=key, Bucket=bucket)  # type: ignore
            return result["TagSet"]

    async def async_set_s3_tags(
        self, key: str, bucket: str, tags: dict[str, Any]
    ) -> None:
        """Return tags."""
        async with await self._get_s3_client() as s3_client:
            if len(tags) > 10:
                raise S3StorageException("Too many tags exceeded (max:10)")
            taggins = [{"Key": str(k), "Value": str(v)} for k, v in tags.items()]
            await s3_client.put_object_tagging(
                Key=key, Bucket=bucket, Tagging={"TagSet": taggins}
            )  # type: ignore

    def get_bucket_key(self, record: dict[str, Any]) -> tuple[str, str]:
        """Return bucket, key from payload."""
        if "s3" in record:
            bucket = record["s3"].get("bucket", {}).get("name")
            key = record["s3"].get("object", {}).get("key")
            if bucket and key:
                return key, bucket

        raise S3BucketKeyException("Unable to determine the bucket and object key.")


class S3StorageException(Exception):
    """Storage exception."""


class S3GetObjectException(S3StorageException):
    """Custom exception for S3 get object errors."""


class S3MoveException(S3StorageException):
    """Custom exception for S3 move errors."""


class S3TaggingException(S3StorageException):
    """Custom exception for S3 move errors."""


class S3LockException(S3StorageException):
    """Custom exception for S3 lock errors."""


class S3UnlockException(S3StorageException):
    """Custom exception for S3 unlock errors."""


class S3MetadataException(S3StorageException):
    """Custom exception for S3 unlock errors."""


class S3BucketKeyException(S3StorageException):
    """Custom exception for S3 unlock errors."""
