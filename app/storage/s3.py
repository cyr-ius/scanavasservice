"""Class for managment S3 storage."""

import time
from typing import Any

from aiobotocore.session import ClientCreatorContext, get_session

from ..clamav import ClamAVResult, ClamAVScanner, ClamAVSendException
from ..const import DELAY, RETRY
from ..helpers import retry
from ..logging import getLogger
from ..models import BucketResponse, ScanResponse
from .exceptions import (
    S3BucketKeyException,
    S3GetObjectException,
    S3LockException,
    S3MoveException,
    S3TaggingException,
)
from .models import S3Tags

logger = getLogger("storage")


class S3Storage:
    """S3 Storage class to manage S3 operations."""

    def __init__(self, endpoint, key, secret, region: str | None = None):
        """Initialize S3Storage."""
        self._endpoint = endpoint
        self._key = key
        self._secret = secret
        self._region = region

    async def _async_s3_client(self) -> ClientCreatorContext:
        """Return async S3 client."""
        session = get_session()
        return session.create_client(
            "s3",
            endpoint_url=self._endpoint,
            aws_access_key_id=self._key,
            aws_secret_access_key=self._secret,
            region_name=self._region,
        )

    async def async_move_s3_object(
        self, key: str, bucket: str, target: str, result: ScanResponse
    ) -> None:
        """Move or copy an object within S3 bucket."""

        logger.debug("Moving %s/%s to %s", bucket, key, target)
        async with await self._async_s3_client() as s3_client:
            try:
                # Get headers and merge with new metada because copy_object
                # lost old metadata on file
                await s3_client.copy_object(
                    Bucket=bucket, Key=target, CopySource={"Bucket": bucket, "Key": key}
                )
                await s3_client.delete_object(Bucket=bucket, Key=key)
                # Set tags
                tags = S3Tags.from_scan_response(result)
                await self.async_set_s3_tags(target, bucket, tags)

            except Exception as e:
                raise S3MoveException(f"s3-move-error:{e}") from e

    async def async_cleanup_s3_folder(
        self, bucket: str, prefix: str, older_than_ms: int
    ) -> None:
        """Delete S3 objects in `bucket/prefix` older than `older_than_ms`."""

        cutoff_ts = time.time() - (older_than_ms / 1000)

        async with await self._async_s3_client() as s3_client:
            paginator = s3_client.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    last_modified = obj["LastModified"].timestamp()
                    if last_modified < cutoff_ts:
                        try:
                            await s3_client.delete_object(Bucket=bucket, Key=key)
                            logger.info(f"Deleted old object {bucket}/{key}")
                        except Exception as e:
                            logger.exception(f"Failed to delete {bucket}/{key}: {e}")

    @retry(
        exceptions=(ClamAVSendException, S3GetObjectException),
        tries=RETRY,
        delay=DELAY,
        logger=logger,
    )
    async def async_scan_s3_object(
        self, key: str, bucket: str, clamav: ClamAVScanner
    ) -> ClamAVResult:
        """Scan a single S3 file using a specific CLAMD host via INSTREAM."""

        # fetch S3 stream (fresh for each attempt)
        async with await self._async_s3_client() as s3_client:
            # connect to S3 and get object
            try:
                logger.debug("Fetching S3 object %s/%s", bucket, key)
                resp = await s3_client.get_object(Bucket=bucket, Key=key)
                body = resp["Body"]
            except Exception as e:
                raise S3GetObjectException(f"s3-get-error:{e}") from e
            else:
                # scan with clamav
                try:
                    return await clamav.async_scan(key, bucket, body)
                finally:
                    try:
                        await body.close()
                    except Exception:
                        pass

    async def async_get_s3_metadata(self, key: str, bucket: str) -> dict[str, Any]:
        """Retrieve metadata."""
        async with await self._async_s3_client() as s3_client:
            obj = await s3_client.head_object(Key=key, Bucket=bucket)
            return obj.get("Metadata", {})

    async def async_get_s3_tags(self, key: str, bucket: str) -> dict[str, Any]:
        """Return tags."""
        async with await self._async_s3_client() as s3_client:
            result = await s3_client.get_object_tagging(Key=key, Bucket=bucket)
            return S3Tags.from_aws_response(result).to_dict()

    async def async_set_s3_tags(self, key: str, bucket: str, tags: S3Tags) -> None:
        """Return tags."""
        async with await self._async_s3_client() as s3_client:
            try:
                await s3_client.put_object_tagging(
                    Key=key, Bucket=bucket, Tagging=tags.to_tagset()
                )
            except Exception as e:
                raise S3TaggingException(f"s3-tagging-error:{e}") from e

    async def astnc_create_s3_file(
        self,
        key: str,
        bucket: str,
        metadata: dict[str, Any] | None = None,
        body: bytes = b"",
    ) -> None:
        """Create S3 file."""
        async with await self._async_s3_client() as s3_client:
            try:
                await s3_client.put_object(
                    Key=key, Bucket=bucket, Body=body, Metadata=metadata
                )
            except Exception as e:
                raise S3LockException(f"s3-lock-error:{e}") from e

    async def async_get_s3_file(self, key: str, bucket: str) -> bytes | None:
        """Get S3 file."""
        async with await self._async_s3_client() as s3_client:
            try:
                logger.debug("Fetching S3 object %s/%s", bucket, key)
                resp = await s3_client.get_object(Bucket=bucket, Key=key)
                body = resp["Body"]
                data = await body.read()
                return data
            except s3_client.exceptions.NoSuchKey:
                return None
            except Exception as e:
                raise S3GetObjectException(f"s3-get-error:{e}") from e

    async def async_stream_s3_file(self, key: str, bucket: str):
        """Stream S3 file."""
        async with await self._async_s3_client() as s3_client:
            logger.debug("Fetching S3 object %s/%s", bucket, key)
            resp = await s3_client.get_object(Bucket=bucket, Key=key)
            body = resp["Body"]
            try:
                async for chunk in body.iter_chunks():
                    if not chunk:
                        break
                    yield chunk
            finally:
                # assure close du body si nécessaire
                try:
                    await body.close()
                except Exception:
                    pass

    async def async_delete_s3_file(self, key: str, bucket: str) -> None:
        """Delete S3 file."""
        async with await self._async_s3_client() as s3_client:
            try:
                await s3_client.delete_object(Bucket=bucket, Key=key)
            except Exception as e:
                raise S3GetObjectException(f"s3-delete-error:{e}") from e

    async def async_browse_s3_bucket(self, bucket: str) -> list[BucketResponse]:
        """Browse S3 bucket."""
        result = []
        try:
            async with await self._async_s3_client() as s3_client:
                paginator = s3_client.get_paginator("list_objects_v2")
                async for page in paginator.paginate(Bucket=bucket):
                    for obj in page.get("Contents", []):
                        obj = {str(k).lower(): v for k, v in obj.items()}
                        key = obj["key"]
                        metadata = (
                            await s3_client.head_object(Bucket=bucket, Key=key)
                        )["Metadata"]
                        tagset = await s3_client.get_object_tagging(
                            Bucket=bucket, Key=key
                        )
                        tags = S3Tags.from_aws_response(tagset).to_dict()
                        result.append(
                            BucketResponse(bucket=bucket, **tags, **obj, **metadata)
                        )
        except Exception as e:
            raise S3GetObjectException(f"s3-browse-error:{e}") from e
        finally:
            return result

    def get_bucket_key(self, record: dict[str, Any]) -> tuple[str, str]:
        """Return bucket, key from payload."""
        if "s3" in record:
            bucket = record["s3"].get("bucket", {}).get("name")
            key = record["s3"].get("object", {}).get("key")
            if bucket and key:
                return key, bucket

        raise S3BucketKeyException("Unable to determine the bucket and object key.")
