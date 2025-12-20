# main.py
import json
import ssl
import uuid
from contextlib import asynccontextmanager

from aiobotocore.session import get_session
from aiokafka import AIOKafkaConsumer
from aiokafka.structs import TopicPartition
from const import (
    CLIENT_ID,
    CLIENT_SCOPES,
    CLIENT_SECRET,
    KAFKA_SASL_MECHANISM,
    KAFKA_SASL_PASSWORD,
    KAFKA_SASL_USERNAME,
    KAFKA_SECURITY_PROTOCOL,
    KAFKA_SERVERS,
    KAFKA_SSL_CHECK_HOSTNAME,
    KAFKA_SSL_VERIFY_MODE,
    KAFKAT_STATS,
    MAX_CHUNK_SIZE,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
    VERSION,
)
from depends import protected
from fastapi import APIRouter, FastAPI, HTTPException, Request, UploadFile, status
from fastapi.params import Depends
from fastapi.responses import JSONResponse, StreamingResponse
from helpers import normalize_ascii
from models import BucketResponse, ErrorResponse, ScanResponse, UploadResponse
from mylogging import mylogging
from pydantic import HttpUrl, ValidationError

logger = mylogging.getLogger("api")
session = get_session()


# Create a reusable asynccontextmanager for S3 client to ensure proper close
@asynccontextmanager
async def s3_client_ctx():
    """Async context manager for S3 client."""
    client = await session.create_client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
    ).__aenter__()
    try:
        yield client
    finally:
        try:
            await client.__aexit__(None, None, None)
        except Exception as e:
            logger.debug("Error closing s3 client: %s", e)


app = FastAPI(
    title="ScanAV as Service (SAVaS) - API",
    description="This API allows you to submit a file to a ClamAV antivirus engine and retrieve the result.",
    root_path="/api",
    version=VERSION,
    swagger_ui_init_oauth={
        "clientId": CLIENT_ID,
        "clientSecret": CLIENT_SECRET,
        "scopes": CLIENT_SCOPES,
        "usePkceWithAuthorizationCodeGrant": False,
    },
)


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    detail = "; ".join([f"{err['loc']}: {err['msg']}" for err in exc.errors()])
    return JSONResponse(status_code=422, content={"status": 422, "detail": detail})


v1_router = APIRouter(prefix="/v1")


@v1_router.post(
    "/upload",
    dependencies=[Depends(protected)],
    tags=["av"],
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        503: {"model": ErrorResponse, "description": "Service Unavailable"},
    },
)
async def upload_file_to_scan(
    file: UploadFile, url: HttpUrl | None = None
) -> UploadResponse:
    """Upload file to S3 and send scan request to Kafka."""
    key = str(uuid.uuid4())
    data = await file.read()
    if url and len(url) > 128:
        raise HTTPException(
            status_code=503, detail="Webhook url: length exceeded (max: 128)"
        )
    try:
        async with s3_client_ctx() as client:  # type: ignore
            if filename := file.filename:
                metadata = {"OriginalFilename": normalize_ascii(filename)}
                if url is not None:
                    metadata = {**metadata, "Webhook": str(url)}
                await client.put_object(
                    Bucket=S3_BUCKET, Key=key, Body=data, Metadata=metadata
                )  # type: ignore
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Filename is required",
                )
    except Exception as e:
        logger.exception("S3 put_object failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Storage unavailable: {e}",
        )

    return UploadResponse(
        key=key,
        bucket=S3_BUCKET,
        status="PENDING",
        webhook=str(url),
        originalfilename=file.filename,
    )


@v1_router.get(
    "/download/{key}",
    dependencies=[Depends(protected)],
    tags=["av"],
    responses={
        200: {
            "description": "File downloaded successfully",
            "content": {"application/octet-stream": {}},
        },
        208: {"model": ErrorResponse, "description": "File is pending scan"},
        402: {"model": ErrorResponse, "description": "File not clean"},
        404: {"model": ErrorResponse, "description": "File not found"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        503: {"model": ErrorResponse, "description": "Storage Unavailable"},
    },
)
async def download_scanned_file(key: str, force: bool = False) -> StreamingResponse:
    """Download scanned file by ID if clean or force is True."""
    result = await scan_status(key)
    if result.status == "PENDING":
        raise HTTPException(
            status_code=status.HTTP_208_ALREADY_REPORTED, detail="File is pending scan"
        )
    if result.status != "CLEAN" and not force:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=f"{result.status}"
        )

    try:
        # Use s3_client_ctx
        async with s3_client_ctx() as s3_client:
            obj_meta = await s3_client.head_object(Bucket=S3_BUCKET, Key=result.key)  # type: ignore
            filename = obj_meta.get("Metadata", {}).get(
                "originalfilename", "unknown_name"
            )

        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return StreamingResponse(
            s3_object_stream(S3_BUCKET, result.key),
            media_type="application/octet-stream",
            headers=headers,
        )

    except Exception as e:
        logger.exception("Download error (%s)", e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found or storage unavailable",
        )


@v1_router.get(
    "/status/{key}",
    dependencies=[Depends(protected)],
    tags=["av"],
    responses={
        404: {"model": ErrorResponse, "description": "File not found"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        503: {"model": ErrorResponse, "description": "Storage Unavailable"},
    },
)
async def scan_status(key: str) -> ScanResponse:
    """Fetch scan result by ID."""

    async with s3_client_ctx() as s3_client:
        tags = {}
        for item in [S3_BUCKET, S3_SCAN_RESULT, S3_SCAN_QUARANTINE]:
            if item in [S3_SCAN_RESULT, S3_SCAN_QUARANTINE]:
                key = f"{item}/{key}"
            try:
                obj = await s3_client.head_object(Bucket=S3_BUCKET, Key=key)  # type: ignore
            except Exception:
                obj = None

            if obj:
                metadata = obj.get("Metadata", {})
                obj_tags = await s3_client.get_object_tagging(Bucket=S3_BUCKET, Key=key)  # type: ignore
                tags = {t["Key"]: t["Value"] for t in obj_tags.get("TagSet", [])}

                return ScanResponse(
                    key=key,
                    bucket=S3_BUCKET,
                    originalfilename=metadata.get("originalfilename"),
                    webhook=metadata.get("webhook"),
                    **tags,
                )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Storage unavailable"
    )


@v1_router.get("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def hearbeat():
    """Hearbeat url."""
    pass


@v1_router.get("/monitor/clamav", dependencies=[Depends(protected)])
async def clamav_monitor():
    """Monitor loadbalancing."""
    try:
        msg = await get_last_message()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Monitor error ({e})",
        )
    else:
        return msg


@v1_router.get("/monitor/bucket", dependencies=[Depends(protected)])
async def bucket_status() -> list[BucketResponse]:
    """Monitor loadbalancing."""
    result = []
    try:
        async with s3_client_ctx() as s3_client:
            paginator = s3_client.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=S3_BUCKET):  # type: ignore
                for obj in page.get("Contents", []):
                    obj = {str(k).lower(): v for k, v in obj.items()}
                    key = obj["key"]
                    metadata = (await s3_client.head_object(Bucket=S3_BUCKET, Key=key))[  # type: ignore
                        "Metadata"
                    ]
                    tagset = await s3_client.get_object_tagging(
                        Bucket=S3_BUCKET, Key=key
                    )  # type: ignore
                    tags = {t["Key"]: t["Value"] for t in tagset["TagSet"]}
                    result.append(
                        BucketResponse(bucket=S3_BUCKET, **obj, **metadata, **tags)
                    )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Status error ({e})",
        )
    else:
        return result


async def s3_object_stream(bucket: str, key: str):
    """Stream S3 object."""
    async with s3_client_ctx() as s3_client:  # type: ignore
        resp = await s3_client.get_object(Bucket=bucket, Key=key)  # type: ignore
        body = resp["Body"]
        try:
            async for chunk in body.iter_chunks(MAX_CHUNK_SIZE):
                if not chunk:
                    break
                yield chunk
        finally:
            # assure close du body si nécessaire
            try:
                await body.close()
            except Exception:
                pass


def _ssl_context():
    """Create SSL context for Kafka connections if needed."""

    context = ssl.create_default_context()
    context.check_hostname = KAFKA_SSL_CHECK_HOSTNAME
    context.verify_mode = ssl.CERT_REQUIRED if KAFKA_SSL_VERIFY_MODE else ssl.CERT_NONE
    return context


async def get_last_message() -> dict | None:
    """Get last message from Kafka topic."""

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
        bootstrap_servers=KAFKA_SERVERS,  # type: ignore
        enable_auto_commit=False,  # ne jamais avancer l'offset
        auto_offset_reset="latest",  # démarrer au dernier offset
        group_id=f"api-tracker-{uuid.uuid4()}",
        security_protocol=security_protocol,
        sasl_mechanism=sasl_mechanism,  # type: ignore
        sasl_plain_username=sasl_plain_username,
        sasl_plain_password=sasl_plain_password,
        ssl_context=_ssl_context(),
        value_deserializer=lambda x: json.loads(x.decode("utf-8")),
    )
    await consumer.start()

    # récupérer les partitions du topic
    partitions = consumer.partitions_for_topic(KAFKAT_STATS)
    if not partitions:
        await consumer.stop()
        return None

    topic_partitions = [TopicPartition(KAFKAT_STATS, p) for p in partitions]
    consumer.assign(topic_partitions)  # assign manuel

    # chercher le dernier offset et lire le dernier message
    last_messages = []
    for tp in topic_partitions:
        end_offset = await consumer.end_offsets([tp])
        last_offset = end_offset[tp] - 1
        if last_offset >= 0:
            consumer.seek(tp, last_offset)
            msg = await consumer.getone()
            last_messages.append(msg.value)

    await consumer.stop()
    return last_messages[-1] if last_messages else None


app.include_router(v1_router)
