# main.py
import asyncio
import json
import uuid
from typing import Annotated, Literal

from const import (
    CLIENT_ID,
    CLIENT_SCOPES,
    CLIENT_SECRET,
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
from models import BucketResponse, ErrorResponse, ScanResponse
from mylogging import mylogging
from pydantic import Field, HttpUrl, ValidationError
from storage import S3Storage

logger = mylogging.getLogger("api")
storage = S3Storage(S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY)


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
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        503: {"model": ErrorResponse, "description": "Service Unavailable"},
    },
)
async def upload_file_to_scan(
    file: UploadFile,
    webhook: Annotated[HttpUrl | None, Field(HttpUrl, max_length=128)] = None,
) -> ScanResponse:
    """Upload file to S3 and send scan request to Kafka."""
    key = str(uuid.uuid4())
    data = await file.read()
    if webhook and len(webhook) > 128:
        raise HTTPException(
            status_code=503, detail="Webhook url: length exceeded (max: 128)"
        )
    try:
        if filename := file.filename:
            metadata = {"OriginalFilename": normalize_ascii(filename)}
            if webhook:
                metadata = {**metadata, "Webhook": str(webhook)}
            await storage.astnc_create_s3_file(key, S3_BUCKET, metadata, data)
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

    return ScanResponse(
        key=key,
        bucket=S3_BUCKET,
        webhook=str(webhook) if webhook else None,
        originalfilename=file.filename,
    )


@v1_router.get(
    "/download/{key}",
    dependencies=[Depends(protected)],
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
        metadata = await storage.async_get_s3_metadata(result.key, S3_BUCKET)
        filename = metadata.get("originalfilename", "unknown_name")

        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return StreamingResponse(
            storage.async_stream_s3_file(result.key, S3_BUCKET),
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
    responses={
        404: {"model": ErrorResponse, "description": "File not found"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        503: {"model": ErrorResponse, "description": "Storage Unavailable"},
    },
)
async def scan_status(key: str) -> ScanResponse:
    """Fetch scan result by ID."""

    tags = {}
    orig_key = key
    for item in [S3_BUCKET, S3_SCAN_RESULT, S3_SCAN_QUARANTINE]:
        if item in [S3_SCAN_RESULT, S3_SCAN_QUARANTINE]:
            key = f"{item}/{orig_key}"

        try:
            metadata = await storage.async_get_s3_metadata(key, S3_BUCKET)
            tags = await storage.async_get_s3_tags(key, S3_BUCKET)

            return ScanResponse(
                key=key,
                bucket=S3_BUCKET,
                originalfilename=metadata.get("originalfilename"),
                webhook=metadata.get("webhook"),
                **tags,
            )
        except Exception:
            pass

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")


@v1_router.get("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def hearbeat():
    """Hearbeat url."""
    pass


@v1_router.get("/monitor/{type}", dependencies=[Depends(protected)])
async def clamav_monitor(
    type: Literal["clamav", "bucket"],
) -> dict | list[BucketResponse] | None:
    """Monitor loadbalancing."""
    try:
        if type == "clamav":
            return await _get_last_stats_message()
        elif type == "bucket":
            return await storage.async_browse_s3_bucket(S3_BUCKET)
        else:
            raise HTTPException()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Monitor error ({e})",
        )


async def _get_last_stats_message() -> dict | None:
    """Get last message from Kafka topic."""
    metadata = {"lock-id": "clamav-scan-ignore"}
    last_stats_message = {}

    await storage.astnc_create_s3_file("stats/_last_stats", S3_BUCKET, metadata)
    await storage.async_set_s3_tags("stats/_last_stats", S3_BUCKET, {"status": "ASKED"})

    async def _check():
        tags = await storage.async_get_s3_tags("stats/_last_stats", S3_BUCKET)
        return tags.get("status") == "ASKED"

    while await _check() == "ASKED":
        await asyncio.sleep(0.5)

    for msg in ["stats/monitor_stats.json", "stats/clamav_counters.json"]:
        if content := await storage.async_get_s3_file(msg, S3_BUCKET):
            r = json.loads(content.decode("utf-8"))
            last_stats_message.update(r)

    return last_stats_message


app.include_router(v1_router)
