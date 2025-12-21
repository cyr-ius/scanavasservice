# main.py
import asyncio
import json
import unicodedata
import uuid
from datetime import timedelta
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    FastAPI,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.params import Depends
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, HttpUrl, ValidationError

from ..const import (
    CLIENT_ID,
    CLIENT_SECRET,
    S3_ACCESS_KEY,
    S3_BUCKET,
    S3_ENDPOINT,
    S3_SCAN_QUARANTINE,
    S3_SCAN_RESULT,
    S3_SECRET_KEY,
    VERSION,
)
from ..models import BucketResponse, ScanResponse
from ..mylogging import mylogging
from ..storage import S3Storage
from .depends import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, protected

logger = mylogging.getLogger("api")
storage = S3Storage(S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY)


class ErrorResponse(BaseModel):
    detail: str
    code: int


app = FastAPI(
    title="ScanAV as Service (SAVaS) - API",
    description="This API allows you to submit a file to a ClamAV antivirus engine and retrieve the result.",
    root_path="/api",
    version=VERSION,
)


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    detail = "; ".join([f"{err['loc']}: {err['msg']}" for err in exc.errors()])
    return JSONResponse(status_code=422, content={"status": 422, "detail": detail})


@app.post("/token", include_in_schema=False)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    if form_data.username != CLIENT_ID or form_data.password != CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def hearbeat():
    """Hearbeat url."""
    pass


v1_router = APIRouter(prefix="/v1", dependencies=[Depends(protected)])

responses = {
    422: {"model": ErrorResponse, "description": "Validation Error"},
    503: {"model": ErrorResponse, "description": "Service Unavailable"},
}


@v1_router.post(
    "/upload",
    responses={
        **responses,
        400: {"model": ErrorResponse, "description": "Bad Request"},
    },
)
async def upload_file_to_scan(
    file: UploadFile,
    scan_notification: HttpUrl | None = Query(
        None, alias="scan-notification", description="Webhook  url", max_length=128
    ),
) -> ScanResponse:
    """Upload file to scan."""
    key = str(uuid.uuid4())
    data = await file.read()

    def normalize_ascii(value: str) -> str:
        return (
            unicodedata.normalize("NFKD", value)
            .encode("ascii", "ignore")
            .decode("ascii")
        )

    if scan_notification and len(scan_notification) > 128:
        raise HTTPException(
            status_code=503, detail="Webhook url: length exceeded (max: 128)"
        )
    try:
        if filename := file.filename:
            metadata = {"OriginalFilename": normalize_ascii(filename)}
            if scan_notification:
                metadata = {**metadata, "Webhook": str(scan_notification)}
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
        webhook=str(scan_notification) if scan_notification else None,
        originalfilename=file.filename,
    )


@v1_router.get(
    "/download/{key}",
    responses={
        200: {
            "description": "File downloaded successfully",
            "content": {"application/octet-stream": {}},
        },
        208: {"model": ErrorResponse, "description": "File is pending scan"},
        402: {"model": ErrorResponse, "description": "File not clean"},
        404: {"model": ErrorResponse, "description": "File not found"},
        **responses,
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
    responses={
        404: {"model": ErrorResponse, "description": "File not found"},
        **responses,
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


@v1_router.get("/monitor/{type}")
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


@app.webhooks.post("scan-notification")
async def scan_notification(body: ScanResponse):
    """
    When a new user subscribes to your service we'll send you a POST request with this
    data to the URL that you register for the event `scan-notification`.
    """


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
