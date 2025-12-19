"""Data models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

# Fastapi


class Metadata(BaseModel):
    originalfilename: str | None = None
    webhook: str | None = None


class MessageBase(BaseModel):
    key: str
    bucket: str
    status: Literal["ERROR", "PENDING", "CLEAN", "INFECTED", "ERROR"] = "PENDING"
    timestamp: datetime = datetime.now()


class ClamAVResult(MessageBase):
    instance: str | None = None
    infos: str | None = None
    analyse: float | None = None


class ScanResult(Metadata, ClamAVResult, MessageBase):
    duration: float | None = None
    worker: str | None = None


class UploadResponse(Metadata, MessageBase):
    pass


class BuckenContent(ScanResult):
    lastmodified: datetime
    etag: str
    size: int
    storageclass: str
