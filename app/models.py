"""Data models."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from .clamav.models import ClamAVResult


class Metadata(BaseModel):
    originalfilename: str | None = None
    webhook: str | None = None


class ScanResponse(Metadata, ClamAVResult):
    key: str
    bucket: str
    timestamp: datetime = Field(default_factory=datetime.now)
    duration: float | None = None

    @field_validator("duration", mode="before")
    @classmethod
    def round_duration(cls, v):
        """Round duration to 2 decimal places."""
        if v is None:
            return None
        return round(float(v), 2)


class BucketResponse(ScanResponse):
    lastmodified: datetime
    etag: str
    size: int
    storageclass: str
